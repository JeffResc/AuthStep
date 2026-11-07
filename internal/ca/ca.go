// Package ca talks to step-ca as a registration authority: it mints
// single-use JWK provisioner tokens and calls the sign API.
package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.step.sm/crypto/jose"
)

const tokenLifetime = 5 * time.Minute

type Client struct {
	url         string
	http        *http.Client
	rootSHA     string
	provisioner string
	key         *jose.JSONWebKey
	now         func() time.Time
}

type Options struct {
	URL         string // e.g. https://step-ca.example.svc:9000
	RootPath    string // root CA certificate (PEM)
	Provisioner string // JWK provisioner name
	KeyPath     string // the provisioner's encryptedKey (JWE) from ca.json
	KeyPassword string
}

func New(o Options) (*Client, error) {
	root, err := LoadRoot(o.RootPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	sum := sha256.Sum256(root.Raw)

	enc, err := os.ReadFile(o.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read provisioner key: %w", err)
	}
	raw, err := jose.Decrypt(bytes.TrimSpace(enc), jose.WithPassword([]byte(o.KeyPassword)))
	if err != nil {
		return nil, fmt.Errorf("decrypt provisioner key: %w", err)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("parse provisioner key: %w", err)
	}
	if key.IsPublic() || key.KeyID == "" || key.Algorithm == "" {
		return nil, errors.New("provisioner key must be a private JWK with kid and alg")
	}

	return &Client{
		url: strings.TrimSuffix(o.URL, "/"),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		rootSHA:     hex.EncodeToString(sum[:]),
		provisioner: o.Provisioner,
		key:         &key,
		now:         time.Now,
	}, nil
}

// LoadRoot reads the CA root certificate (PEM).
func LoadRoot(path string) (*x509.Certificate, error) {
	rootPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA root: %w", err)
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CA root: no PEM certificate found")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA root: %w", err)
	}
	return root, nil
}

// Signed is the result of a sign request.
type Signed struct {
	Leaf *x509.Certificate
	// Chain holds the certificates after the leaf, issuer first.
	Chain []*x509.Certificate
}

// Sign asks step-ca to sign csrDER. The token authorizes exactly cn and sans
// and is bound to this CSR, so step-ca refuses any other request with it.
func (c *Client) Sign(ctx context.Context, csrDER []byte, cn string, sans []string, validity time.Duration) (*Signed, error) {
	sum := sha256.Sum256(csrDER)
	ott, err := c.token(cn, c.url+"/1.0/sign", map[string]any{
		"sans": sans,
		"cnf":  map[string]string{"x5rt#S256": base64.RawURLEncoding.EncodeToString(sum[:])},
	})
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"csr":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott":      ott,
		"notAfter": validity.String(),
	}
	var resp struct {
		CertChain []string `json:"certChain"`
	}
	if err := c.post(ctx, "/1.0/sign", body, &resp); err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, p := range resp.CertChain {
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			return nil, errors.New("sign response: bad PEM in certChain")
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("sign response: %w", err)
		}
		certs = append(certs, crt)
	}
	if len(certs) == 0 {
		return nil, errors.New("sign response: empty certChain")
	}
	return &Signed{Leaf: certs[0], Chain: certs[1:]}, nil
}

// Revoke revokes the certificate with the given serial (decimal). step-ca
// supports only passive revocation: it records the serial, refuses renewal
// and lists the serial in its CRL.
func (c *Client) Revoke(ctx context.Context, serial string, reasonCode int, reason string) error {
	ott, err := c.token(serial, c.url+"/1.0/revoke", map[string]any{})
	if err != nil {
		return err
	}
	body := map[string]any{"serial": serial, "ott": ott, "reasonCode": reasonCode, "reason": reason, "passive": true}
	var resp struct {
		Status string `json:"status"`
	}
	if err := c.post(ctx, "/1.0/revoke", body, &resp); err != nil {
		return err
	}
	if resp.Status != "ok" {
		return fmt.Errorf("step-ca revoke: unexpected status %q", resp.Status)
	}
	return nil
}

func (c *Client) token(sub, aud string, extra map[string]any) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(c.key.Algorithm), Key: c.key.Key},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", c.key.KeyID))
	if err != nil {
		return "", fmt.Errorf("token signer: %w", err)
	}
	jti := make([]byte, 16)
	rand.Read(jti)
	now := c.now()
	claims := jose.Claims{
		Issuer:    c.provisioner,
		Subject:   sub,
		Audience:  jose.Audience{aud},
		ID:        hex.EncodeToString(jti),
		IssuedAt:  jose.NewNumericDate(now),
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(tokenLifetime)),
	}
	extra["sha"] = c.rootSHA
	return jose.Signed(sig).Claims(claims).Claims(extra).Serialize()
}

// Error is a non-2xx response from step-ca.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("step-ca: %d %s", e.Status, e.Message) }

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("step-ca %s: %w", path, err)
	}
	// The body is read in full below; a close error changes nothing.
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("step-ca %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		return &Error{Status: resp.StatusCode, Message: e.Message}
	}
	return json.Unmarshal(data, out)
}
