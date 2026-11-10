// Package config loads AuthStep's configuration from the environment.
//
// Secrets can be given directly or as a path in the matching *_FILE variable.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// BaseURL is the public URL users reach AuthStep on. The OIDC redirect URL
	// is BaseURL + "/auth/callback".
	BaseURL    *url.URL
	ListenAddr string
	DBPath     string

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	// OIDCSkipEmailVerified turns off the email_verified check. Load sets it
	// when AUTHSTEP_OIDC_REQUIRE_EMAIL_VERIFIED is false.
	OIDCSkipEmailVerified bool
	// GroupsClaim is the ID token claim that holds the user's groups.
	GroupsClaim string
	// IssuerGroup is required to use AuthStep at all.
	IssuerGroup string
	// AdminGroup grants admin rights.
	AdminGroup string

	CAURL         string
	CARootPath    string
	CAProvisioner string
	// CAKeyPath holds the JWK provisioner's encryptedKey (a JWE) from ca.json.
	CAKeyPath     string
	CAKeyPassword string

	// InternalListenAddr serves step-ca's SCEP webhooks over mTLS.
	InternalListenAddr string
	InternalTLSCert    string
	InternalTLSKey     string
	// SCEPURL is the step-ca SCEP endpoint devices enrol against.
	SCEPURL string
	// ProfileSigningCert and ProfileSigningKey sign .mobileconfig files. Use a
	// publicly trusted certificate so devices show the profile as verified.
	ProfileSigningCert string
	ProfileSigningKey  string

	// SMTPAddr (host:port) enables email. Empty disables all email.
	SMTPAddr     string
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword string
	// SMTPAllowPlaintext permits sending without TLS when the server does not
	// offer STARTTLS, e.g. an internal relay on port 25.
	SMTPAllowPlaintext bool
	// AdminEmail receives every audit event. Optional.
	AdminEmail string

	// TrustedProxies are the reverse proxies whose X-Forwarded-For header is
	// used for the client IP in the audit log.
	TrustedProxies []netip.Prefix
}

// Load reads the configuration from environment variables.
func Load() (*Config, error) {
	var errs []error
	req := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
		return v
	}

	c := &Config{
		ListenAddr:  getDefault("AUTHSTEP_LISTEN_ADDR", ":8080"),
		DBPath:      getDefault("AUTHSTEP_DB_PATH", "authstep.db"),
		OIDCIssuer:  req("AUTHSTEP_OIDC_ISSUER"),
		GroupsClaim: getDefault("AUTHSTEP_OIDC_GROUPS_CLAIM", "groups"),
		IssuerGroup: req("AUTHSTEP_ISSUER_GROUP"),
		AdminGroup:  req("AUTHSTEP_ADMIN_GROUP"),

		CAURL:         req("AUTHSTEP_CA_URL"),
		CARootPath:    req("AUTHSTEP_CA_ROOT"),
		CAProvisioner: req("AUTHSTEP_CA_PROVISIONER"),
		CAKeyPath:     req("AUTHSTEP_CA_PROVISIONER_KEY"),

		InternalListenAddr: getDefault("AUTHSTEP_INTERNAL_LISTEN_ADDR", ":9443"),
		InternalTLSCert:    req("AUTHSTEP_INTERNAL_TLS_CERT"),
		InternalTLSKey:     req("AUTHSTEP_INTERNAL_TLS_KEY"),
		SCEPURL:            req("AUTHSTEP_SCEP_URL"),
		ProfileSigningCert: req("AUTHSTEP_PROFILE_SIGNING_CERT"),
		ProfileSigningKey:  req("AUTHSTEP_PROFILE_SIGNING_KEY"),

		SMTPAddr:     os.Getenv("AUTHSTEP_SMTP_ADDR"),
		SMTPUsername: os.Getenv("AUTHSTEP_SMTP_USERNAME"),
		AdminEmail:   os.Getenv("AUTHSTEP_ADMIN_EMAIL"),
	}
	if v := os.Getenv("AUTHSTEP_OIDC_REQUIRE_EMAIL_VERIFIED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("AUTHSTEP_OIDC_REQUIRE_EMAIL_VERIFIED: %w", err))
		}
		c.OIDCSkipEmailVerified = !b
	}
	if c.SMTPAddr != "" {
		c.SMTPFrom = req("AUTHSTEP_SMTP_FROM")
		if v := os.Getenv("AUTHSTEP_SMTP_ALLOW_PLAINTEXT"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("AUTHSTEP_SMTP_ALLOW_PLAINTEXT: %w", err))
			}
			c.SMTPAllowPlaintext = b
		}
		if c.SMTPUsername != "" {
			pass, err := secret("AUTHSTEP_SMTP_PASSWORD")
			if err != nil {
				errs = append(errs, err)
			}
			c.SMTPPassword = pass
		}
	} else if c.AdminEmail != "" {
		errs = append(errs, errors.New("AUTHSTEP_ADMIN_EMAIL needs AUTHSTEP_SMTP_ADDR"))
	}

	clientID, err := secret("AUTHSTEP_OIDC_CLIENT_ID")
	if err != nil {
		errs = append(errs, err)
	}
	c.OIDCClientID = clientID

	clientSecret, err := secret("AUTHSTEP_OIDC_CLIENT_SECRET")
	if err != nil {
		errs = append(errs, err)
	}
	c.OIDCClientSecret = clientSecret

	caPass, err := secret("AUTHSTEP_CA_PROVISIONER_PASSWORD")
	if err != nil {
		errs = append(errs, err)
	}
	c.CAKeyPassword = caPass

	base := req("AUTHSTEP_BASE_URL")
	if base != "" {
		u, err := url.Parse(strings.TrimSuffix(base, "/"))
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("AUTHSTEP_BASE_URL: %w", err))
		case u.Scheme != "https" && !isLocalhost(u.Hostname()):
			errs = append(errs, errors.New("AUTHSTEP_BASE_URL must use https (http is allowed only for localhost and *.localhost)"))
		default:
			c.BaseURL = u
		}
	}

	for _, s := range strings.Split(os.Getenv("AUTHSTEP_TRUSTED_PROXIES"), ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("AUTHSTEP_TRUSTED_PROXIES: %w", err))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// isLocalhost reports names browsers treat as secure over plain http.
func isLocalhost(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func getDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// secret reads NAME, or the file named by NAME_FILE. Exactly one must be set.
func secret(name string) (string, error) {
	v, path := os.Getenv(name), os.Getenv(name+"_FILE")
	switch {
	case v != "" && path != "":
		return "", fmt.Errorf("set only one of %s and %s_FILE", name, name)
	case v != "":
		return v, nil
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("%s or %s_FILE is required", name, name)
}
