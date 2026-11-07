package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Mailer sends one plain-text email.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

const smtpTimeout = 30 * time.Second

// SMTP sends mail through one server. Port 465 uses implicit TLS; any other
// port must offer STARTTLS unless the server is on localhost.
type SMTP struct {
	addr, host string
	from       mail.Address
	username   string
	password   string
	roots      *x509.CertPool
}

// NewSMTP returns a mailer that verifies the server against roots, so an
// internal relay can use a certificate from the AuthStep CA.
func NewSMTP(addr, from, username, password string, roots *x509.CertPool) (*SMTP, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("SMTP address: %w", err)
	}
	f, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("SMTP from address: %w", err)
	}
	return &SMTP{addr: addr, host: host, from: *f, username: username, password: password, roots: roots}, nil
}

func (m *SMTP) Send(ctx context.Context, to, subject, body string) error {
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	msg, err := message(m.from, *rcpt, subject, body)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()
	tlsConf := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12, RootCAs: m.roots}
	var conn net.Conn
	if strings.HasSuffix(m.addr, ":465") {
		conn, err = (&tls.Dialer{Config: tlsConf}).DialContext(ctx, "tcp", m.addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", m.addr)
	}
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return errors.Join(err, conn.Close())
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return errors.Join(err, conn.Close())
	}
	defer func() { _ = c.Close() }() // Quit below reports the meaningful error

	if _, isTLS := conn.(*tls.Conn); !isTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConf); err != nil {
				return err
			}
		} else if !isLocalhost(m.host) {
			return fmt.Errorf("SMTP server %s does not offer STARTTLS", m.addr)
		}
	}
	if m.username != "" {
		// PlainAuth refuses to send credentials without TLS, except to localhost.
		if err := c.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return errors.Join(err, w.Close())
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func isLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// message builds a quoted-printable UTF-8 email. Header values have line
// breaks removed so user-controlled text cannot add headers.
func message(from, to mail.Address, subject, body string) ([]byte, error) {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	oneLine := strings.NewReplacer("\r", " ", "\n", " ")
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	fmt.Fprintf(&b, "To: %s\r\n", to.String())
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", oneLine.Replace(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@authstep>\r\n", hex.EncodeToString(id))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
