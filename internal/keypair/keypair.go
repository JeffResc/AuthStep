// Package keypair serves a certificate and key from files and reloads them
// when they change, so certificates rotated by cert-manager are picked up
// without a restart.
package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

type File struct {
	certPath, keyPath string

	mu              sync.Mutex
	certMod, keyMod time.Time
	cert            *tls.Certificate
}

// Load reads the pair once so configuration errors show at startup.
func Load(certPath, keyPath string) (*File, error) {
	f := &File{certPath: certPath, keyPath: keyPath}
	if _, err := f.Get(); err != nil {
		return nil, err
	}
	return f, nil
}

// Get returns the current pair, reloading it if either file changed.
func (f *File) Get() (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cm, err := modTime(f.certPath)
	if err != nil {
		return nil, err
	}
	km, err := modTime(f.keyPath)
	if err != nil {
		return nil, err
	}
	if f.cert != nil && cm.Equal(f.certMod) && km.Equal(f.keyMod) {
		return f.cert, nil
	}
	c, err := tls.LoadX509KeyPair(f.certPath, f.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", f.certPath, err)
	}
	f.cert, f.certMod, f.keyMod = &c, cm, km
	return f.cert, nil
}

// Chain returns the leaf and the remaining certificates from the cert file.
func (f *File) Chain() (*tls.Certificate, []*x509.Certificate, error) {
	c, err := f.Get()
	if err != nil {
		return nil, nil, err
	}
	var rest []*x509.Certificate
	for _, der := range c.Certificate[1:] {
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, err
		}
		rest = append(rest, crt)
	}
	return c, rest, nil
}

func modTime(path string) (time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return st.ModTime(), nil
}
