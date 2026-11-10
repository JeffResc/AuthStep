package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JeffResc/AuthStep/internal/audit"
	"github.com/JeffResc/AuthStep/internal/auth"
	"github.com/JeffResc/AuthStep/internal/ca"
	"github.com/JeffResc/AuthStep/internal/certs"
	"github.com/JeffResc/AuthStep/internal/config"
	"github.com/JeffResc/AuthStep/internal/keypair"
	"github.com/JeffResc/AuthStep/internal/notify"
	"github.com/JeffResc/AuthStep/internal/scep"
	"github.com/JeffResc/AuthStep/internal/store"
	"github.com/JeffResc/AuthStep/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("close store", "err", err)
		}
	}()

	// Email is optional: without SMTP, nothing is queued.
	var notifier audit.Notifier
	if cfg.SMTPAddr != "" {
		// Trust public CAs and the AuthStep root, so internal relays can use it.
		roots, err := x509.SystemCertPool()
		if err != nil {
			return err
		}
		root, err := ca.LoadRoot(cfg.CARootPath)
		if err != nil {
			return err
		}
		roots.AddCert(root)
		mailer, err := notify.NewSMTP(cfg.SMTPAddr, cfg.SMTPFrom, cfg.SMTPUsername, cfg.SMTPPassword, roots, cfg.SMTPAllowPlaintext)
		if err != nil {
			return err
		}
		n := notify.New(st, cfg.BaseURL.String(), cfg.AdminEmail, log)
		notifier = n
		go notify.NewOutbox(st, mailer, log).Run(ctx)
		go n.RunReminders(ctx)
	} else {
		log.Warn("AUTHSTEP_SMTP_ADDR is not set; no emails will be sent")
	}
	if cfg.OIDCSkipEmailVerified {
		log.Warn("AUTHSTEP_OIDC_REQUIRE_EMAIL_VERIFIED is false; sign-in accepts unverified email addresses")
	}
	rec := audit.New(st, notifier, cfg.TrustedProxies, log)
	a, err := auth.New(ctx, cfg, st, rec, log)
	if err != nil {
		return err
	}
	caClient, err := ca.New(ca.Options{
		URL:         cfg.CAURL,
		RootPath:    cfg.CARootPath,
		Provisioner: cfg.CAProvisioner,
		KeyPath:     cfg.CAKeyPath,
		KeyPassword: cfg.CAKeyPassword,
	})
	if err != nil {
		return err
	}
	signer, err := keypair.Load(cfg.ProfileSigningCert, cfg.ProfileSigningKey)
	if err != nil {
		return err
	}
	scepSvc := scep.New(st, rec, signer, cfg.SCEPURL, log)
	handler, err := web.New(a, certs.New(st, caClient, log), scepSvc, st, rec, log, cfg.BaseURL)
	if err != nil {
		return err
	}
	internal, err := internalServer(cfg, scepSvc)
	if err != nil {
		return err
	}

	go cleanupSessions(ctx, st, log)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 2)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL.String(), "version", version)
		errc <- srv.ListenAndServe()
	}()
	go func() {
		log.Info("listening for step-ca webhooks", "addr", cfg.InternalListenAddr)
		errc <- internal.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return errors.Join(ignoreClosed(srv.Shutdown(shutdownCtx)), ignoreClosed(internal.Shutdown(shutdownCtx)))
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// internalServer serves step-ca's SCEP webhooks. Callers must present a
// client certificate from the CA's root that names the step-ca host, which is
// step-ca's own TLS certificate.
func internalServer(cfg *config.Config, svc *scep.Service) (*http.Server, error) {
	pair, err := keypair.Load(cfg.InternalTLSCert, cfg.InternalTLSKey)
	if err != nil {
		return nil, err
	}
	root, err := ca.LoadRoot(cfg.CARootPath)
	if err != nil {
		return nil, err
	}
	caURL, err := url.Parse(cfg.CAURL)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /scep/challenge", svc.Challenge)
	mux.HandleFunc("POST /scep/notify", svc.Notify)
	return &http.Server{
		Addr:              cfg.InternalListenAddr,
		Handler:           scep.RequireCA(caURL.Hostname(), mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      roots,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return pair.Get() },
		},
	}, nil
}

func cleanupSessions(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			n, err := st.DeleteExpiredSessions(ctx, now.Add(-auth.SessionIdle), now.Add(-auth.SessionMax))
			if err != nil {
				log.Error("session cleanup", "err", err)
				continue
			}
			log.Info("session cleanup", "deleted", n)
		}
	}
}
