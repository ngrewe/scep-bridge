package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smallstep/pkcs7"
	"halbordnung.de/scep/internal/challenge"
	"halbordnung.de/scep/internal/config"
	"halbordnung.de/scep/internal/openbao"
	"halbordnung.de/scep/internal/signing"
	"halbordnung.de/scep/internal/transport"
)

func main() {
	configPath := flag.String("config",
		cmp.Or(os.Getenv("SCEP_CONFIG"), "/etc/scep/config.yaml"),
		"path to the configuration file")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(*configPath, logger); err != nil {
		logger.Error("a fatal error occurred", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {

	err := pkcs7.SetDefaultDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA512)
	if err != nil {
		return err
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	certs := cfg.Bao.RootCertificates()
	if len(certs) > 0 {
		subjects := make([]string, 0, len(certs))
		for _, cert := range certs {
			subjects = append(subjects, cert.Subject.String())
		}
		logger.Info("Extra root certificates configured", "authorities", subjects)
	}

	var clientSource openbao.ClientSource
	clientSource, err = openbao.NewStatic()
	if err != nil {
		if errors.Is(err, openbao.ErrNoToken) {
			if cfg.Bao.KubernetesRole != "" {
				clientSource = openbao.NewKubernetes(cfg.Bao.KubernetesRole)
			} else {
				return errors.New("no authentication source for OpenBAO found. Either provide a BAO_TOKEN or a Kubernetes role")
			}
		} else {
			return err
		}
	}
	logger.Info("selected OpenBAO client source", "clientSource", clientSource)
	staticChallenge, err := challenge.NewStatic(cfg.ChallengeFile, clientSource, cfg.Bao.SignRole)
	if err != nil {
		return err
	}
	ra := signing.NewRA(cfg.Bao.PKIMount, cfg.Bao.RARole, cfg.Bao.RATTL, cfg.Bao.RACommonName, clientSource, cfg.Bao.RootCertificates())
	signer := signing.NewSigner(cfg.Bao.PKIMount, staticChallenge)
	handler := transport.WithRecovery(logger, transport.NewHandler(ra, signer, logger))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	shutdownDone := make(chan struct{})

	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		logger.Info("shutting down server")
		stop() // remove the signal handler again

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "err", err)
		}
	}()
	logger.Info("listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-shutdownDone
	logger.Info("shutdown complete")
	return nil
}
