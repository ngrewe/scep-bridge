package transport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"halbordnung.de/scep/internal/challenge"
)

const (
	CapAES              = "AES"
	CapPOSTPKIOperation = "POSTPKIOperation"
	CapSCEPStandard     = "SCEPStandard"
	CapSHA256           = "SHA-256"
	CapSHA512           = "SHA-512"
	OpGetCACaps         = "GetCACaps"
	OpGetCACert         = "GetCACert"
	OpPKIOperation      = "PKIOperation"
)

var (
	AllCaps = []byte(strings.Join([]string{CapAES, CapPOSTPKIOperation, CapSCEPStandard, CapSHA256, CapSHA512}, "\n"))
)

type RACertificateProvider interface {
	GetSigningCertAndKey(ctx context.Context) (*x509.Certificate, crypto.Decrypter, error)
	GetCertificateCollection(ctx context.Context) ([]*x509.Certificate, error)
}

type Signer interface {
	Sign(ctx context.Context, csr *x509.CertificateRequest, challenge challenge.Challenge) (*x509.Certificate, error)
}

type Handler struct {
	ra     RACertificateProvider
	signer Signer
	logger *slog.Logger
}

func NewHandler(ra RACertificateProvider, signer Signer, logger *slog.Logger) *Handler {
	return &Handler{
		ra:     ra,
		signer: signer,
		logger: logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("operation") {
	case OpGetCACaps:
		h.getCaCaps(w, r)
	case OpGetCACert:
		h.getCaCerts(w, r)
	case OpPKIOperation:
		h.postPKIOperation(w, r)
	default:
		h.logger.Warn("operation unknown", "operation", r.URL.Query().Get("operation"))
		http.Error(w, "unknown operation", http.StatusBadRequest)
	}
}

func (h *Handler) getCaCaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(AllCaps)
}

func (h *Handler) getCaCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	var buf bytes.Buffer
	certs, err := h.ra.GetCertificateCollection(r.Context())
	if err != nil {
		h.logger.Error("could not retrieve certificates", "error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}

	degenerate, err := pkcs7.DegenerateCertificate(buf.Bytes())
	if err != nil {
		h.logger.Error("could not wrap certificates in CMS envelope", "error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
	_, _ = w.Write(degenerate)
}

func (h *Handler) postPKIOperation(w http.ResponseWriter, r *http.Request) {
	var msg *scep.PKIMessage
	var eCert *x509.Certificate
	var eKey crypto.Decrypter
	logger := h.logger
	defer func() {
		if recovery := recover(); recovery != nil {
			if msg != nil && eKey != nil && eCert != nil {
				h.writeFailure(w, msg, eCert, eKey)
			} else {
				http.Error(w, "", http.StatusInternalServerError)
			}
		}
	}()
	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Warn("could not read body", "error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	msg, err = scep.ParsePKIMessage(body)
	if err != nil {
		logger.Warn("could not parse PKI message", "error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	logger = logger.With("transaction_id", msg.TransactionID)

	eCert, eKey, err = h.ra.GetSigningCertAndKey(r.Context())
	if err != nil {
		logger.Error("could not retrieve RA certificate for envelope encryption", "error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	clientCert, err := h.issueCert(r.Context(), msg, eCert, eKey, logger)
	if err != nil {
		if errors.Is(err, challenge.ErrMismatchedChallenge) {
			logger.Warn("challenge mismatched in CSR", "error", err)
		} else {
			logger.Error("failed to issue certificate from OpenBAO", "error", err)
		}
		h.writeFailure(w, msg, eCert, eKey)
		return
	}
	logger = logger.With("serial", clientCert.SerialNumber.String())
	responseMessage, err := msg.Success(eCert, eKey, clientCert)
	if err != nil {
		logger.Error("OpenBAO issued the certificate, but we could not send it. It needs revoking", "error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pki-message")
	_, _ = w.Write(responseMessage.Raw)
}

func (h *Handler) issueCert(ctx context.Context, msg *scep.PKIMessage, eCert *x509.Certificate, eKey crypto.Decrypter, logger *slog.Logger) (*x509.Certificate, error) {
	err := msg.DecryptPKIEnvelope(eCert, eKey)
	if err != nil {
		return nil, err
	}
	if msg.MessageType != scep.PKCSReq || msg.CSRReqMessage == nil {
		return nil, errors.New("unsupported message type")
	}
	if msg.CSR == nil {
		return nil, errors.New("missing CSR")
	}
	clientCert, err := h.signer.Sign(ctx, msg.CSR, challenge.Challenge(msg.ChallengePassword))
	if err != nil {
		return nil, err
	}
	logger.Info("issued new certificate", "serial", clientCert.SerialNumber.String(), "common_name", clientCert.Subject.CommonName)
	return clientCert, nil
}

func (h *Handler) writeFailure(w http.ResponseWriter, msg *scep.PKIMessage, eCert *x509.Certificate, eKey crypto.Decrypter) {
	response, err := msg.Fail(eCert, eKey, scep.BadRequest)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pki-message")
	_, _ = w.Write(response.Raw)
}

func WithRecovery(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
				logger.Error("panic serving request", "panic", rec, "stack", string(debug.Stack()))
				http.Error(w, "", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
