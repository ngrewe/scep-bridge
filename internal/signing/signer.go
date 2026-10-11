package signing

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"halbordnung.de/scep/internal/challenge"
)

type Resolver interface {
	Resolve(ctx context.Context, csr *x509.CertificateRequest, challenge challenge.Challenge) (*challenge.Context, error)
}

type Signer struct {
	pkiMount string
	resolver Resolver
}

func NewSigner(pkiMount string, resolver Resolver) *Signer {
	return &Signer{
		pkiMount: pkiMount,
		resolver: resolver,
	}
}

func (s *Signer) Sign(ctx context.Context, csr *x509.CertificateRequest, challenge challenge.Challenge) (*x509.Certificate, error) {
	sCtx, err := s.resolver.Resolve(ctx, csr, challenge)
	if err != nil {
		return nil, err
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: sCtx.CSR().Raw})
	resp, err := sCtx.Client().Logical().Write(fmt.Sprintf("%s/sign/%s", s.pkiMount, sCtx.Role()), map[string]interface{}{
		"common_name": sCtx.CSR().Subject.CommonName,
		"format":      "der",
		"csr":         string(csrPem),
	})
	if err != nil {
		return nil, err
	}
	certData, ok := resp.Data["certificate"].(string)
	if !ok {
		return nil, ErrNoCertificateInResponse
	}
	certBytes, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
