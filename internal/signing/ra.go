package signing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"halbordnung.de/scep/internal/openbao"
)

var (
	ErrCertificateExpired      = errors.New("ra: certificate expired")
	ErrNoCertificateInResponse = errors.New("ra: no certificate in response")
)

type RA struct {
	mu           sync.Mutex           // mutex to protect renewals
	pkiMount     string               // Where the pki provider is mounted
	raRole       string               // which role to use when generating RA certs
	raTTL        time.Duration        // time for TTL
	cn           string               // common name for the certificate
	clientSource openbao.ClientSource // provider for the client
	signingKey   *rsa.PrivateKey      // The signing key for the RA
	signingCert  *x509.Certificate    // The signing certificate for the RA
	chainCerts   []*x509.Certificate  // Certificates that come from OpenBAOs chain
	extraCerts   []*x509.Certificate  // Extra certificates injected by the operator
}

func NewRA(pkiMount string, raRole string, raTTL time.Duration, cn string, clientSource openbao.ClientSource, extraCerts []*x509.Certificate) *RA {
	return &RA{
		pkiMount:     pkiMount,
		raRole:       raRole,
		raTTL:        raTTL,
		cn:           cn,
		clientSource: clientSource,
		extraCerts:   extraCerts,
	}
}

func (ra *RA) needRenewal() bool {
	if ra.signingKey == nil || ra.signingCert == nil || ra.signingCert.NotAfter.Before(time.Now().Add(30*time.Second)) {
		return true
	}
	return false
}

func (ra *RA) GetSigningCertAndKey(ctx context.Context) (*x509.Certificate, crypto.Decrypter, error) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	err := ra.ensureSigningCert(ctx)
	if err != nil {
		return nil, nil, err
	}
	return ra.signingCert, ra.signingKey, nil
}

func (ra *RA) GetCertificateCollection(ctx context.Context) ([]*x509.Certificate, error) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	err := ra.ensureSigningCert(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*x509.Certificate, 0, len(ra.chainCerts)+len(ra.extraCerts)+1)
	out = append(out, ra.extraCerts...)
	out = append(out, ra.chainCerts...)
	out = append(out, ra.signingCert)
	return out, nil
}

// only under ra.mu lock!
func (ra *RA) ensureSigningCert(ctx context.Context) error {
	if !ra.needRenewal() {
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	subject := pkix.Name{
		CommonName: ra.cn,
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA512WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return err
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	client, err := ra.clientSource.Client(ctx)
	if err != nil {
		return err
	}
	resp, err := client.Logical().Write(fmt.Sprintf("%s/sign/%s", ra.pkiMount, ra.raRole), map[string]interface{}{
		"common_name": ra.cn,
		"ttl":         fmt.Sprintf("%d", int(ra.raTTL.Seconds())),
		"format":      "der",
		"csr":         string(csrPem),
	})
	if err != nil {
		return err
	}
	if resp == nil {
		// Not sure why this should happen, but let's be safe
		return ErrNoCertificateInResponse
	}

	certData, ok := resp.Data["certificate"].(string)
	if !ok {
		return ErrNoCertificateInResponse
	}
	certBytes, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}
	chainCertDatas, ok := resp.Data["ca_chain"].([]any)
	if ok {
		chainCerts := make([]*x509.Certificate, len(chainCertDatas))
		for i, chainCertData := range chainCertDatas {
			chainCertString, elementOk := chainCertData.(string)
			if !elementOk {
				return errors.New("ra: failed to parse chain certificate")
			}
			chainCertBytes, err := base64.StdEncoding.DecodeString(chainCertString)
			if err != nil {
				return err
			}
			chainCert, err := x509.ParseCertificate(chainCertBytes)
			if err != nil {
				return err
			}
			chainCerts[i] = chainCert
		}
		ra.chainCerts = chainCerts
	} else {
		ra.chainCerts = []*x509.Certificate{}
	}
	ra.signingKey = key
	ra.signingCert = cert
	return nil
}
