package challenge

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"os"

	"halbordnung.de/scep/internal/openbao"
)

var (
	ErrMismatchedChallenge = errors.New("challenge was mismatched")
)

type Static struct {
	path         string
	clientSource openbao.ClientSource
	signingRole  string
}

func NewStatic(path string, clientSource openbao.ClientSource, signingRole string) (*Static, error) {
	_, err := readChallenge(path)
	if err != nil {
		return nil, err
	}
	return &Static{
		path:         path,
		clientSource: clientSource,
		signingRole:  signingRole,
	}, nil
}

func readChallenge(path string) (ChallengeBytes, error) {
	dat, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dat = bytes.TrimSpace(dat)
	if len(dat) == 0 {
		return nil, errors.New("challenge file is empty")
	}
	if len(dat) > 255 {
		return nil, errors.New("challenge is too long")
	}
	return dat, nil
}

func (s *Static) Resolve(ctx context.Context, csr *x509.CertificateRequest, challenge Challenge) (*Context, error) {
	expected, err := readChallenge(s.path)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(challenge), expected) != 1 {
		return nil, ErrMismatchedChallenge
	}
	client, err := s.clientSource.Client(ctx)
	if err != nil {
		return nil, err
	}
	return NewContext(client, s.signingRole, csr)
}
