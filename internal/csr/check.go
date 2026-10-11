package csr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	ErrMissingCSR   = errors.New("csr: missing")
	ErrKeyAlgorithm = errors.New("csr: unsupported public key algorithm")
	ErrKeySize      = errors.New("csr: key size out of bounds")
	ErrSANPresent   = errors.New("csr: subject alternative names not permitted")
	ErrSignature    = errors.New("csr: signature verification failed")
)

var AllErrors = []error{
	ErrMissingCSR, ErrKeyAlgorithm, ErrKeySize, ErrSANPresent, ErrSignature,
}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

func checkAlgorithm(csr *x509.CertificateRequest) error {
	if csr.PublicKeyAlgorithm == x509.DSA || csr.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return ErrKeyAlgorithm
	}
	return nil
}

func checkBitSize(csr *x509.CertificateRequest) error {
	if csr.PublicKeyAlgorithm == x509.RSA {
		rsaKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return ErrKeyAlgorithm
		}
		if rsaKey.N.BitLen() < 2048 || rsaKey.N.BitLen() > 8192 {
			return ErrKeySize
		}
	} else if csr.PublicKeyAlgorithm == x509.ECDSA {
		ecdsaKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrKeyAlgorithm
		}
		if ecdsaKey.Curve.Params().BitSize < elliptic.P256().Params().BitSize {
			return ErrKeySize
		}
	}
	return nil
}

func checkSignature(csr *x509.CertificateRequest) error {
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("csr signature: %w: %w", ErrSignature, err)
	}
	return nil
}

func checkSANs(csr *x509.CertificateRequest) error {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			return ErrSANPresent
		}
	}
	return nil
}

// CheckCertificateSigningRequest validates the CSR against requirements imposed by OpenBAO or us.
func CheckCertificateSigningRequest(csr *x509.CertificateRequest) error {
	if csr == nil {
		return ErrMissingCSR
	}
	return errors.Join(checkAlgorithm(csr), checkBitSize(csr), checkSANs(csr), checkSignature(csr))
}
