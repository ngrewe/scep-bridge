package signing_test

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/smallstep/scep"
	"go.step.sm/crypto/pemutil"
)

func TestCanReadAppleScep(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "apple-macos-pkcsreq.der"))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := scep.ParsePKIMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if msg.MessageType != scep.PKCSReq {
		t.Errorf("Wrong message type expected PKCSReq(19), got %s", msg.MessageType)
	}
	err = msg.DecryptPKIEnvelope(getSignerCert(t), getSignerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if msg.ChallengePassword != "spike" {
		t.Errorf("Wrong challenge password expected 'spike', got %s", msg.ChallengePassword)
	}
}

func getSignerCert(t *testing.T) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "irving.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pemutil.ParseCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func getSignerKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	pemData, err := os.ReadFile(filepath.Join("testdata", "irving.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
