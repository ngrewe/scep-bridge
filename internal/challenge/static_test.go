package challenge_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"halbordnung.de/scep/internal/challenge"
	"halbordnung.de/scep/internal/openbao"
)

func TestResolvesMatchingChallenge(t *testing.T) {
	challengeString := "Mr. Lamb succeeds not by conforming to the Spirit of the Age, but in opposition to it"
	resolver := makeStaticResolver(t, challengeString)
	_, err := resolver.Resolve(t.Context(), makeCsr("device.wifi"), challenge.Challenge(challengeString))
	if err != nil {
		t.Fatalf("Challenge was not verified: %v", err)
	}
}

func TestResolvesMatchingChallengeWithNewLine(t *testing.T) {
	challengeString := "Mr. Lamb succeeds not by conforming to the Spirit of the Age, but in opposition to it"
	resolver := makeStaticResolver(t, challengeString+"\n")
	_, err := resolver.Resolve(t.Context(), makeCsr("device.wifi"), challenge.Challenge(challengeString))
	if err != nil {
		t.Fatalf("Challenge was not verified: %v", err)
	}
}

func TestDoesNotResolveUnmatchedChallenge(t *testing.T) {
	challengeString := "Mr. Lamb succeeds not by conforming to the Spirit of the Age, but in opposition to it"
	resolver := makeStaticResolver(t, challengeString+"\n")
	_, err := resolver.Resolve(t.Context(), makeCsr("device.wifi"), "He does not march boldly along with the crowd, but steals off the pavement to pick his way in the contrary direction.")
	if !errors.Is(err, challenge.ErrMismatchedChallenge) {
		t.Fatalf("Challenge should have been rejected, but  %v", err)
	}
}

func TestDoesNotResolveEmptyChallenge(t *testing.T) {
	challengeString := "Mr. Lamb succeeds not by conforming to the Spirit of the Age, but in opposition to it"
	resolver := makeStaticResolver(t, challengeString+"\n")
	_, err := resolver.Resolve(t.Context(), makeCsr("device.wifi"), "")
	if !errors.Is(err, challenge.ErrMismatchedChallenge) {
		t.Fatalf("Challenge should have been rejected, but %v", err)
	}
}

func TestRejectsEmptyChallenge(t *testing.T) {
	path := writeChallengeFile(t, "")
	clientSource := makeClientSource(t)
	_, err := challenge.NewStatic(path, clientSource, "wifi-pki")
	if err == nil {
		t.Fatal("empty challenge should have been rejected")
	}
}

func TestRejectsOverlyLongChallenge(t *testing.T) {
	path := writeChallengeFile(t, strings.Repeat("a", 256))
	clientSource := makeClientSource(t)
	_, err := challenge.NewStatic(path, clientSource, "wifi-pki")
	if err == nil {
		t.Fatal("challenge > 255 bytes should have been rejected")
	}
}

// Write the challenge to the file, return the path
func writeChallengeFile(t *testing.T, challenge string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "challenge")
	err := os.WriteFile(path, []byte(challenge), 0644)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func makeClientSource(t *testing.T) openbao.ClientSource {
	t.Helper()
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return &fakeClientSource{c: client}
}

func makeStaticResolver(t *testing.T, challengeValue string) *challenge.Static {
	path := writeChallengeFile(t, challengeValue)
	clientSource := makeClientSource(t)
	resolver, err := challenge.NewStatic(path, clientSource, "wifi-pki")
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func makeCsr(commonName string) *x509.CertificateRequest {
	subject := pkix.Name{
		CommonName: commonName,
	}
	return &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
}

type fakeClientSource struct{ c *api.Client }

func (f fakeClientSource) Client(context.Context) (*api.Client, error) { return f.c, nil }
