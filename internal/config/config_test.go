package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"halbordnung.de/scep/internal/config"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		result  *config.Config
	}{
		{"valid", "valid.yaml", &config.Config{
			ListenAddr:    ":8081",
			ChallengeFile: "/run/secrets/challenge",
			Bao: config.BaoConfig{
				KubernetesRole: "scep-bridge",
				PKIMount:       "pki",
				SignRole:       "wifi",
				RARole:         "scep-ra",
				RATTL:          24 * time.Hour,
				RACommonName:   "scep-bridge",
			},
		}},
		{"missing fields", "missing.yaml", nil},
		{"wrong type", "wrong-type.yaml", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("testdata", tt.fixture)
			c, err := config.Load(path)
			if tt.result != nil && err != nil {
				t.Errorf("could not parse config %s: %v", path, err)
				return
			}
			if tt.result != nil && err == nil {
				if !reflect.DeepEqual(tt.result, c) {
					t.Errorf("loaded config did not match expected config. Got %v, expected %v", c, tt.result)
				}
				return
			}
			if tt.result == nil && err == nil {
				t.Errorf("Configuration loader should have errored but got %v", c)
				return
			}
		})
	}
}

func TestEnvOverwrites(t *testing.T) {
	t.Setenv("SCEP_BRIDGE_BAO_RA_TTL", "6h")
	c, err := config.Load("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("could not parse config: %v", err)
		return
	}
	if c.Bao.RATTL != 6*time.Hour {
		t.Errorf("Expected env override of RA TTL to 6h, got %v", c.Bao.RATTL)
	}
}

func TestLoadsRootCA(t *testing.T) {
	path := filepath.Join("testdata", "root-ca.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read fixture at %s: %v", path, err)
	}
	t.Setenv("SCEP_BRIDGE_BAO_ROOT_CA_CERTIFICATE", string(data))
	c, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("could not parse config: %v", err)
	}
	certs := c.Bao.RootCertificates()
	if len(certs) != 1 {
		t.Errorf("got %d root certificates, expected 1", len(certs))
	}
}

func TestRejectsIntermediateCA(t *testing.T) {
	path := filepath.Join("testdata", "intermediate-ca.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read fixture at %s: %v", path, err)
	}
	t.Setenv("SCEP_BRIDGE_BAO_ROOT_CA_CERTIFICATE", string(data))
	_, err = config.Load(filepath.Join("testdata", "valid.yaml"))
	if err == nil {
		t.Fatalf("Non self-signed CA certificate should have been rejected")
	}
}
