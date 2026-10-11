// Package config loading - conceptually lifted from Ory's Oathkeeper and other stuff, simplified. Hence, parts of this
// code copyright © 2023 Ory Corp, licensed under the Apache 2.0 license.
package config

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/kaptinlin/jsonschema"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	"go.step.sm/crypto/pemutil"
)

//go:embed config.schema.json
var schemaJson []byte

//go:embed config.defaults.json
var defaultsJson []byte

type BaoConfig struct {
	KubernetesRole    string        `koanf:"kubernetesRole"`
	PKIMount          string        `koanf:"pkiMount"`
	SignRole          string        `koanf:"signRole"`
	RARole            string        `koanf:"raRole"`
	RATTL             time.Duration `koanf:"raTTL"`
	RACommonName      string        `koanf:"raCommonName"`
	RootCaCertificate string        `koanf:"rootCaCertificate"`
	rootCertificates  []*x509.Certificate
}

func (c *BaoConfig) RootCertificates() []*x509.Certificate {
	return c.rootCertificates
}

type Config struct {
	ListenAddr    string    `koanf:"listenAddr"`
	ChallengeFile string    `koanf:"challengeFile"`
	Bao           BaoConfig `koanf:"bao"`
}

// envKeys maps the handful of env keys we have into the config schemaJson, if we ever need more, we should consider reversing
// this from the schemaJson
var envKeys = map[string]string{
	"SCEP_BRIDGE_LISTEN_ADDR":             "listenAddr",
	"SCEP_BRIDGE_CHALLENGE_FILE":          "challengeFile",
	"SCEP_BRIDGE_BAO_KUBERNETES_ROLE":     "bao.kubernetesRole",
	"SCEP_BRIDGE_BAO_PKI_MOUNT":           "bao.pkiMount",
	"SCEP_BRIDGE_BAO_SIGN_ROLE":           "bao.signRole",
	"SCEP_BRIDGE_BAO_RA_ROLE":             "bao.raRole",
	"SCEP_BRIDGE_BAO_RA_TTL":              "bao.raTTL",
	"SCEP_BRIDGE_BAO_RA_COMMON_NAME":      "bao.raCommonName",
	"SCEP_BRIDGE_BAO_ROOT_CA_CERTIFICATE": "bao.rootCaCertificate",
}

// mapEnvKey is a simple lookup from envKeys
func mapEnvKey(k, v string) (string, any) {
	key, ok := envKeys[k]
	if !ok {
		// don't expose any unknown keys
		return "", nil
	}
	return key, v
}

func Load(configPath string) (*Config, error) {
	k := koanf.New(".")

	// 1. defaults
	if err := k.Load(rawbytes.Provider(defaultsJson), json.Parser()); err != nil {
		return nil, fmt.Errorf("loading defaults: %w", err)
	}

	if configPath != "" {
		// 2. config file
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("parsing config file %s: %w", configPath, err)
		}
	}
	// 3. environment
	if err := k.Load(env.Provider(".", env.Opt{
		Prefix:        "SCEP_BRIDGE_",
		TransformFunc: mapEnvKey,
	}), nil); err != nil {
		return nil, fmt.Errorf("problem loading environment variables: %w", err)
	}

	// Roundtrip the merged values through the JSON schema
	schema, err := jsonschema.NewCompiler().Compile(schemaJson)
	if err != nil {
		return nil, fmt.Errorf("compiling schema: %w", err)
	}
	merged, err := k.Marshal(json.Parser())
	if err != nil {
		return nil, fmt.Errorf("marshalling merged config: %w", err)
	}
	result := schema.ValidateJSON(merged)
	if !result.IsValid() {
		return nil, fmt.Errorf("merged config is invalid: %v", result.DetailedErrors())
	}
	var config Config
	err = k.UnmarshalWithConf("", &config, koanf.UnmarshalConf{Tag: "koanf"})
	if err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	if config.Bao.RootCaCertificate != "" {
		certs, err := pemutil.ParseCertificateBundle([]byte(config.Bao.RootCaCertificate))
		if err != nil {
			return nil, fmt.Errorf("parsing root CA certificate(s): %w", err)
		}
		containsSelfSignedCert := false
		for _, cert := range certs {
			if cert.CheckSignatureFrom(cert) == nil {
				containsSelfSignedCert = true
				break
			}
		}
		if !containsSelfSignedCert {
			return nil, fmt.Errorf("root CA certificate bundle does not include a self-signed certificate")
		}

		config.Bao.rootCertificates = certs
	}
	return &config, nil

}
