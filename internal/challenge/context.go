package challenge

import (
	"crypto/x509"
	"errors"

	"github.com/openbao/openbao/api/v2"
)

// Context specifies how to have OpenBAO create the certificate
type Context struct {
	client *api.Client              // OpenBAO client to use
	role   string                   // The role to sign against
	csr    *x509.CertificateRequest // The CSR submitted by the client
}

func NewContext(client *api.Client, role string, csr *x509.CertificateRequest) (*Context, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	if csr == nil {
		return nil, errors.New("csr is nil")
	}
	if role == "" {
		return nil, errors.New("role is empty")
	}
	return &Context{
		client: client,
		role:   role,
		csr:    csr,
	}, nil
}

func (c *Context) Client() *api.Client {
	return c.client
}

func (c *Context) Role() string {
	return c.role
}

func (c *Context) CSR() *x509.CertificateRequest {
	return c.csr
}
