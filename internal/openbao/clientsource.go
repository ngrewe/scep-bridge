package openbao

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openbao/openbao/api/auth/kubernetes/v2"
	"github.com/openbao/openbao/api/v2"
)

var (
	ErrNoToken = errors.New("openbao: no token in environment (BAO_TOKEN)")
)

type ClientSource interface {
	Client(ctx context.Context) (*api.Client, error)
}

type Static struct {
	client *api.Client
}

func (s *Static) LogValue() slog.Value {
	return slog.StringValue("Static(BAO_TOKEN)")
}

func NewStatic() (*Static, error) {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	if client.Token() == "" {
		return nil, ErrNoToken
	}
	return &Static{client: client}, nil
}

func (s *Static) Client(ctx context.Context) (*api.Client, error) {
	return s.client, nil
}

type Kubernetes struct {
	role    string
	expires time.Time
	client  *api.Client
	mu      sync.Mutex
}

func (k *Kubernetes) LogValue() slog.Value {
	return slog.StringValue(fmt.Sprintf("Kubernetes(role: %s)", k.role))
}

func NewKubernetes(role string) *Kubernetes {
	return &Kubernetes{
		role:    role,
		expires: time.Time{},
		client:  nil,
	}
}

func (k *Kubernetes) Client(ctx context.Context) (*api.Client, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.needsRenewal() {
		client, expires, err := kubernetesAuth(ctx, k.role)
		if err != nil {
			return nil, err
		}
		k.client = client
		k.expires = expires
	}
	return k.client, nil
}

func (k *Kubernetes) needsRenewal() bool {
	return k.client == nil || k.expires.Before(time.Now().Add(time.Second*30))
}

func kubernetesAuth(ctx context.Context, role string) (*api.Client, time.Time, error) {
	auth, err := kubernetes.NewKubernetesAuth(role)
	if err != nil {
		return nil, time.Time{}, err
	}
	baoApi, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, time.Time{}, err
	}
	when := time.Now()
	secret, err := baoApi.Auth().Login(ctx, auth)
	if err != nil {
		return nil, time.Time{}, err
	}
	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, time.Time{}, err
	}
	return baoApi, when.Add(ttl), nil
}
