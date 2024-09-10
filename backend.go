package example

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type exampleBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *exampleClient
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *exampleBackend {
	var b = exampleBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths:       framework.PathAppend(),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *exampleBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	//b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *exampleBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *exampleBackend) getClient(ctx context.Context, s logical.Storage) (*exampleClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	return nil, fmt.Errorf("need to return client")
}

// backendHelp should contain help information for the backend
const backendHelp = `
The Example secrets backend dynamically generates user tokens.
After mounting this backend, credentials to manage HashiCups user tokens
must be configured with the "config/" endpoints.
`
