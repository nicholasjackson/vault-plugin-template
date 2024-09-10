package example

import (
	"errors"
)

// hashiCupsClient creates an object storing
// the client.
type exampleClient struct {
}

// newClient creates a new client to access HashiCups
// and exposes it for any secrets or roles to use.
func newClient(c *config) (*exampleClient, error) {
	if c == nil {
		return nil, errors.New("client configuration was nil")
	}

	if c.Username == "" {
		return nil, errors.New("client username was not defined")
	}

	if c.Password == "" {
		return nil, errors.New("client password was not defined")
	}

	if c.URL == "" {
		return nil, errors.New("client URL was not defined")
	}

	return &exampleClient{}, nil
}

type exampleResponse struct {
	UserID string
	Token  string
}

func (c *exampleClient) SignIn() (*exampleResponse, error) {
	return &exampleResponse{}, nil
}

func (c *exampleClient) SignOut(token string) error {
	return nil
}
