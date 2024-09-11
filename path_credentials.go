package example

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *exampleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// pathCredentialsRead creates a new HashiCups token each time it is called if a
// role exists.
func (b *exampleBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleEntry)
}

// createUserCreds creates a new HashiCups token to store into the Vault backend, generates
// a response with the secrets information, and checks the TTL and MaxTTL attributes.
func (b *exampleBackend) createUserCreds(ctx context.Context, req *logical.Request, role *roleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	// The response is divided into two objects (1) internal data and (2) data.
	// If you want to reference any information in your code, you need to
	// store it in internal data!
	resp := b.tokenSecret().Response(map[string]interface{}{
		"token":    token.Token,
		"token_id": token.TokenID,
		"user_id":  token.UserID,
		"username": token.Username,
	}, map[string]interface{}{
		"token": token.Token,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	//return resp, nil
	return nil, nil
}

// createToken uses the HashiCups client to sign in and get a new token
func (b *exampleBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *roleEntry) (*tokenData, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *tokenData

	token, err = createToken(ctx, client, roleEntry.Username)
	if err != nil {
		return nil, fmt.Errorf("error creating token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating token")
	}

	return token, nil
}

const pathCredentialsHelpSyn = `
Generate a token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates tokens based on a particular role.`
