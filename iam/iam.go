package iam

import (
	"fmt"
	"net/http"

	"github.com/fabiolb/fabio/config"
)

// IAM implements an identity and access management interface
type IAM interface {
	// Init is called with an auth config file as defined in the application config.  The
	// implementation loads its specific configuration from this file when fabio starts.
	// This is referenced as a sperate file as it will contain auth data.
	Init(cfgfile string) error
	// Authenticate should authenticate a request and return any data needed for
	// Authorization or an error on failure.
	Authenticate(r *http.Request) (interface{}, error)
	// Authorize should check the authorization for a request.  authData is the data
	// returned from the Authenticate call.  If should return an error when unauthorized.
	Authorize(r *http.Request, authData interface{}) error
}

// New instantiates a new IAM instance
func New(conf config.Auth) (iam IAM, err error) {
	switch conf.Type {
	case "dummy":
		iam = &DummyIAM{}
	default:
		err = fmt.Errorf("unsupported auth type: %s", conf.Type)
		return
	}

	err = iam.Init(conf.ConfigFile)
	return
}

// DummyIAM implements a dummy IAM interface that does nothing.
type DummyIAM struct{}

// Init is a no-op
func (iam *DummyIAM) Init(string) error { return nil }

// Authenticate is a no-op
func (iam *DummyIAM) Authenticate(*http.Request) (interface{}, error) { return struct{}{}, nil }

// Authorize is a no-op
func (iam *DummyIAM) Authorize(*http.Request, interface{}) error { return nil }
