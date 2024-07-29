package registry

import (
	"net/http/httptest"

	"github.com/docker/docker/api/server/router"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/aquasecurity/testdocker/auth"
	"github.com/aquasecurity/testdocker/server"
)

type Option struct {
	Images map[string]v1.Image
	Auth   auth.Auth
}

func NewDockerRegistry(option Option) *httptest.Server {
	var routes []router.Router
	routes = append(routes, NewRouter(option.Images))

	a := auth.NewRouter(option.Auth)
	routes = append(routes, a)

	m := server.CreateMux(routes)

	if option.Auth.IsValid() {
		// Authentication
		m.Use(a.Middleware)
	}

	return httptest.NewServer(m)
}
