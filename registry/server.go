package registry

import (
	"net/http/httptest"

	"github.com/aquasecurity/testdocker/auth"
	"github.com/aquasecurity/testdocker/server"
	"github.com/docker/docker/api/server/router"
)

type Option struct {
	Images map[string]string
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
