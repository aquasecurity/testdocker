package registry

import (
	"net/http/httptest"

	"github.com/aquasecurity/testdocker/server"
	"github.com/docker/docker/api/server/router"
)

func NewDockerRegistry(images map[string]string) *httptest.Server {
	var routes []router.Router
	routes = append(routes, NewRouter(images))

	m := server.CreateMux(routes)

	return httptest.NewServer(m)
}
