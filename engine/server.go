package engine

import (
	"net/http"
	"net/http/httptest"

	"github.com/aquasecurity/testdocker/server"

	"github.com/docker/docker/api/server/router"

	"github.com/aquasecurity/testdocker/engine/image"
)

const (
	defaultAPIVersion = "1.38"
)

type Option struct {
	APIVersion   string
	ImagePaths   map[string]string
	InspectPaths map[string]string
}

func NewDockerEngine(opt Option) *httptest.Server {
	if opt.APIVersion == "" {
		opt.APIVersion = defaultAPIVersion
	}

	var routes []router.Router
	routes = append(routes, image.NewRouter(opt.ImagePaths, opt.InspectPaths))

	m := server.CreateMux(routes)
	m.Path("/_ping").Methods("GET").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Api-Version", opt.APIVersion)
		w.WriteHeader(http.StatusOK)
	}))

	return httptest.NewServer(m)
}
