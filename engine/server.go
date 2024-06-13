package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"

	"github.com/docker/docker/api/server/router"

	"github.com/aquasecurity/testdocker/engine/image"
	"github.com/aquasecurity/testdocker/server"
)

const (
	defaultAPIVersion = "1.45"
)

type Option struct {
	APIVersion       string
	ImagePaths       map[string]string
	UnixDomainSocket string
}

func NewDockerEngine(opt Option) *httptest.Server {
	if opt.APIVersion == "" {
		opt.APIVersion = defaultAPIVersion
	}

	var routes []router.Router
	routes = append(routes, image.NewRouter(opt.ImagePaths))

	m := server.CreateMux(routes)
	m.Path("/_ping").Methods("GET").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Api-Version", opt.APIVersion)
		w.WriteHeader(http.StatusOK)
	}))

	if opt.UnixDomainSocket != "" {
		newUnixDomainSocketServer(opt.UnixDomainSocket, m)
	}

	return httptest.NewServer(m)
}

func newUnixDomainSocketServer(socketPath string, handler http.Handler) *httptest.Server {
	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		panic(fmt.Sprintf("failed to listen on %s: %s", socketPath, err))
	}

	s := &httptest.Server{
		Listener: unixListener,
		Config:   &http.Server{Handler: handler},
	}
	s.Start()
	return s
}
