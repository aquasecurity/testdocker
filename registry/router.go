package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/docker/docker/errdefs"
	"golang.org/x/xerrors"

	"github.com/docker/docker/api/server/router"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/aquasecurity/testdocker/tarfile"
)

// registryRouter is a router to talk with the image controller
type registryRouter struct {
	routes []router.Route
	images map[string]string
}

// NewRouter initializes a new image router
func NewRouter(images map[string]string) router.Router {
	r := &registryRouter{
		images: images,
	}
	r.initRoutes()
	return r
}

// Routes returns the available routes to the image controller
func (s *registryRouter) Routes() []router.Route {
	return s.routes
}

// initRoutes initializes the routes in the image router
func (s *registryRouter) initRoutes() {
	s.routes = []router.Route{
		// GET
		router.NewGetRoute("/", s.pingHandler),
		router.NewGetRoute("/{name:.*}/manifests/{reference}", s.manifestHandler),
		router.NewGetRoute("/{name:.*}/blobs/{digest}", s.blobHandler),
	}
}

func (s *registryRouter) pingHandler(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	switch vars["version"] {
	case "2":
		return nil
	default:
		return errdefs.NotImplemented(xerrors.Errorf("unknown version: v%s", vars["version"]))
	}
}

func (s *registryRouter) manifestHandler(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	imageName := fmt.Sprintf("v%s/%s:%s", vars["version"], vars["name"], vars["reference"])
	filePath, ok := s.images[imageName]
	if !ok {
		return errdefs.NotFound(xerrors.Errorf("unknown image: %s", imageName))
	}

	opener := func() (io.ReadCloser, error) {
		return tarfile.Open(filePath)
	}

	img, err := tarball.Image(opener, nil)
	if err != nil {
		return errdefs.NotFound(xerrors.Errorf("unknown image: %s", filePath))
	}

	m, err := img.Manifest()
	if err != nil {
		return errdefs.Unavailable(err)
	}

	w.Header().Set("Content-Type", string(m.MediaType))
	w.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(w).Encode(m); err != nil {
		return errdefs.Unavailable(err)
	}
	return nil
}

func (s *registryRouter) blobHandler(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	imageName := fmt.Sprintf("v%s/%s", vars["version"], vars["name"])
	for image, filePath := range s.images {
		if !strings.HasPrefix(image, imageName) {
			continue
		}

		opener := func() (io.ReadCloser, error) {
			return tarfile.Open(filePath)
		}

		img, err := tarball.Image(opener, nil)
		if err != nil {
			return errdefs.NotFound(xerrors.Errorf("unknown image: %s", filePath))
		}

		h, err := v1.NewHash(vars["digest"])
		if err != nil {
			return errdefs.InvalidParameter(err)
		}

		// return the config file
		configName, err := img.ConfigName()
		if err != nil {
			return errdefs.Unavailable(err)
		}

		if configName == h {
			b, err := img.RawConfigFile()
			if err != nil {
				return errdefs.Unavailable(err)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, err = w.Write(b)
			return errdefs.Unavailable(err)
		}

		// return the layer content
		l, err := img.LayerByDigest(h)
		if err != nil {
			return errdefs.Unavailable(err)
		}

		rc, err := l.Compressed()
		if err != nil {
			return errdefs.Unavailable(err)
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", vars["digest"])
		w.WriteHeader(http.StatusOK)
		if _, err = io.Copy(w, rc); err != nil {
			return errdefs.Unavailable(err)
		}
		return nil
	}

	return errdefs.NotFound(xerrors.Errorf("unknown image: %s", imageName))
}
