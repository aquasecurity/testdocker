package image

import (
	"context"
	"io"
	"net/http"
	"os"

	"github.com/aquasecurity/testdocker/tarfile"

	"github.com/docker/docker/pkg/ioutils"

	"github.com/docker/docker/api/server/router"
)

// imageRouter is a router to talk with the image controller
type imageRouter struct {
	routes   []router.Route
	images   map[string]string
	inspects map[string]string
}

// NewRouter initializes a new image router
func NewRouter(images map[string]string, inspects map[string]string) router.Router {
	r := &imageRouter{
		images:   images,
		inspects: inspects,
	}
	r.initRoutes()
	return r
}

// Routes returns the available routes to the image controller
func (s *imageRouter) Routes() []router.Route {
	return s.routes
}

// initRoutes initializes the routes in the image router
func (s *imageRouter) initRoutes() {
	s.routes = []router.Route{
		// GET
		router.NewGetRoute("/images/{name:.*}/json", s.getImagesByName),
		router.NewGetRoute("/images/{name:.*}/get", s.getImagesGet),
	}
}

// ref. https://github.com/moby/moby/blob/852542b3976754f62232f1fafca7fd35deeb1da3/api/server/router/image/image.go#L34
func (s *imageRouter) getImagesByName(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	imageName := vars["name"]
	filePath, ok := s.inspects[imageName]
	if !ok {
		http.NotFound(w, r)
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}

	if _, err = io.Copy(w, f); err != nil {
		return err
	}
	return nil
}

// ref. https://github.com/moby/moby/blob/cb3ec99b1674e0bf4988edc3fed5f6c7dabeda45/api/server/router/image/image_routes.go#L144
func (s *imageRouter) getImagesGet(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	w.Header().Set("Content-Type", "application/x-tar")

	output := ioutils.NewWriteFlusher(w)
	defer output.Close()
	var names []string
	if name, ok := vars["name"]; ok {
		names = []string{name}
	} else {
		names = r.Form["names"]
	}

	if len(names) == 0 {
		http.Error(w, "'name' or 'names' must be specified", http.StatusBadRequest)
	}

	if len(names) > 1 {
		http.Error(w, "testdocker doesn't support multiple images", http.StatusBadRequest)
	}

	name := names[0]
	filePath, ok := s.images[name]
	if !ok {
		http.NotFound(w, r)
		return nil
	}

	f, err := tarfile.Open(filePath)
	if err != nil {
		return err
	}

	if _, err = io.Copy(w, f); err != nil {
		return err
	}
	return nil
}
