package image

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/docker/docker/errdefs"

	"github.com/docker/docker/api/server/httputils"
	"github.com/docker/docker/api/server/router"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/go-connections/nat"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/testdocker/tarfile"
)

// imageRouter is a router to talk with the image controller
type imageRouter struct {
	routes []router.Route
	images map[string]string
}

// NewRouter initializes a new image router
func NewRouter(images map[string]string) router.Router {
	r := &imageRouter{
		images: images,
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
		router.NewGetRoute("/images/get", s.getImagesGet),
	}
}

// ref. https://github.com/moby/moby/blob/852542b3976754f62232f1fafca7fd35deeb1da3/api/server/router/image/image.go#L34
func (s *imageRouter) getImagesByName(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	imageName := vars["name"]
	filePath, ok := s.images[imageName]
	if !ok {
		return errdefs.NotFound(xerrors.Errorf("unknown image: %s", imageName))
	}

	opener := func() (io.ReadCloser, error) {
		return tarfile.Open(filePath)
	}

	img, err := tarball.Image(opener, nil)
	if err != nil {
		return errdefs.NotFound(xerrors.Errorf("unable to open the file path (%s): %w", filePath, err))
	}

	rc, err := tarfile.Open(filePath)
	if err != nil {
		return errdefs.NotFound(xerrors.Errorf("unable to open the file path (%s): %w", filePath, err))
	}

	b, err := tarfile.ExtractFileFromTar(rc, "manifest.json")
	if err != nil {
		return errdefs.Unavailable(err)
	}

	var manifests tarball.Manifest
	if err := json.Unmarshal(b, &manifests); err != nil {
		return errdefs.Unavailable(err)
	}

	if len(manifests) != 1 {
		return errdefs.Unavailable(xerrors.New("tarball must contain only a single image to be used with testdocker"))
	}

	config, err := img.ConfigFile()
	if err != nil {
		return errdefs.Unavailable(err)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return errdefs.Unavailable(err)
	}

	exposedPorts := nat.PortSet{}
	for port := range config.Config.ExposedPorts {
		exposedPorts[nat.Port(port)] = struct{}{}
	}

	var diffIDs []string
	for _, d := range config.RootFS.DiffIDs {
		diffIDs = append(diffIDs, d.String())
	}

	var healthCheck *container.HealthConfig
	if config.Config.Healthcheck != nil {
		healthCheck = &container.HealthConfig{
			Test:        config.Config.Healthcheck.Test,
			Interval:    config.Config.Healthcheck.Interval,
			Timeout:     config.Config.Healthcheck.Timeout,
			StartPeriod: config.Config.Healthcheck.StartPeriod,
			Retries:     config.Config.Healthcheck.Retries,
		}
	}

	containerConfig := &container.Config{
		Hostname:        config.Config.Hostname,
		Domainname:      config.Config.Domainname,
		User:            config.Config.User,
		AttachStdin:     config.Config.AttachStdin,
		AttachStdout:    config.Config.AttachStdout,
		AttachStderr:    config.Config.AttachStderr,
		ExposedPorts:    exposedPorts,
		Tty:             config.Config.Tty,
		OpenStdin:       config.Config.OpenStdin,
		StdinOnce:       config.Config.StdinOnce,
		Env:             config.Config.Env,
		Cmd:             config.Config.Cmd,
		Healthcheck:     healthCheck,
		ArgsEscaped:     config.Config.ArgsEscaped,
		Image:           config.Config.Image,
		Volumes:         config.Config.Volumes,
		WorkingDir:      config.Config.WorkingDir,
		Entrypoint:      config.Config.Entrypoint,
		NetworkDisabled: config.Config.NetworkDisabled,
		MacAddress:      config.Config.MacAddress,
		OnBuild:         config.Config.OnBuild,
		Labels:          config.Config.Labels,
		StopSignal:      config.Config.StopSignal,
		StopTimeout:     nil, // not supported
		Shell:           config.Config.Shell,
	}

	inspect := types.ImageInspect{
		ID:              manifest.Config.Digest.String(),
		RepoTags:        manifests[0].RepoTags,
		RepoDigests:     nil, // not supported
		Parent:          "",  // not supported
		Comment:         "",  // not supported
		Created:         config.Created.String(),
		Container:       config.Container,
		ContainerConfig: containerConfig,
		DockerVersion:   config.DockerVersion,
		Author:          config.Author,
		Config:          containerConfig,
		Architecture:    config.Architecture,
		Os:              config.OS,
		OsVersion:       config.OSVersion,
		Size:            0,                       // not supported
		VirtualSize:     0,                       // not supported
		GraphDriver:     types.GraphDriverData{}, // not supported
		RootFS: types.RootFS{
			Type:   config.RootFS.Type,
			Layers: diffIDs,
		},
		Metadata: types.ImageMetadata{},
	}

	if err = json.NewEncoder(w).Encode(inspect); err != nil {
		return errdefs.Unavailable(xerrors.Errorf("unable to encode JSON: %w", err))
	}

	return nil
}

// ref. https://github.com/moby/moby/blob/cb3ec99b1674e0bf4988edc3fed5f6c7dabeda45/api/server/router/image/image_routes.go#L144
func (s *imageRouter) getImagesGet(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return errdefs.InvalidParameter(err)
	}

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
		err := xerrors.New("'name' or 'names' must be specified")
		return errdefs.InvalidParameter(err)
	}

	if len(names) > 1 {
		err := xerrors.New("testdocker doesn't support multiple images")
		return errdefs.InvalidParameter(err)
	}

	name := names[0]
	filePath, ok := s.images[name]
	if !ok {
		return errdefs.NotFound(xerrors.Errorf("unknown image: %s", name))
	}

	f, err := tarfile.Open(filePath)
	if err != nil {
		return errdefs.NotFound(xerrors.Errorf("unknown image (%s): %w", filePath, err))
	}

	if _, err = io.Copy(w, f); err != nil {
		return errdefs.Unavailable(err)
	}

	return nil
}
