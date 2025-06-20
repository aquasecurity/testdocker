package image

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/docker/docker/errdefs"

	"github.com/aquasecurity/testdocker/tarfile"
	"github.com/docker/docker/api/server/httputils"
	"github.com/docker/docker/api/server/router"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/storage"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/xerrors"
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
		router.NewGetRoute("/images/{name:.*}/history", s.getImageHistory),
	}
}

// ref. https://github.com/moby/moby/blob/852542b3976754f62232f1fafca7fd35deeb1da3/api/server/router/image/image.go#L34
func (s *imageRouter) getImagesByName(_ context.Context, w http.ResponseWriter, _ *http.Request, vars map[string]string) error {
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

	exposedPorts := map[string]struct{}{}
	for port := range config.Config.ExposedPorts {
		exposedPorts[port] = struct{}{}
	}

	var diffIDs []string
	for _, d := range config.RootFS.DiffIDs {
		diffIDs = append(diffIDs, d.String())
	}

	volumes := map[string]struct{}{}
	for vol := range config.Config.Volumes {
		volumes[vol] = struct{}{}
	}

	var healthcheck *dockerspec.HealthcheckConfig
	if config.Config.Healthcheck != nil {
		healthcheck = &dockerspec.HealthcheckConfig{
			Test:        config.Config.Healthcheck.Test,
			Interval:    config.Config.Healthcheck.Interval,
			Timeout:     config.Config.Healthcheck.Timeout,
			StartPeriod: config.Config.Healthcheck.StartPeriod,
			Retries:     config.Config.Healthcheck.Retries,
		}
	}

	// ContainerConfig is deprecated but kept for backward compatibility
	containerConfig := &container.Config{
		User:       config.Config.User,
		Env:        config.Config.Env,
		Cmd:        config.Config.Cmd,
		WorkingDir: config.Config.WorkingDir,
		Entrypoint: config.Config.Entrypoint,
		Labels:     config.Config.Labels,
	}

	imageConfig := &dockerspec.DockerOCIImageConfig{
		ImageConfig: ocispec.ImageConfig{
			User:         config.Config.User,
			ExposedPorts: exposedPorts,
			Env:          config.Config.Env,
			Entrypoint:   config.Config.Entrypoint,
			Cmd:          config.Config.Cmd,
			Volumes:      volumes,
			WorkingDir:   config.Config.WorkingDir,
			Labels:       config.Config.Labels,
			StopSignal:   config.Config.StopSignal,
			ArgsEscaped:  config.Config.ArgsEscaped,
		},
		DockerOCIImageConfigExt: dockerspec.DockerOCIImageConfigExt{
			Healthcheck: healthcheck,
			OnBuild:     config.Config.OnBuild,
			Shell:       config.Config.Shell,
		},
	}
	inspect := image.InspectResponse{
		ID:              manifest.Config.Digest.String(),
		RepoTags:        manifests[0].RepoTags,
		RepoDigests:     nil, // not supported
		Parent:          "",  // not supported
		Comment:         "",  // not supported
		Created:         config.Created.Time.Format(time.RFC3339Nano),
		ContainerConfig: containerConfig,
		DockerVersion:   config.DockerVersion,
		Author:          config.Author,
		Config:          imageConfig,
		Architecture:    config.Architecture,
		Os:              config.OS,
		OsVersion:       config.OSVersion,
		Size:            0,                       // not supported
		VirtualSize:     0,                       // not supported
		GraphDriver:     storage.DriverData{}, // not supported
		RootFS: image.RootFS{
			Type:   config.RootFS.Type,
			Layers: diffIDs,
		},
		Metadata: image.Metadata{},
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

func (s *imageRouter) getImageHistory(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
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
	layers, err := img.Layers()
	if err != nil {
		return errdefs.Unavailable(err)
	}
	var allLayerSizes []int64
	for _, layer := range layers {
		reader, err := layer.Uncompressed()
		if err != nil {
			return errdefs.Unavailable(err)
		}
		/* TODO The uncompressed layer size that we calculate is not correct.
		We have to identify how docker calculates the uncompressed layer sizes
		Example: python:alpine3.11
		*/
		layerSize, err := tarfile.UncompressedLayerSize(reader)
		if err != nil {
			return errdefs.NotFound(xerrors.Errorf("failed calculating uncompressed size (%s): %w", layer, err))
		}
		allLayerSizes = append(allLayerSizes, layerSize)
	}
	config, err := img.ConfigFile()
	if err != nil {
		return errdefs.Unavailable(err)
	}

	var inspectHistory []image.HistoryResponseItem
	var layerSize int64
	layerIndex := 0
	for _, configHistory := range config.History {
		if configHistory.EmptyLayer {
			layerSize = 0
		} else {
			layerSize = allLayerSizes[layerIndex]
			layerIndex++
		}
		inspectHistory = append(inspectHistory, image.HistoryResponseItem{
			Comment:   configHistory.Comment,
			Created:   configHistory.Created.Unix(),
			CreatedBy: configHistory.CreatedBy,
			Size:      layerSize,
		})
	}

	if err = json.NewEncoder(w).Encode(inspectHistory); err != nil {
		return errdefs.Unavailable(xerrors.Errorf("unable to encode JSON: %w", err))
	}

	return nil
}
