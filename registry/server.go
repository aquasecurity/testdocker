package registry

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/aquasecurity/testdocker/tarfile"
	"github.com/gorilla/mux"
)

type Registry struct {
	Images map[string]DockerImageDetail
}

func (rg Registry) pingHandler(w http.ResponseWriter, r *http.Request) {
	switch mux.Vars(r)["apiVersion"] {
	case "v2":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (rg Registry) manifestHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	imageName := fmt.Sprintf("%s/%s:%s", vars["apiVersion"], vars["name"], vars["reference"])
	filePath, ok := rg.Images[imageName]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	f, err := tarfile.Open(filePath.imagePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	b, err := tarfile.ExtractFileFromTar(f, "manifest.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func containsLayer(input []string, e string) bool {
	for _, s := range input {
		if s == e {
			return true
		}
	}
	return false
}

func (rg Registry) blobHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	var imageFound bool
	imageName := fmt.Sprintf("%s/%s", vars["apiVersion"], vars["name"])
	for image, detail := range rg.Images {
		if strings.Contains(image, imageName) {
			if containsLayer(detail.layers, vars["digest"]) {
				imageFound = true
			}
		}
		if imageFound {
			f, err := tarfile.Open(detail.imagePath)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			b, err := tarfile.ExtractFileFromTar(f, fmt.Sprintf("%s/layer.tar", vars["digest"]))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Docker-Content-Digest", vars["digest"])
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
			return
		}
	}
	if !imageFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

type DockerImageDetail struct {
	imagePath string
	layers    []string
}

type DockerRegistryStore struct {
	images map[string]DockerImageDetail
}

func NewDockerRegistry(detail DockerRegistryStore) *mux.Router {
	rg := Registry{Images: detail.images}

	r := mux.NewRouter()
	r.HandleFunc("/{apiVersion}", rg.pingHandler).Methods(http.MethodGet)
	r.HandleFunc("/{apiVersion}/{name}/manifests/{reference}", rg.manifestHandler).Methods(http.MethodGet)
	r.HandleFunc("/{apiVersion}/{name}/blobs/{digest}", rg.blobHandler).Methods(http.MethodGet)
	return r
}
