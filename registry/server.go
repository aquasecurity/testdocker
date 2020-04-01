package registry

import (
	"fmt"
	"net/http"

	"github.com/aquasecurity/testdocker/tarfile"
	"github.com/gorilla/mux"
)

type Registry struct {
	Images map[string]string
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

	f, err := tarfile.Open(filePath)
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

func (rg Registry) blobHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	blobName := fmt.Sprintf("%s/%s:%s", vars["apiVersion"], vars["name"], vars["digest"])
	blobPath, ok := rg.Images[blobName]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", vars["digest"])
	http.ServeFile(w, r, blobPath)
	return
}

func NewDockerRegistry(images map[string]string) *mux.Router { // TODO: Change images to be a better struct
	rg := Registry{Images: images}

	r := mux.NewRouter()
	r.HandleFunc("/{apiVersion}", rg.pingHandler).Methods("GET")
	r.HandleFunc("/{apiVersion}/{name}/manifests/{reference}", rg.manifestHandler).Methods("GET")
	r.HandleFunc("/{apiVersion}/{name}/blobs/{digest}", rg.blobHandler).Methods("GET")
	return r
}
