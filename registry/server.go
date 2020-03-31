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

func NewDockerRegistry(images map[string]string) *mux.Router {
	rg := Registry{Images: images}

	r := mux.NewRouter()
	r.HandleFunc("/{apiVersion}", rg.pingHandler)
	r.HandleFunc("/{apiVersion}/{name}/manifests/{reference}", rg.manifestHandler)
	return r
}
