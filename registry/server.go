package registry

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/aquasecurity/testdocker/tarfile"
)

func NewDockerRegistry(images map[string]string) *httptest.Server {
	// TODO: rewrite with gorilla/mux
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.Trim(r.URL.Path, "/")
		s := strings.Split(p, "/")

		switch {
		case len(s) == 1 && s[0] == "v2":
			// ping
			w.WriteHeader(http.StatusOK)
			return
		case len(s) == 5 && s[3] == "manifests":
			// manifest.json
			imageName := fmt.Sprintf("%s/%s:%s", s[1], s[2], s[4])
			filePath, ok := images[imageName]
			if !ok {
				http.NotFound(w, r)
				return
			}

			r, err := tarfile.Open(filePath)
			if err != nil {
				http.Error(w, "error", http.StatusInternalServerError)
			}

			b, err := tarfile.ExtractFileFromTar(r, "manifest.json")
			if err != nil {
				http.Error(w, "error", http.StatusInternalServerError)
			}

			_, _ = w.Write(b)
			return
		default:
			http.NotFound(w, r)
		}
	}))
	return ts
}
