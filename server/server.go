package server

import (
	"context"
	"net/http"

	"github.com/docker/docker/api/server/httpstatus"
	"github.com/docker/docker/api/server/httputils"
	"github.com/docker/docker/api/server/router"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/versions"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/status"
)

const versionMatcher = "/v{version:[0-9.]+}"

func makeHTTPHandler(handler httputils.APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		if vars == nil {
			vars = make(map[string]string)
		}

		if err := handler(context.Background(), w, r, vars); err != nil {
			makeErrorHandler(err)(w, r)
		}
	}
}

func makeErrorHandler(err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		statusCode := httpstatus.FromError(err)
		vars := mux.Vars(r)
		if apiVersionSupportsJSONErrors(vars["version"]) {
			response := &types.ErrorResponse{
				Message: err.Error(),
			}
			_ = httputils.WriteJSON(w, statusCode, response)
		} else {
			http.Error(w, status.Convert(err).Message(), statusCode)
		}
	}
}

func apiVersionSupportsJSONErrors(version string) bool {
	const firstAPIVersionWithJSONErrors = "1.23"
	return version == "" || versions.GreaterThan(version, firstAPIVersionWithJSONErrors)
}

// https://github.com/moby/moby/blob/fdf7f4d4ea38e0af3967668c5e2fd06046b8bead/api/server/server.go#L166
func CreateMux(routes []router.Router) *mux.Router {
	// https://github.com/moby/moby/blob/fdf7f4d4ea38e0af3967668c5e2fd06046b8bead/api/server/server.go#L166
	m := mux.NewRouter()
	for _, route := range routes {
		for _, r := range route.Routes() {
			f := makeHTTPHandler(r.Handler())
			m.Path(versionMatcher + r.Path()).Methods(r.Method()).Handler(f)
			m.Path(r.Path()).Methods(r.Method()).Handler(f)
		}
	}
	return m
}
