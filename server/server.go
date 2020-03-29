package server

import (
	"context"
	"net/http"

	"github.com/docker/docker/api/server/httputils"
	"github.com/docker/docker/api/server/router"
	"github.com/gorilla/mux"
)

const versionMatcher = "/v{version:[0-9.]+}"

func makeHTTPHandler(handler httputils.APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		if vars == nil {
			vars = make(map[string]string)
		}

		if err := handler(context.Background(), w, r, vars); err != nil {
			httputils.MakeErrorHandler(err)(w, r)
		}
	}
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
