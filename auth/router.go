package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/docker/docker/api/server/router"
	"github.com/docker/docker/errdefs"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/xerrors"
)

const (
	issuer = "testdocker"
)

type authRouter struct {
	routes []router.Route
	auth   Auth
}

// ref. https://docs.docker.com/registry/spec/auth/token/#requesting-a-token
type TokenResponse struct {
	Token        string    `json:"token"`
	AccessToken  string    `json:"access_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshToken string    `json:"refresh_token"`
}

type Auth struct {
	User     string // required
	Password string // required
	Secret   string // required
}

func (a Auth) IsValid() bool {
	return a.User != "" && a.Password != "" && a.Secret != ""
}

// NewRouter initializes a new auth router
func NewRouter(auth Auth) *authRouter {
	r := &authRouter{
		auth: auth,
	}
	r.initRoutes()
	return r
}

// Routes returns the available routes to the image controller
func (a *authRouter) Routes() []router.Route {
	return a.routes
}

// initRoutes initializes the routes in the image router
func (a *authRouter) initRoutes() {
	a.routes = []router.Route{
		// GET
		router.NewGetRoute("/token", a.tokenHandler), // issue a registry token
	}
}

func (a *authRouter) tokenHandler(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	// Authorization: Basic dGVzdDp0ZXN0cGFzcw==
	authorization := r.Header.Get("Authorization")

	// Basic dGVzdDp0ZXN0cGFzcw==
	s := strings.Fields(authorization)
	if len(s) != 2 {
		return errdefs.Unauthorized(xerrors.New("invalid Authorization header"))
	}
	if s[0] != "Basic" {
		return errdefs.Unauthorized(xerrors.New("'Basic' must be specified"))
	}

	// dGVzdDp0ZXN0cGFzcw==
	decoded, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return errdefs.Unauthorized(err)
	}

	// test:testpass
	s = strings.Split(string(decoded), ":")
	if s[0] != a.auth.User || s[1] != a.auth.Password {
		return errdefs.Unauthorized(xerrors.New("invalid username/password"))
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer,
	})

	tokenString, err := token.SignedString([]byte(a.auth.Secret))
	if err != nil {
		return errdefs.Unavailable(err)
	}

	t := TokenResponse{
		Token:       tokenString,
		AccessToken: tokenString,
		ExpiresIn:   60,
		IssuedAt:    time.Now(),
	}

	b, _ := json.Marshal(t)
	if _, err = w.Write(b); err != nil {
		return errdefs.Unavailable(err)
	}

	return nil
}

// Middleware function, which will be called for each request
func (a authRouter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip checking a token for an endpoint to issue the token
		if r.Method == http.MethodGet && r.URL.Path == "/token" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			// verify the bearer token
			_, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, xerrors.New("invalid bearer token")
				}
				return []byte(a.auth.Secret), nil
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		} else {
			// Write an error and stop the handler chain
			w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="http://%s/token"`, r.Host))
			http.Error(w, "UNAUTHORIZED", http.StatusUnauthorized)
		}
	})
}
