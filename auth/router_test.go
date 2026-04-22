package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/testdocker/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_BearerRealm(t *testing.T) {
	testCases := []struct {
		name           string
		host           string
		expectedStatus int
		expectedRealm  string
	}{
		{
			name:           "loopback IPv4 is rewritten to localhost",
			host:           "127.0.0.1:5000",
			expectedStatus: http.StatusUnauthorized,
			expectedRealm:  `Bearer realm="http://localhost:5000/token"`,
		},
		{
			name:           "loopback IPv6 is rewritten to localhost",
			host:           "[::1]:5000",
			expectedStatus: http.StatusUnauthorized,
			expectedRealm:  `Bearer realm="http://localhost:5000/token"`,
		},
		{
			name:           "regular hostname is preserved",
			host:           "registry.example.com:5000",
			expectedStatus: http.StatusUnauthorized,
			expectedRealm:  `Bearer realm="http://registry.example.com:5000/token"`,
		},
		{
			name:           "non-loopback IP is preserved",
			host:           "192.168.1.1:5000",
			expectedStatus: http.StatusUnauthorized,
			expectedRealm:  `Bearer realm="http://192.168.1.1:5000/token"`,
		},
		{
			name:           "host without port returns 500",
			host:           "localhost",
			expectedStatus: http.StatusInternalServerError,
		},
	}

	a := auth.Auth{User: "u", Password: "p", Secret: "s"}
	r := auth.NewRouter(a)
	handler := r.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/v2/", nil)
			require.NoError(t, err)
			req.Host = tc.host

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.expectedStatus, rec.Code)
			if tc.expectedRealm != "" {
				assert.Equal(t, tc.expectedRealm, rec.Header().Get("Www-Authenticate"))
			}
		})
	}
}
