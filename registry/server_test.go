package registry

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestNewDockerRegistry_pingHandler(t *testing.T) {
	testCases := []struct {
		name               string
		urlPath            string
		expectedStatusCode int
	}{
		{
			name:               "happy path, /v2 reports StatusOK",
			urlPath:            "/v2/",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "sad path, /v3 reports StatusNotImplemented",
			urlPath:            "/v3/",
			expectedStatusCode: http.StatusNotImplemented,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewDockerRegistry(Option{})
			resp, err := http.Get(r.URL + tc.urlPath)
			assert.NoError(t, err, tc.name)
			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, tc.name)
		})
	}
}

func TestNewDockerRegistry_manifestHandler(t *testing.T) {
	testCases := []struct {
		name                 string
		urlPath              string
		option               Option
		expectedStatusCode   int
		expectedResponseBody string
		expectedError        error
	}{
		{
			name:    "happy path, alpine",
			urlPath: "/v2/alpine/manifests/ref123",
			option: Option{
				Images: map[string]string{
					"v2/alpine:ref123": "testdata/alpine/alpine.tar",
				},
			},
			expectedStatusCode:   http.StatusOK,
			expectedResponseBody: `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":1512,"digest":"sha256:af341ccd2df8b0e2d67cf8dd32e087bfda4e5756ebd1c76bbf3efa0dc246590e"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":3029607,"digest":"sha256:988beb990993123f9c14951440e468cb469f9f1f4fe512fd9095b48f9c9e7130"}]}`,
		},
		{
			name:               "sad path, image not found",
			urlPath:            "/v2/bogusimage/manifests/ref123",
			expectedStatusCode: http.StatusNotFound,
		},
		{
			name:    "sad path, image exists but tar not found",
			urlPath: "/v2/notarfile/manifests/ref123",
			option: Option{
				Images: map[string]string{
					"v2/notarfile:ref123": "doesntexist.tar",
				},
			},
			expectedStatusCode: http.StatusNotFound,
		},
		{
			name:    "sad path, image exists but tar is corrupt",
			urlPath: "/v2/corrupt/manifests/ref123",
			option: Option{
				Images: map[string]string{
					"v2/corrupt:ref123": "testdata/corrupt.tar",
				},
			},
			expectedStatusCode: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewDockerRegistry(tc.option)

			resp, err := http.Get(r.URL + tc.urlPath)
			switch {
			case tc.expectedError != nil:
				assert.Equal(t, tc.expectedError, err, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, tc.name)
			if resp.StatusCode != http.StatusOK {
				return
			}
			respBody, _ := ioutil.ReadAll(resp.Body)
			assert.Equal(t, tc.expectedResponseBody, string(respBody), tc.name)
		})
	}
}

func TestNewDockerRegistry_blobHandler(t *testing.T) {
	testCases := []struct {
		name                 string
		urlPath              string
		option               Option
		expectedStatusCode   int
		expectedContentType  string
		expectedResponseFile string
		expectedDigest       string
	}{
		{
			name:    "happy path, blob returns binary data",
			urlPath: "/v2/alpine/blobs/sha256:988beb990993123f9c14951440e468cb469f9f1f4fe512fd9095b48f9c9e7130",
			option: Option{
				Images: map[string]string{
					"v2/alpine:ref123": "testdata/alpine/alpine.tar",
				},
			},
			expectedStatusCode:   http.StatusOK,
			expectedContentType:  "application/octet-stream",
			expectedResponseFile: "testdata/alpine/layer.tar.gz",
			expectedDigest:       "sha256:988beb990993123f9c14951440e468cb469f9f1f4fe512fd9095b48f9c9e7130",
		},
		{
			name:               "sad path, requested blob does not exist",
			urlPath:            "/v2/alpine/blobs/invalidreference",
			expectedStatusCode: http.StatusNotFound,
		},
		{
			name:    "sad path, image entry and layers entry exists but no image file",
			urlPath: "/v2/alpine/blobs/71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8",
			option: Option{
				Images: map[string]string{
					"v2/alpine:ref123": "doesnt/exist/image/path",
				},
			},
			expectedStatusCode: http.StatusServiceUnavailable,
		},
		{
			name:    "sad path, image entry and layers entry exists but corrupt image file",
			urlPath: "/v2/alpine/blobs/71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8",
			option: Option{
				Images: map[string]string{
					"v2/alpine:ref123": "testdata/corrupt.tar",
				},
			},
			expectedStatusCode: http.StatusServiceUnavailable,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewDockerRegistry(tc.option)

			resp, err := http.Get(r.URL + tc.urlPath)
			assert.NoError(t, err, tc.name)
			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, tc.name)

			if tc.expectedStatusCode != http.StatusOK {
				return
			}

			expectedContent, err := ioutil.ReadFile(tc.expectedResponseFile)
			require.NoError(t, err)

			actualResp, _ := ioutil.ReadAll(resp.Body)
			assert.Equal(t, expectedContent, actualResp, tc.name)

			assert.Equal(t, tc.expectedContentType, resp.Header.Get("Content-Type"), tc.name)
			assert.Equal(t, tc.expectedDigest, resp.Header.Get("Docker-Content-Digest"), tc.name)
		})
	}
}
