package registry

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"testing"
	"time"

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
			urlPath:            "/v2",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "sad path, /v3 reports StatusNotImplemented",
			urlPath:            "/v3",
			expectedStatusCode: http.StatusNotImplemented,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)

			r := NewDockerRegistry(nil)
			srv := &http.Server{
				Addr:    "127.0.0.1:8000",
				Handler: r,
			}

			// run until shutdown received
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
			defer func() {
				_ = srv.Shutdown(ctx)
				cancel()
			}()

			// wait for the server to start
			time.Sleep(time.Millisecond * 100)

			// start the server
			go func() {
				_ = srv.ListenAndServe()
			}()

			resp, err := http.Get("http://" + srv.Addr + tc.urlPath)
			assert.NoError(t, err, tc.name)
			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, tc.name)
		})
	}
}

func TestNewDockerRegistry_manifestHandler(t *testing.T) {
	testCases := []struct {
		name                 string
		urlPath              string
		imagesPresent        map[string]string
		expectedStatusCode   int
		expectedResponseBody string
		expectedError        error
	}{
		{
			name:    "happy path, alpine",
			urlPath: "/v2/alpine/manifests/ref123",
			imagesPresent: map[string]string{
				"v2/alpine:ref123": "testdata/alpine/alpine.tar",
			},
			expectedStatusCode: http.StatusOK,
			expectedResponseBody: `[{"Config":"af341ccd2df8b0e2d67cf8dd32e087bfda4e5756ebd1c76bbf3efa0dc246590e.json","RepoTags":["alpine:3.10"],"Layers":["71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8/layer.tar"]}]
`,
		},
		{
			name:               "sad path, image not found",
			urlPath:            "/v2/bogusimage/manifests/ref123",
			expectedStatusCode: http.StatusNotFound,
		},
		{
			name:    "sad path, image exists but tar not found",
			urlPath: "/v2/notarfile/manifests/ref123",
			imagesPresent: map[string]string{
				"v2/notarfile:ref123": "doesntexist.tar",
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name:    "sad path, image exists but tar is corrupt",
			urlPath: "/v2/corrupt/manifests/ref123",
			imagesPresent: map[string]string{
				"v2/corrupt:ref123": "testdata/corrupt.tar",
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)

			r := NewDockerRegistry(tc.imagesPresent)
			srv := &http.Server{
				Addr:    "127.0.0.1:8000",
				Handler: r,
			}

			// run until shutdown received
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
			defer func() {
				_ = srv.Shutdown(ctx)
				cancel()
			}()

			// start the server
			go func() {
				_ = srv.ListenAndServe()
			}()

			// wait for the server to start
			time.Sleep(time.Millisecond * 100)

			resp, err := http.Get("http://" + srv.Addr + tc.urlPath)
			switch {
			case tc.expectedError != nil:
				assert.Equal(t, tc.expectedError, err, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, tc.name)
			respBody, _ := ioutil.ReadAll(resp.Body)
			assert.Equal(t, tc.expectedResponseBody, string(respBody), tc.name)
		})
	}
}

func TestNewDockerRegistry_blobHandler(t *testing.T) {
	testCases := []struct {
		name                 string
		urlPath              string
		imagesPresent        map[string]string
		expectedStatusCode   int
		expectedResponseFile string
		expectedDigest       string
	}{
		{
			name:    "happy path, blob returns binary data",
			urlPath: "/v2/alpine/blobs/71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8",
			imagesPresent: map[string]string{
				"v2/alpine:71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8": "testdata/alpine/71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8/layer.tar",
			},
			expectedStatusCode:   http.StatusOK,
			expectedResponseFile: "testdata/alpine/71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8/layer.tar",
			expectedDigest:       "71dba1fabbde4baabcdebcde4895d3f3887e388b09cef162f8159cf7daffa1b8",
		},

		// TODO: Add sad paths
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)

			r := NewDockerRegistry(tc.imagesPresent)
			srv := &http.Server{
				Addr:    "127.0.0.1:8000",
				Handler: r,
			}

			// run until shutdown received
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
			defer func() {
				_ = srv.Shutdown(ctx)
				cancel()
			}()

			// wait for the server to start
			time.Sleep(time.Second * 1)

			// start the server
			go func() {
				_ = srv.ListenAndServe()
			}()

			resp, err := http.Get("http://" + srv.Addr + tc.urlPath)
			assert.NoError(t, err, tc.name)
			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, tc.name)

			var expectedContent []byte
			switch {
			case len(tc.expectedResponseFile) > 0:
				expectedContent, _ = ioutil.ReadFile(tc.expectedResponseFile)
			}
			actualResp, _ := ioutil.ReadAll(resp.Body)
			assert.Equal(t, expectedContent, actualResp, tc.name)

			assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"), tc.name)
			assert.Equal(t, strconv.Itoa(len(actualResp)), resp.Header.Get("Content-Length"), tc.name)
			assert.Equal(t, tc.expectedDigest, resp.Header.Get("Docker-Content-Digest"), tc.name)
		})
	}
}
