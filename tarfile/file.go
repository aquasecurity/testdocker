package tarfile

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func Open(filePath string) (io.Reader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	var r io.Reader
	if strings.HasSuffix(filePath, ".gz") {
		r, err = gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
	} else {
		r = f
	}

	return r, nil
}

func ExtractFileFromTar(r io.Reader, filePath string) ([]byte, error) {
	tf := tar.NewReader(r)
	for {
		hdr, err := tf.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == filePath {
			return ioutil.ReadAll(r)
		}
	}
	return nil, fmt.Errorf("file %s not found in tar", filePath)
}
