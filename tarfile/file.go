package tarfile

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

func Open(filePath string) (io.ReadCloser, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	var r io.ReadCloser
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
			data := make([]byte, hdr.Size)
			_, err := tf.Read(data)
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("unable to read file: %s", err)
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("file %s not found in tar", filePath)
}

func UncompressedLayerSize(r io.Reader) (int64, error) {
	var unCompSize int64
	tf := tar.NewReader(r)
	for {
		hdr, err := tf.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		unCompSize = unCompSize + hdr.Size
	}
	return unCompSize, nil
}
