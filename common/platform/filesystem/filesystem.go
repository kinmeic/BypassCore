// Package filesystem provides asset (geodata) file access.
// Assets are resolved under the directory reported by
// common/platform.GetAssetLocation.
package filesystem // import "github.com/eugene/bypasscore/common/platform/filesystem"

import (
	"io"
	"os"
	"path/filepath"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/platform"
)

// OpenAsset opens an asset file (e.g. geoip.dat) for reading.
func OpenAsset(file string) (io.ReadCloser, error) {
	path, err := ResolveAsset(file)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// ReadAsset reads an asset file fully into memory.
func ReadAsset(file string) ([]byte, error) {
	path, err := ResolveAsset(file)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// StatAsset returns os.FileInfo for an asset.
func StatAsset(file string) (os.FileInfo, error) {
	path, err := ResolveAsset(file)
	if err != nil {
		return nil, err
	}
	return os.Stat(path)
}

// ResolveAsset returns the absolute path of an asset, validating that the path
// stays within the asset directory (no traversal escapes).
func ResolveAsset(file string) (string, error) {
	if file == "" {
		return "", errors.New("empty asset path")
	}
	if !filepath.IsLocal(file) {
		return "", errors.New("asset path must stay in asset directory: ", file)
	}
	path := platform.GetAssetLocation(file)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("asset is not a regular file: ", file)
	}
	return path, nil
}
