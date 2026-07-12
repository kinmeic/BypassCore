// Package platform provides environment-based configuration helpers.
package platform // import "github.com/eugene/bypasscore/common/platform"

import (
	"os"
	"path/filepath"
)

// AssetEnv is the environment variable consulted for the asset directory.
const AssetEnv = "BYPASSCORE_ASSETS"

// GetAssetLocation returns the full path to an asset file.
//
// The asset directory is resolved, in priority order, from:
//  1. the BYPASSCORE_ASSETS environment variable
//  2. the current working directory
//
// If `file` is already absolute, it is returned as-is.
func GetAssetLocation(file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	dir := os.Getenv(AssetEnv)
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			dir = "."
		}
	}
	return filepath.Join(dir, file)
}
