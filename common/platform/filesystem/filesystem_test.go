package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eugene/bypasscore/common/platform"
)

func TestResolveAssetRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.dat")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.dat")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(platform.AssetEnv, root)
	if _, err := ResolveAsset("escape.dat"); err == nil {
		t.Fatal("asset symlink escape was accepted")
	}
}

func TestResolveAssetAllowsInternalSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.dat")
	if err := os.WriteFile(target, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "alias.dat")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(platform.AssetEnv, root)
	got, err := ResolveAsset("alias.dat")
	if err != nil {
		t.Fatal(err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != resolvedTarget {
		t.Fatalf("resolved path = %q, want %q", got, resolvedTarget)
	}
}
