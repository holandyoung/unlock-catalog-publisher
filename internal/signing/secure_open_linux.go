//go:build linux

package signing

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openNoSymlinks(filePath string) (*os.File, error) {
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	descriptor, err := unix.Openat2(unix.AT_FDCWD, absolute, how)
	if err != nil {
		return nil, fmt.Errorf("open without symlinks: %w", err)
	}
	return os.NewFile(uintptr(descriptor), absolute), nil
}
