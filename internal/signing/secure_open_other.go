//go:build !linux

package signing

import (
	"fmt"
	"os"
)

func openNoSymlinks(string) (*os.File, error) {
	return nil, fmt.Errorf("secure signer file access requires Linux openat2")
}
