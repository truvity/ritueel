package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// Program is the copy of ritueel that runs: the member `ritueel` of a plan (docs/reference/
// ceremony-record.md, "The plan"; record 0005, rule 32). The three members are the version, the
// system and architecture as "<GOOS>/<GOARCH>", and the SHA-256 of the program's own file in 64
// lower-case hexadecimal characters.
type Program struct {
	Version string `json:"version"`
	OSArch  string `json:"os_arch"`
	SHA256  string `json:"sha256"`
}

// Self describes the program that runs: its version ([Read]), its system and architecture, and the
// SHA-256 of its own file. The file is the one that os.Executable names, opened read-only and
// hashed as a stream: it is larger than the longest file that the readers of a bundle accept, so it
// is never read whole into memory. A file that cannot be found, opened or read to its end is an
// error and gives no Program: a digest that cannot be computed is not an empty one.
func Self() (Program, error) {
	exe, err := os.Executable()
	if err != nil {
		return Program{}, fmt.Errorf("buildinfo: the file of the running program cannot be found: %w", err)
	}
	sum, err := fileDigest(exe)
	if err != nil {
		return Program{}, err
	}
	return Program{Version: Read().Version, OSArch: runtime.GOOS + "/" + runtime.GOARCH, SHA256: sum}, nil
}

// fileDigest returns the SHA-256 of the regular file at path, read as a stream. A path that is not
// a regular file (a folder, a FIFO, a device) is an error, so that the read never waits.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("buildinfo: the file of the running program cannot be opened: %w", err)
	}
	defer func() {
		// The file was opened to read it only; a failed close loses nothing.
		_ = f.Close()
	}()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("buildinfo: the file of the running program cannot be looked at: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("buildinfo: the file of the running program is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("buildinfo: the file of the running program cannot be read: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
