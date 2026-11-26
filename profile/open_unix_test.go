//go:build linux

package profile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestRejectFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	assertFailure(t, testProfile+"tls-crypt fifo\n"+inlinePKI(testkit.NewPKI(t)), Options{Root: root}, CodeFile, "tls-crypt", 4)
}
