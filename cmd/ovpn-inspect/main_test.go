package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestInspectProfile(t *testing.T) {
	pki := testkit.NewPKI(t)
	head := "client\ndev tun\nremote sensitive-marker.test\nremote-random\nverb 3\n"
	text := head + fmt.Sprintf("<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n",
		pki.CA, pki.Client.Certificate, pki.Client.PrivateKey)
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	if code := run([]string{"-"}, strings.NewReader(text), stdout, stderr); code != 0 ||
		!strings.Contains(stdout.String(), "Remotes: 1") || !strings.Contains(stderr.String(), "ignored_directive (verb)") {
		t.Fatalf("inspect valid profile failed with exit %d, stdout %q and stderr %q", code, stdout, stderr)
	}
	if strings.Contains(stdout.String()+stderr.String(), "sensitive-marker") {
		t.Fatal("inspection exposed profile input")
	}

	root := t.TempDir()
	for name, data := range map[string][]byte{
		"ca": pki.CA, "cert": pki.Client.Certificate, "key": pki.Client.PrivateKey,
		"profile": []byte(head + "ca ca\ncert cert\nkey key\n"),
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "profile")
	if code := run([]string{path}, nil, stdout, stderr); code != 1 ||
		!strings.Contains(stderr.String(), "file_unavailable (ca)") {
		t.Fatalf("expected file references to require an explicit root: %d", code)
	}
	if code := run([]string{"-root", root, path}, nil, stdout, stderr); code != 0 {
		t.Fatalf("could not inspect profile with references: %d", code)
	}
}

type brokenOutput struct{}

func (brokenOutput) Write(p []byte) (int, error) {
	return len(p) / 2, errors.New("private output detail")
}

func TestInspectOutputFailures(t *testing.T) {
	pki := testkit.NewPKI(t)
	text := "client\ndev tun\nremote localhost\n" + fmt.Sprintf("<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n",
		pki.CA, pki.Client.Certificate, pki.Client.PrivateKey)
	for _, args := range [][]string{{"-"}, {"-capabilities", "-"}, {"-help"}} {
		var diagnostics bytes.Buffer
		if code := run(args, strings.NewReader(text), brokenOutput{}, &diagnostics); code != 1 ||
			strings.Contains(diagnostics.String(), "private output detail") {
			t.Fatalf("failed writer: exit %d, diagnostics %q", code, diagnostics.String())
		}
		if code := run(args, strings.NewReader(text), brokenOutput{}, brokenOutput{}); code != 1 {
			t.Fatalf("failed stderr changed exit status: %d", code)
		}
	}
	if code := run(nil, nil, brokenOutput{}, brokenOutput{}); code != 2 {
		t.Fatalf("invalid usage changed exit status: %d", code)
	}
}

func TestInspectCapabilitiesRejectsConflictingProviderFlags(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "sensitive-marker")
	for _, incompatible := range [][]string{
		{"-expressvpn"}, {"-protonvpn-server-name", "sensitive-marker"}, {"-protonvpn-verify-ip"},
	} {
		var stdout, stderr bytes.Buffer
		args := []string{"-capabilities", "-access-server-name", "sensitive-marker", "-auth-file", missing}
		args = append(args, incompatible...)
		args = append(args, missing)
		code := run(args, nil, &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "conflicting_directive") ||
			strings.Contains(stderr.String(), "sensitive-marker") {
			t.Fatalf("conflicting options returned %d, stdout %q and stderr %q", code, &stdout, &stderr)
		}
	}
}

func TestInspectCapabilitiesReportsIncompleteUnsupportedInline(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-capabilities", "-"}, strings.NewReader("client\n<secret>\nprivate-marker\n</wrong>\n"),
		&stdout, &stderr)
	if code != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "invalid_syntax") ||
		!strings.Contains(stdout.String(), "unsupported_directive") || strings.Contains(stdout.String(), "private-marker") {
		t.Fatalf("unexpected exit %d and report %q, diagnostics %q", code, &stdout, &stderr)
	}
}
