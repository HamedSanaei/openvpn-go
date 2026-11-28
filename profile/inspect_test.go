package profile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestInspectEnumeratesAndRedacts(t *testing.T) {
	text := "client\nremote private.example 443 tcp\nverb 3\ncompress lzo\nsynthetic-unknown confidential\nallow-compression yes\n<auth-user-pass>\nsecret-user\nsecret-password\n</auth-user-pass>\n<secret>\nINLINE-MATERIAL\n</secret>\nup /private/script\nca /private/ca\n"
	report, err := Inspect(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	want := []CapabilityEntry{
		{1, "client", Supported, ""}, {2, "remote", Supported, ""}, {3, "verb", Ignored, CodeIgnored},
		{4, "compress", PolicyDisabled, CodeUnsupported}, {5, "", Rejected, CodeUnsupported},
		{6, "allow-compression", PolicyDisabled, CodeUnsupported}, {7, "auth-user-pass", Supported, ""},
		{11, "secret", PolicyDisabled, CodeUnsupported}, {14, "up", PolicyDisabled, CodeUnsupported},
		{15, "ca", Rejected, CodeFile},
	}
	if len(report.Entries) != len(want) {
		t.Fatalf("entries = %+v", report.Entries)
	}
	for i, entry := range report.Entries {
		if entry != want[i] {
			t.Errorf("entry %d = %+v; want %+v", i, entry, want[i])
		}
	}
	json, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"private.example", "synthetic-unknown", "confidential", "secret-user",
		"secret-password", "INLINE-MATERIAL", "/private/script", "/private/ca"} {
		if strings.Contains(string(json), value) {
			t.Fatal("report exposed profile input")
		}
	}
}

func TestInspectDisabledRegistry(t *testing.T) {
	for name := range unsupported {
		report, err := Inspect(strings.NewReader(name + " REDACTED_VALUE\n"))
		if err != nil || len(report.Entries) != 1 ||
			report.Entries[0] != (CapabilityEntry{1, name, PolicyDisabled, CodeUnsupported}) {
			t.Fatalf("%s classification = %+v, %v", name, report, err)
		}
	}
}

func TestInspectRecoversAfterMissingBlockRemote(t *testing.T) {
	source := "<connection>\nproto udp\n</connection>\nclient\ndev tun\nremote localhost\n"
	report, err := Inspect(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	var missing, recognized bool
	for _, entry := range report.Entries {
		missing = missing || entry.Line == 3 && entry.Directive == "connection" && entry.Code == CodeRequired
		recognized = recognized || entry.Line == 4 && entry.Directive == "client" && entry.Capability == Supported
	}
	if !missing || !recognized {
		t.Fatalf("unexpected inspection recovery: %+v", report.Entries)
	}
	if _, _, err := Parse(strings.NewReader(source), Options{}); err == nil {
		t.Fatal("strict import accepted the incomplete block")
	}
}

func TestInspectSkippedInlineSectionsRequireClosingTag(t *testing.T) {
	for _, inspect := range []func(string) (Report, error){
		func(s string) (Report, error) { return Inspect(strings.NewReader(s)) },
		func(s string) (Report, error) {
			return InspectWithOptions(strings.NewReader(s), Options{ProtonVPNVerifyIP: true})
		},
	} {
		for _, tc := range []struct {
			tail   string
			closed bool
		}{
			{"", false},
			{"</different>", false},
			{"</secret>\n", true},
			{"  </secret>\t\n", true},
		} {
			report, err := inspect("client\n<secret>\nprivate-marker\nremote private-host\n" + tc.tail)
			if err != nil {
				t.Fatal(err)
			}
			want := []CapabilityEntry{{1, "client", Supported, ""}, {2, "secret", PolicyDisabled, CodeUnsupported}}
			if !tc.closed {
				want = append(want, CapabilityEntry{2, "secret", Rejected, CodeSyntax})
			}
			if !slices.Equal(report.Entries, want) {
				t.Fatalf("unexpected report: %+v", report.Entries)
			}
		}
	}
}
