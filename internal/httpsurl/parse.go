// Package httpsurl applies the common syntax policy for browser handoffs.
package httpsurl

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Parse validates a bounded absolute HTTPS URL. The caller owns policy for
// the origin, callback path, query parameters and navigation.
func Parse(value string, maxBytes int) *url.URL {
	if len(value) > maxBytes || strings.ContainsAny(value, "\\#") ||
		strings.ContainsFunc(value, unicode.IsControl) {
		return nil
	}
	uri, err := url.Parse(value)
	if err != nil || uri.Scheme != "https" || uri.Hostname() == "" ||
		uri.User != nil || strings.HasSuffix(uri.Host, ":") {
		return nil
	}
	if strings.HasPrefix(uri.Host, "[") || strings.Contains(uri.Hostname(), ":") {
		addr, err := netip.ParseAddr(uri.Hostname())
		if !strings.HasPrefix(uri.Host, "[") || err != nil || !addr.Is6() {
			return nil
		}
	}
	if port := uri.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil
		}
	}
	return uri
}
