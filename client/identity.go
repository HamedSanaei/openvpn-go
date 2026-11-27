package client

import "github.com/hamedsanaei/openvpn-go/internal/tlscontrol"

// X509NameMode selects the certificate field used for an identity policy.
type X509NameMode string

const (
	X509Subject    X509NameMode = "subject"
	X509CommonName X509NameMode = "name"
	X509NamePrefix X509NameMode = "name-prefix"
	// X509CommonNamePrefix uses a trusted CA, leaf server usage, and a CN
	// prefix for an endpoint with no usable SAN identity.
	X509CommonNamePrefix X509NameMode = "common-name-prefix"
)

// X509Name is an optional identity policy. Subject and CommonName select
// exact identities. NamePrefix also requires the endpoint's DNS or IP SAN.
// CommonNamePrefix requires an explicit CA and server usage.
// The zero value uses the endpoint's DNS or IP SAN alone.
type X509Name struct {
	Mode  X509NameMode
	Value string
}

// Validate checks that the policy is representable before network activity.
func (n X509Name) Validate() error {
	if !tlscontrol.ValidNamePolicy(string(n.Mode), n.Value) {
		return configError("X.509 name policy")
	}
	return nil
}
