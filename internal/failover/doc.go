// Package failover implements remote ordering and retry policy.
//
// It classifies retryable transport failures separately from terminal
// authentication and certificate-validation failures.
package failover
