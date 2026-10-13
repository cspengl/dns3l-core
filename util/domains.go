package util

import "strings"

// GetDomainFQDNDot is default notation in dns3l
func GetDomainFQDNDot(d string) string {
	if !strings.HasSuffix(d, ".") {
		d = d + "."
	}

	return d
}

// GetDomainNoFQDNDot is used for providers like Infoblox,
// which don't want the dot despite being a FQDN...
func GetDomainNoFQDNDot(d string) string {
	return strings.TrimSuffix(d, ".")
}

func IsWildcard(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}
