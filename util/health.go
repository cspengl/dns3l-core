package util

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	"github.com/miekg/dns"
)

type Health struct {
	Healthy  bool
	Endpoint string
	Message  string
}

type HealthCheckable interface {
	GetHealth() Health
}

type MultiHealthCheckable interface {
	GetHealth() map[string]Health
}

func CheckHealth(checks ...HealthCheck) (bool, error) {
	for _, check := range checks {
		healthy, err := check()
		if err != nil {
			return false, err
		}
		if !healthy {
			return false, nil
		}
	}
	return true, nil
}

type HealthCheck func() (bool, error)

func CheckDNSResolution(hostnameOrURL string) HealthCheck {
	return func() (bool, error) {
		// try to parse url
		u, err := url.Parse(hostnameOrURL)
		if err == nil && u.Host != "" {
			hostnameOrURL = u.Host
		}
		_, err = net.LookupHost(hostnameOrURL)
		if err != nil {
			return false, fmt.Errorf("dns resolution failed for %s: %w", hostnameOrURL, err)
		}
		return true, nil
	}
}

func CheckTCPConnection(hostnameOrURL string) HealthCheck {
	return func() (bool, error) {
		// try to parse url
		u, err := url.Parse(hostnameOrURL)
		if err == nil && u.Host != "" {
			hostnameOrURL = u.Host
		}
		conn, err := net.Dial("tcp", hostnameOrURL)
		if err != nil {
			return false, fmt.Errorf("tcp connection check failed for %s: %w", hostnameOrURL, err)
		}
		//nolint:errcheck // ignore error on close, since we are only checking connectivity
		defer conn.Close()
		return true, nil
	}
}

func CheckTLSConnection(hostnameOrURL string, insecureSkipVerify bool) HealthCheck {
	return func() (bool, error) {
		// try to parse url
		u, err := url.Parse(hostnameOrURL)
		if err == nil && u.Host != "" {
			hostnameOrURL = u.Host
		}
		conn, err := net.Dial("tcp", hostnameOrURL)
		if err != nil {
			return false, fmt.Errorf("tls connection check failed for %s: %w", hostnameOrURL, err)
		}
		//nolint:errcheck // ignore error on close, since we are only checking connectivity
		defer conn.Close()
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			ServerName:         hostnameOrURL,
		})
		err = tlsConn.Handshake()
		if err != nil {
			return false, fmt.Errorf("tls handshake failed for %s: %w", hostnameOrURL, err)
		}
		return true, nil
	}
}

func CheckDNSServer(hostPort string, hostNames ...string) HealthCheck {
	return func() (bool, error) {
		if len(hostNames) == 0 {
			return false, fmt.Errorf("no host names provided for dns server check")
		}
		for _, hostName := range hostNames {
			m := new(dns.Msg)
			m.SetQuestion(hostName, dns.TypeA)

			_, err := dns.Exchange(m, hostPort)
			if err != nil {
				return false, fmt.Errorf("dns server check failed for %s: %w", hostPort, err)
			}
		}
		return true, nil
	}
}
