package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type safeDialer struct {
	resolver     resolver
	dialer       net.Dialer
	allowPrivate bool
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid destination: %w", err)
	}
	addresses, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("resolve destination: %w", err)
	}
	for _, address := range addresses {
		if !d.allowPrivate && unsafeIP(address.IP) {
			return nil, fmt.Errorf("destination resolves to a prohibited address")
		}
	}
	return d.dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
}

func validateDestination(u *url.URL, allowPrivate bool) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("destination scheme is not allowed")
	}
	if u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("destination host is invalid")
	}
	if ip := net.ParseIP(strings.Trim(u.Hostname(), "[]")); ip != nil && !allowPrivate && unsafeIP(ip) {
		return fmt.Errorf("destination address is prohibited")
	}
	return nil
}

func unsafeIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

func redirectPolicy(allowPrivate bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		if err := validateDestination(req.URL, allowPrivate); err != nil {
			return err
		}
		if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
			return fmt.Errorf("cross-origin redirect is not allowed")
		}
		// Drop credentials even on same-origin redirects; the scanner never needs them.
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		return nil
	}
}
