package httpclient

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
)

type networkPolicy struct {
	allowedHosts map[string]bool
	allowPrivate bool
}

func newNetworkPolicy(hosts []string, allowPrivate bool) (networkPolicy, error) {
	p := networkPolicy{allowedHosts: map[string]bool{}, allowPrivate: allowPrivate}
	normalized, err := NormalizeAllowedHosts(hosts)
	if err != nil {
		return networkPolicy{}, err
	}
	for _, host := range normalized {
		p.allowedHosts[host] = true
	}
	return p, nil
}

// NormalizeAllowedHosts validates exact hostnames/IP literals used as authority
// boundaries. URLs, ports, wildcards, userinfo, and path/query syntax are refused.
func NormalizeAllowedHosts(hosts []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		host := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "[]"))
		if host == "" || strings.Contains(host, "://") || strings.ContainsAny(host, "/?#@* ") {
			return nil, fmt.Errorf("invalid allowed hostname %q (use a hostname without scheme, port, path, or wildcard)", raw)
		}
		if net.ParseIP(host) == nil {
			if strings.Contains(host, ":") || len(host) > 253 {
				return nil, fmt.Errorf("invalid allowed hostname %q", raw)
			}
			for _, label := range strings.Split(host, ".") {
				if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return nil, fmt.Errorf("invalid allowed hostname %q", raw)
				}
				for _, ch := range label {
					if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
						return nil, fmt.Errorf("invalid allowed hostname %q", raw)
					}
				}
			}
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out, nil
}

func (p networkPolicy) validateURL(ctx context.Context, u *url.URL) error {
	host := strings.ToLower(u.Hostname())
	if len(p.allowedHosts) > 0 && !p.allowedHosts[host] {
		return fmt.Errorf("host %q is outside the configured scope", host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("host %q resolved to no addresses", host)
	}
	for _, addr := range addrs {
		if !p.allowPrivate && unsafeIP(addr.IP) {
			return fmt.Errorf("host %q resolves to a private or special-use address", host)
		}
	}
	return nil
}

func (p networkPolicy) dialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		u := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, port)}
		if err := p.validateURL(ctx, u); err != nil {
			return nil, err
		}
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		for _, addr := range addrs {
			if !p.allowPrivate && unsafeIP(addr.IP) {
				continue
			}
			conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			err = dialErr
		}
		return nil, fmt.Errorf("dial approved address for %q: %w", host, err)
	}
}

func unsafeIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// IsGlobalUnicast includes documentation, benchmarking, shared-address-space,
	// and other special-use ranges. They are not valid public scan targets.
	for _, block := range specialUseNetworks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

var specialUseNetworks = mustNetworks(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"2001:db8::/32",
)

func mustNetworks(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, block)
	}
	return out
}
