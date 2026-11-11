package gateway

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/yetone/magpie/internal/usageapi"
)

// clientIP is the address a request came from, for its usage row: the
// forwarding header's client address when MAGPIE_TRUST_PROXY is set, else
// the connection's own (peerAddr). "" when RemoteAddr isn't an address.
func clientIP(r *http.Request) string {
	if trustProxy() {
		if ip := forwardedIP(r); ip != "" {
			return ip
		}
	}
	a, ok := peerAddr(r)
	if !ok || !a.IsValid() {
		return ""
	}
	return a.String()
}

// forwardedIP reads the client address set by the immediate reverse proxy:
// single-value headers first, then the rightmost valid entry of
// X-Forwarded-For (where the proxy sitting in front of magpie appends the
// connection's peer address, so a client-supplied XFF prefix cannot spoof it).
func forwardedIP(r *http.Request) string {
	for _, h := range []string{"X-Real-IP", "Cf-Connecting-IP", "True-Client-IP"} {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(h))); err == nil && a.IsValid() {
			return a.WithZone("").Unmap().String()
		}
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if a, err := netip.ParseAddr(strings.TrimSpace(parts[i])); err == nil && a.IsValid() {
			return a.WithZone("").Unmap().String()
		}
	}
	return ""
}

// withoutClientIPs is a ledger page with the address each call came from
// taken out: the gateway's usage API answers other computers (Remote
// magpie, a shared gateway's key holders), and where this computer's
// clients connect from stays on it. The Usage page reads it from the GUI's
// own /api/usage/requests.
func withoutClientIPs(l usageapi.Ledger) usageapi.Ledger {
	for i := range l.Rows {
		l.Rows[i].ClientIP = ""
	}
	return l
}
