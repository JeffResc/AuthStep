package audit

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("fd00::/8")}
	tests := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct client ignores header", "203.0.113.9:4000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"through trusted proxy", "10.42.0.5:4000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"forged left entries are skipped", "10.42.0.5:4000", []string{"1.2.3.4, 198.51.100.1"}, "198.51.100.1"},
		{"chain of trusted proxies", "10.42.0.5:4000", []string{"198.51.100.1, 10.42.1.1", "10.42.2.2"}, "198.51.100.1"},
		{"no header", "10.42.0.5:4000", nil, "10.42.0.5"},
		{"all hops trusted", "10.42.0.5:4000", []string{"10.42.9.9"}, "10.42.0.5"},
		{"garbage hop is untrusted", "10.42.0.5:4000", []string{"not-an-ip"}, "not-an-ip"},
		{"IPv6 trusted proxy", "[fd00::1]:4000", []string{"2001:db8::7"}, "2001:db8::7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for _, h := range tt.xff {
				r.Header.Add("X-Forwarded-For", h)
			}
			if got := ClientIP(r, trusted); got != tt.want {
				t.Fatalf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}
