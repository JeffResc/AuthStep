package web

import (
	"strings"
	"testing"
)

func TestDetectOS(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) AppleWebKit/605.1.15": "ios",
		"Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 Chrome/150.0":   "android",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0":   "windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari": "macos",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/150.0":             "linux",
		"curl/8.17.0": "",
	} {
		if got := detectOS(ua); got != want {
			t.Errorf("detectOS(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestQRSVG(t *testing.T) {
	svg, err := qrSVG("https://authstep.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	s := string(svg)
	if !strings.HasPrefix(s, "<svg") || !strings.Contains(s, `fill="#fff"`) || strings.Count(s, "h1v1h-1z") < 100 {
		t.Fatalf("unexpected SVG: %.200s", s)
	}
}
