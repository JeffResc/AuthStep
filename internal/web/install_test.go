package web

import (
	"strings"
	"testing"
	"time"
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

func TestMinutesLeft(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second:                "1 minute",
		time.Minute:                     "1 minute",
		time.Minute + time.Second:       "2 minutes",
		14*time.Minute + 59*time.Second: "15 minutes",
	} {
		if got := minutesLeft(d); got != want {
			t.Errorf("minutesLeft(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestDeviceExample(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) AppleWebKit/605.1.15": "Personal iPhone",
		"Mozilla/5.0 (iPad; CPU OS 27_0 like Mac OS X) AppleWebKit/605.1.15":          "Personal iPad",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari": "Personal MacBook",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0":   "Personal Computer",
		"Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 Chrome/150.0":   "Personal Phone",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/150.0":             "Personal Computer",
		"curl/8.17.0": "Personal Computer",
	} {
		if got := deviceExample(ua); got != want {
			t.Errorf("deviceExample(%q) = %q, want %q", ua, got, want)
		}
	}
}
