package netsec

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestParsePortsBoundsAndSorts(t *testing.T) {
	ports, err := parsePorts("443,80,8000-8002")
	if err != nil {
		t.Fatal(err)
	}
	expected := []int{80, 443, 8000, 8001, 8002}
	for index, value := range expected {
		if ports[index] != value {
			t.Fatalf("unexpected ports: %#v", ports)
		}
	}
	if _, err := parsePorts("1-5000"); err == nil {
		t.Fatal("expected oversized range rejection")
	}
}
func TestHostnameNormalization(t *testing.T) {
	host, err := hostname("https://example.test:8443/path")
	if err != nil || host != "example.test" {
		t.Fatalf("unexpected host: %q %v", host, err)
	}
	if _, err := hostname("bad host"); err == nil {
		t.Fatal("expected invalid hostname rejection")
	}
}

func TestSubdomainsSeparateWildcardDNSMatches(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]string, error) {
		switch {
		case strings.HasPrefix(host, "canary-"):
			return []string{"203.0.113.10"}, nil
		case host == "www.example.test":
			return []string{"203.0.113.20"}, nil
		case host == "api.example.test":
			return []string{"203.0.113.10"}, nil
		default:
			return nil, errors.New("not found")
		}
	}
	result, err := discoverSubdomains(context.Background(), "example.test", []string{"www", "api", "missing"}, []string{"canary-one.example.test", "canary-two.example.test"}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if result["wildcard_detected"] != true || result["wildcard_filtered"] != 1 {
		t.Fatalf("expected wildcard DNS detection: %#v", result)
	}
	confirmed := result["subdomains"].([]subdomainResult)
	ambiguous := result["ambiguous"].([]subdomainResult)
	if len(confirmed) != 1 || confirmed[0].Name != "www.example.test" || len(ambiguous) != 1 || ambiguous[0].Name != "api.example.test" {
		t.Fatalf("unexpected confirmed/ambiguous split: %#v", result)
	}
}

func TestPortScanCapturesPassiveBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_, _ = connection.Write([]byte("220 owned-test FTP ready\r\n"))
			connection.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	result, err := PortScan(context.Background(), "127.0.0.1", strconv.Itoa(port), 1000)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result["open_ports"])
	if err != nil {
		t.Fatal(err)
	}
	var open []struct {
		Banner string `json:"banner"`
	}
	if err := json.Unmarshal(raw, &open); err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || !strings.Contains(open[0].Banner, "owned-test FTP") {
		t.Fatalf("expected a passive service banner: %#v", result)
	}
}
