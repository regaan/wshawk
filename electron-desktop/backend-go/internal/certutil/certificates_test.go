package certutil

import (
	"encoding/pem"
	"testing"
)

func TestGenerateCAAndHostCertificate(t *testing.T) {
	ca, err := GenerateCA("WSHawk Test CA", 30)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode([]byte(ca.CertificatePEM)); block == nil {
		t.Fatal("missing CA PEM")
	}
	host, err := GenerateHost(ca.CertificatePEM, ca.PrivateKeyPEM, "lab.example", 7)
	if err != nil {
		t.Fatal(err)
	}
	if host.Fingerprint == "" || host.NotAfter == "" {
		t.Fatalf("invalid host certificate: %#v", host)
	}
}
