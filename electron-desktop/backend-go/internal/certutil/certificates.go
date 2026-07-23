package certutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

type Pair struct {
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	Fingerprint    string `json:"fingerprint"`
	NotAfter       string `json:"not_after"`
}

func GenerateCA(commonName string, validDays int) (Pair, error) {
	if strings.TrimSpace(commonName) == "" {
		commonName = "WSHawk Local Lab CA"
	}
	if validDays <= 0 {
		validDays = 365
	}
	if validDays > 3650 {
		validDays = 3650
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return Pair{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: commonName, Organization: []string{"WSHawk authorized testing"}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Duration(validDays) * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return Pair{}, err
	}
	return pair(der, key, template.NotAfter), nil
}
func GenerateHost(caCertificatePEM, caKeyPEM, hostname string, validDays int) (Pair, error) {
	block, _ := pem.Decode([]byte(caCertificatePEM))
	if block == nil {
		return Pair{}, errors.New("CA certificate PEM is invalid")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Pair{}, err
	}
	keyBlock, _ := pem.Decode([]byte(caKeyPEM))
	if keyBlock == nil {
		return Pair{}, errors.New("CA private key PEM is invalid")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return Pair{}, err
	}
	if !ca.IsCA {
		return Pair{}, errors.New("certificate is not a CA")
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return Pair{}, errors.New("hostname is required")
	}
	if validDays <= 0 {
		validDays = 30
	}
	if validDays > 398 {
		validDays = 398
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Pair{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: hostname}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Duration(validDays) * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return Pair{}, err
	}
	return pair(der, key, template.NotAfter), nil
}
func pair(der []byte, key *rsa.PrivateKey, notAfter time.Time) Pair {
	sum := sha256.Sum256(der)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return Pair{CertificatePEM: string(certificate), PrivateKeyPEM: string(privateKey), Fingerprint: hex.EncodeToString(sum[:]), NotAfter: notAfter.Format(time.RFC3339)}
}
func serial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return value
}
