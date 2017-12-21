package crypto

import (
	"fmt"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// add by LR

// ParseOneCertificateFromPEM attempts to parse one PEM encoded certificate object,
// either a raw x509 certificate possibly containing
// multiple certificates, from the top of certsPEM, which itself may
// contain multiple PEM encoded certificate objects.
func ParseOneCertificateFromPEM(certsPEM []byte) ([]*x509.Certificate, []byte, error) {

	block, rest := pem.Decode(certsPEM)
	if block == nil {
		return nil, rest, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, rest, err
	}
	var certs = []*x509.Certificate{cert}
	return certs, rest, nil
}


// ParseCertificatePEM parses and returns a PEM-encoded certificate,
// can handle PEM encoded PKCS #7 structures.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	certPEM = bytes.TrimSpace(certPEM)
	cert, _, err := ParseOneCertificateFromPEM(certPEM)
	if err != nil {
		// Log the actual parsing error but throw a default parse error message.
		fmt.Errorf("Certificate parsing error: %v", err)
		return nil, err
	}
	return cert[0], nil
}

// Get the options to verify
func  getVerifyOptions(certFile string) (*x509.VerifyOptions, error) {

	chain, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(chain)
	if block == nil {
		return nil, fmt.Errorf("No root certificate was found")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse root certificate: %s", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	var intPool *x509.CertPool
	if len(rest) > 0 {
		intPool = x509.NewCertPool()
		if !intPool.AppendCertsFromPEM(rest) {
			return nil, fmt.Errorf("Failed to add intermediate PEM certificates")
		}
	}
	verifyOptions := &x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	return verifyOptions, nil
}

// VerifyCertificate verifies that 'cert' was issued by this CA
// Return nil if successful; otherwise, return an error.
func VerifyCertificate(cert *x509.Certificate, caCertFile string) error {
	opts, err := getVerifyOptions(caCertFile)
	if err != nil {
		return fmt.Errorf("Failed to get verify options: %s", err)
	}
	_, err = cert.Verify(*opts)
	if err != nil {
		return fmt.Errorf("Failed to verify certificate: %s", err)
	}
	//fmt.Print("verify cert OK")
	return nil
}

