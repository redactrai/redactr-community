// Package catrust installs/removes Redactr's CA in the OS trust store.
package catrust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// commonName reads the CA cert at pemPath and returns its Subject CommonName.
func commonName(pemPath string) (string, error) {
	b, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", fmt.Errorf("no PEM block in %s", pemPath)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", err
	}
	return c.Subject.CommonName, nil
}

// Install adds the CA at pemPath to the OS trust store (may prompt for sudo/admin).
func Install(pemPath string) error { return installOS(pemPath) }

// Remove removes the CA (by common name) from the OS trust store; no-op if absent.
func Remove(pemPath string) error { return removeOS(pemPath) }

// IsTrusted reports whether the CA is present in the OS trust store.
func IsTrusted(pemPath string) (bool, error) { return isTrustedOS(pemPath) }
