// Package mobileconfig builds and signs Apple configuration profiles that
// enrol a device for a client certificate over SCEP.
package mobileconfig

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"
)

const (
	// RSA is the only key type Apple's SCEP payload supports.
	keyType = "RSA"
	keySize = 2048
	// Key Usage bit 1 is "signing", which TLS client authentication needs.
	keyUsageSigning = 1
)

// SCEPProfile describes one device enrolment.
type SCEPProfile struct {
	ProfileUUID string // also the certificate record ID
	PayloadUUID string
	DeviceName  string
	URL         string // step-ca SCEP endpoint
	Challenge   string
	Email       string
	DeviceURI   string
}

type profile struct {
	PayloadContent           []scepPayload `plist:"PayloadContent"`
	PayloadDescription       string        `plist:"PayloadDescription"`
	PayloadDisplayName       string        `plist:"PayloadDisplayName"`
	PayloadIdentifier        string        `plist:"PayloadIdentifier"`
	PayloadOrganization      string        `plist:"PayloadOrganization"`
	PayloadRemovalDisallowed bool          `plist:"PayloadRemovalDisallowed"`
	PayloadType              string        `plist:"PayloadType"`
	PayloadUUID              string        `plist:"PayloadUUID"`
	PayloadVersion           int           `plist:"PayloadVersion"`
}

type scepPayload struct {
	PayloadContent     scepContent `plist:"PayloadContent"`
	PayloadDescription string      `plist:"PayloadDescription"`
	PayloadDisplayName string      `plist:"PayloadDisplayName"`
	PayloadIdentifier  string      `plist:"PayloadIdentifier"`
	PayloadType        string      `plist:"PayloadType"`
	PayloadUUID        string      `plist:"PayloadUUID"`
	PayloadVersion     int         `plist:"PayloadVersion"`
}

type scepContent struct {
	URL              string            `plist:"URL"`
	Name             string            `plist:"Name"`
	Subject          [][][]string      `plist:"Subject"`
	SubjectAltName   map[string]string `plist:"SubjectAltName"`
	Challenge        string            `plist:"Challenge"`
	KeyType          string            `plist:"Key Type"`
	Keysize          int               `plist:"Keysize"`
	KeyUsage         int               `plist:"Key Usage"`
	KeyIsExtractable bool              `plist:"KeyIsExtractable"`
	Retries          int               `plist:"Retries"`
	RetryDelay       int               `plist:"RetryDelay"`
}

// Build returns the unsigned profile as an XML plist.
func Build(p SCEPProfile) ([]byte, error) {
	id := "authstep." + p.ProfileUUID
	doc := profile{
		PayloadContent: []scepPayload{{
			PayloadContent: scepContent{
				URL:              p.URL,
				Name:             "AuthStep",
				Subject:          [][][]string{{{"CN", p.Email}}},
				SubjectAltName:   map[string]string{"rfc822Name": p.Email, "uniformResourceIdentifier": p.DeviceURI},
				Challenge:        p.Challenge,
				KeyType:          keyType,
				Keysize:          keySize,
				KeyUsage:         keyUsageSigning,
				KeyIsExtractable: false,
				Retries:          3,
				RetryDelay:       10,
			},
			PayloadDescription: "Creates a key on this device and requests a client certificate for it.",
			PayloadDisplayName: "Client certificate",
			PayloadIdentifier:  id + ".scep",
			PayloadType:        "com.apple.security.scep",
			PayloadUUID:        p.PayloadUUID,
			PayloadVersion:     1,
		}},
		PayloadDescription:  fmt.Sprintf("Client certificate for %s (%s).", p.DeviceName, p.Email),
		PayloadDisplayName:  "AuthStep: " + p.DeviceName,
		PayloadIdentifier:   id,
		PayloadOrganization: "AuthStep",
		PayloadType:         "Configuration",
		PayloadUUID:         p.ProfileUUID,
		PayloadVersion:      1,
	}
	return plist.MarshalIndent(doc, plist.XMLFormat, "\t")
}

// Sign wraps content in a CMS SignedData (SHA-256) signed by cert, with the
// chain certificates included so the device can build the path to a root.
func Sign(content []byte, cert *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSignerChain(cert, key, chain, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	return sd.Finish()
}
