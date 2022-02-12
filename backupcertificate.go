package httpproxy

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type BackupCertificateDisk struct {
	PathCertificates string
}

func (backupCert *BackupCertificateDisk) Load(host string) *tls.Certificate {

	path := filepath.Join(backupCert.PathCertificates, host)

	// Load certificate
	cert, err := tls.LoadX509KeyPair(path+".crt", path+".pk.pem")
	if err != nil {
		return nil
	}
	return &cert
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func (backupCert *BackupCertificateDisk) Save(host string, cert *tls.Certificate) error {

	//Create dir
	if _, err := os.Stat(backupCert.PathCertificates); os.IsNotExist(err) {
		err := os.Mkdir(backupCert.PathCertificates, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Path certificate and privateKey
	path := filepath.Join(backupCert.PathCertificates, host)

	// Create privatekey File
	filePrivateKey, err := os.OpenFile(path+".pk.pem", os.O_RDWR|os.O_CREATE, 0700)
	if err != nil {
		return fmt.Errorf("%v:%v", path+".pk.pem", err)
	}
	defer filePrivateKey.Close()

	// Create certificate File
	fileCertificate, err := os.OpenFile(path+".crt", os.O_RDWR|os.O_CREATE, 0700)
	if err != nil {
		return fmt.Errorf("%v:%v", path+".crt", err)
	}
	defer fileCertificate.Close()

	// Encode pem
	pem.Encode(fileCertificate, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	pem.Encode(filePrivateKey, pemBlockForKey(cert.PrivateKey))

	return nil
}

type WithoutBackupCertificate struct {
}

func (backupCert *WithoutBackupCertificate) Load(host string) *tls.Certificate {
	return nil
}
func (backupCert *WithoutBackupCertificate) Save(host string, cert *tls.Certificate) error {
	return nil
}
