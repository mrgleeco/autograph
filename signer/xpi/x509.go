package xpi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

// every minute, add an rsa key to the cache. This will block if
// the cache channel is already full, which is what we want anyway
func (s *PKCS7Signer) populateRsaCache(size int) {
	for {
		key, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			log.Fatalf("xpi.populateRsaCache: %v", err)
		}
		s.rsaCache <- key
		time.Sleep(time.Minute)
	}
}

// retrieve a key from the cache or generate one if it takes too long
// or if the size is wrong
func (s *PKCS7Signer) getRsaKey(size int) (*rsa.PrivateKey, error) {
	select {
	case key := <-s.rsaCache:
		if key.N.BitLen() != size {
			// it's theoritically impossible for this to happen
			// because the end entity has the same key size has
			// the signer, but we're paranoid so handling it
			log.Printf("WARNING: xpi rsa cache returned a key of size %d when %d was requested", key.N.BitLen(), size)
			return rsa.GenerateKey(rand.Reader, size)
		}
		return key, nil
	case <-time.After(100 * time.Millisecond):
		// generate a key if none available
		return rsa.GenerateKey(rand.Reader, size)
	}
}


// makeTemplate returns a pointer to a template for an x509.Certificate EE
func (s *PKCS7Signer) makeTemplate(cn string) (*x509.Certificate) {
	return &x509.Certificate{
		// The maximum length of a serial number per rfc 5280 is 20 bytes / 160 bits
		// https://tools.ietf.org/html/rfc5280#section-4.1.2.2
		// Setting it to nanoseconds guarantees we'll never have two conflicting serials
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Addons"},
			OrganizationalUnit: []string{s.OU},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"Mountain View"},
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(8760 * time.Hour), // one year
		SignatureAlgorithm: s.issuerCert.SignatureAlgorithm,
	}
}

// MakeEndEntity generates a private key and certificate ready to sign a given XPI.
// The subject CN of the certificate is taken from the `cn` string passed as argument.
// The type of key is identical to the key of the signer that issues the certificate,
// if the signer uses an RSA 2048 key, so will the end-entity. The signature algorithm
// and expiration date are also copied over from the issuer.
//
// The signed certificate and private key are returned.
func (s *PKCS7Signer) MakeEndEntity(cn string) (eeCert *x509.Certificate, eeKey crypto.PrivateKey, err error) {
	var (
		issuerPrivateKey crypto.PrivateKey
		eePublicKey crypto.PublicKey
		derCert []byte
	)

	template := s.makeTemplate(cn)

	switch s.issuerKey.(type) {
	case *rsa.PrivateKey:
		size := s.issuerKey.(*rsa.PrivateKey).N.BitLen()
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to generate rsa private key of size %d", size)
			return
		}
		issuerPrivateKey = s.issuerKey.(*rsa.PrivateKey)
		eePublicKey = eeKey.(*rsa.PrivateKey).Public()
	case *ecdsa.PrivateKey:
		curve := s.issuerKey.(*ecdsa.PrivateKey).Curve
		eeKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to generate ecdsa private key on curve %s", curve.Params().Name)
			return
		}
		issuerPrivateKey = s.issuerKey.(*ecdsa.PrivateKey)
		eePublicKey = eeKey.(*ecdsa.PrivateKey).Public()
	}
	derCert, err = x509.CreateCertificate(rand.Reader, template, s.issuerCert, eePublicKey, issuerPrivateKey)
	if err != nil {
		err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to create certificate")
		return
	}
	if len(derCert) == 0 {
		err = errors.Errorf("xpi.MakeEndEntity: certificate creation failed for an unknown reason")
		return
	}
	eeCert, err = x509.ParseCertificate(derCert)
	if err != nil {
		err = errors.Wrapf(err, "xpi.MakeEndEntity: certificate parsing failed")
	}
	return
}


// KeyType is the type to use in keyOptions to tell MakeDEREndEntity
// which type of crypto.PrivateKey to generate
type KeyType string
const (
	// keyTypeRSA is the keyOptions.keyType to generate an rsa.PrivateKey
	keyTypeRSA KeyType = "rsa"

	// keyTypeECDSA is the keyOptions.keyType to generate an ecdsa.PrivateKey
	keyTypeECDSA KeyType = "ecdsa"
)

// keyOptions
type keyOptions struct {
	keyType KeyType

	// rsaBits is the bit length or size of the RSA key to generate only applies when keyType is keyTypeRSA
	rsaBits int

	// ecdsaCurve is the elliptic curve to generate an ECDSA key with only applies when keyType is keyTypeECDSA
	ecdsaCurve elliptic.Curve
}

// MakeDEREndEntity generates an EE cert and private key like
// MakeEndEntity but returns the DER encoded certificate bytes instead
// of a X.509 certificate and takes additional options to generate EEs
// using different key types or params than the issuer cert
func (s *PKCS7Signer) MakeDEREndEntity(cn string, opts keyOptions) (eeDERCert []byte, eeKey crypto.PrivateKey, err error) {
	var eePublicKey crypto.PublicKey
	template := s.makeTemplate(cn)
	size := opts.rsaBits
	curve := opts.ecdsaCurve

	switch opts.keyType {
	case keyTypeRSA:
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to generate rsa private key of size %d", size)
			return
		}
		eePublicKey = eeKey.(*rsa.PrivateKey).Public()
	case keyTypeECDSA:
		eeKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to generate ecdsa private key on curve %s", curve.Params().Name)
			return
		}
		eePublicKey = eeKey.(*ecdsa.PrivateKey).Public()
	default:
		err = errors.New("xpi: invalid EE private key type")
		return
	}
	eeDERCert, err = x509.CreateCertificate(rand.Reader, template, s.issuerCert, eePublicKey, s.issuerKey)
	if err != nil {
		err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to create certificate")
		return
	}
	if len(eeDERCert) == 0 {
		err = errors.Errorf("xpi.MakeEndEntity: certificate creation failed for an unknown reason")
		return
	}
	return
}
