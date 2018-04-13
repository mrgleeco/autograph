package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/rand"
	"time"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/pkcs7"
	"go.mozilla.org/cose"
)

const (
	// Type of this signer is "xpi"
	Type = "xpi"

	// ModeAddOn represents a signer that issues signatures for
	// regular firefox add-ons and web extensions developed by anyone
	ModeAddOn = "add-on"

	// ModeExtension represents a signer that issues signatures for
	// internal extensions developed by Mozilla
	ModeExtension = "extension"

	// ModeSystemAddOn represents a signer that issues signatures for
	// System Add-Ons developed by Mozilla
	ModeSystemAddOn = "system add-on"

	// ModeHotFix represents a signer that issues signatures for
	// Firefox HotFixes
	ModeHotFix = "hotfix"

	// SubSignerType all subsigners must be this type
	SubSignerType = "cose"
)

type EESignerConfig struct {
	signer.Configuration
	issuerKey  crypto.PrivateKey
	issuerCert *x509.Certificate

	// OU is the organizational unit of the end-entity certificate
	// generated for each operation performed by this signer
	OU string

	// EndEntityCN is the subject CN of the end-entity certificate generated
	// for each operation performed by this signer. Most of the time
	// the ID will be left blank and provided by the requester of the
	// signature, but for hotfix signers, it is set to a specific value.
	EndEntityCN string
}

// A PKCS7Signer is configured to issue PKCS7 detached signatures
// for Firefox Add-ons of various types.
type PKCS7Signer struct {
	EESignerConfig

	// rsa cache is used to pre-generate RSA private keys and speed up
	// the signing process
	rsaCache chan *rsa.PrivateKey
}

// A COSESigner adds COSE signatures to a SignMessage
type COSESigner struct {
	EESignerConfig

	// the COSE Algorithm to use for signing
	alg cose.Algorithm
}

// An XPISigner issues COSE signatures and an optional PKCS7 detached
// signature for Firefox Add-ons.
type XPISigner struct {
	maybePKCS7Signer *PKCS7Signer
	coseSigners []COSESigner
}

func (s *XPISigner) Config() signer.Configuration {
	if s.maybePKCS7Signer != nil {
		return s.maybePKCS7Signer.Config()
	} else {
		panic("not implemented")
	}
}
func (s *XPISigner) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	if s.maybePKCS7Signer != nil {
		return s.maybePKCS7Signer.SignFile(input, options)
	} else {
		panic("not implemented")
	}
}
func (s *XPISigner) SignData(sigfile []byte, options interface{}) (signer.Signature, error) {
	if s.maybePKCS7Signer != nil {
		return s.maybePKCS7Signer.SignData(sigfile, options)
	} else {
		panic("not implemented")
	}
}

func newPKCS7Signer(conf signer.Configuration) (s *PKCS7Signer, err error) {
	s = new(PKCS7Signer)
	if conf.Type != Type {
		return nil, errors.Errorf("xpi: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type
	if conf.ID == "" {
		return nil, errors.New("xpi: missing signer ID in signer configuration")
	}
	s.ID = conf.ID
	if conf.PrivateKey == "" {
		return nil, errors.New("xpi: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	s.issuerKey, err = signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "xpi: failed to parse private key")
	}
	block, _ := pem.Decode([]byte(conf.Certificate))
	if block == nil {
		return nil, errors.New("xpi: failed to parse certificate PEM")
	}
	s.issuerCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: could not parse X.509 certificate")
	}
	// some sanity checks for the signer cert
	if !s.issuerCert.IsCA {
		return nil, errors.New("xpi: signer certificate must have CA constraint set to true")
	}
	if time.Now().Before(s.issuerCert.NotBefore) || time.Now().After(s.issuerCert.NotAfter) {
		return nil, errors.New("xpi: signer certificate is not currently valid")
	}
	if s.issuerCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("xpi: signer certificate is missing certificate signing key usage")
	}
	hasCodeSigning := false
	for _, eku := range s.issuerCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return nil, errors.New("xpi: signer certificate does not have code signing EKU")
	}
	switch conf.Mode {
	case ModeAddOn:
		s.OU = "Production"
	case ModeExtension:
		s.OU = "Mozilla Extensions"
	case ModeSystemAddOn:
		s.OU = "Mozilla Components"
	case ModeHotFix:
		// FIXME: this also needs to pin the signing key somehow
		s.OU = "Production"
		s.EndEntityCN = "firefox-hotfix@mozilla.org"
	default:
		return nil, errors.Errorf("xpi: unknown signer mode %q, must be 'add-on', 'extension', 'system add-on' or 'hotfix'", conf.Mode)
	}
	s.Mode = conf.Mode

	// If the private key is rsa, launch a go routine that populates
	// the rsa cache with private keys of the same length
	if _, ok := s.issuerKey.(*rsa.PrivateKey); ok {
		s.rsaCache = make(chan *rsa.PrivateKey, 100)
		go s.populateRsaCache(s.issuerKey.(*rsa.PrivateKey).N.BitLen())
	}

	return
}

// New initializes an XPI signer using a configuration
func New(conf signer.Configuration) (s *XPISigner, err error) {
	var (
		pkcs7Signer *PKCS7Signer
	)
	s = new(XPISigner)

	if len(conf.COSESigners) > 0 {
		for _, coseConf := range conf.COSESigners {
			coseSigner, coseErr := newCOSESigner(coseConf)
			if coseErr != nil {
				err = errors.Wrapf(coseErr, "xpi: error parsing COSESigner conf")
				return
			}
			s.coseSigners = append(s.coseSigners, *coseSigner)
		}
	}

	pkcs7Signer, err = newPKCS7Signer(conf)
	if err != nil && len(s.coseSigners) < 1 {  // errors are OK if we have a COSESigner
		err = err
		return
	} else if err == nil {
		s.maybePKCS7Signer = pkcs7Signer
	}

	return
}

var supportedCOSEAlgorithms = map[*cose.Algorithm]bool{
	cose.GetAlgByNameOrPanic("PS256"): true,
	cose.GetAlgByNameOrPanic("ES256"): true,
	cose.GetAlgByNameOrPanic("ES384"): true,
	cose.GetAlgByNameOrPanic("ES512"): true,
}

func newCOSESigner(conf signer.Configuration) (s *COSESigner, err error) {
	if conf.Type != SubSignerType {
		return nil, errors.Errorf("xpi: invalid sub signer type %q, must be %q", conf.Type, SubSignerType)
	}
	s.Type = conf.Type
	if conf.PrivateKey == "" {
		return nil, errors.New("xpi: missing private key in sub signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	s.issuerKey, err = signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "xpi: failed to parse private key")
	}
	block, _ := pem.Decode([]byte(conf.Certificate))
	if block == nil {
		return nil, errors.New("xpi: failed to parse certificate PEM")
	}
	s.issuerCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: could not parse X.509 certificate")
	}
	// some sanity checks for the signer cert
	if !s.issuerCert.IsCA {
		return nil, errors.New("xpi: sub signer certificate must have CA constraint set to true")
	}
	if time.Now().Before(s.issuerCert.NotBefore) || time.Now().After(s.issuerCert.NotAfter) {
		return nil, errors.New("xpi: sub signer certificate is not currently valid")
	}
	if s.issuerCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("xpi: sub signer certificate is missing certificate signing key usage")
	}
	hasCodeSigning := false
	for _, eku := range s.issuerCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return nil, errors.New("xpi: sub signer certificate does not have code signing EKU")
	}
	switch conf.Mode {
	case ModeAddOn:
		s.OU = "Production"
	case ModeExtension:
		s.OU = "Mozilla Extensions"
	case ModeSystemAddOn:
		s.OU = "Mozilla Components"
	case ModeHotFix:
		// FIXME: this also needs to pin the signing key somehow
		s.OU = "Production"
		s.EndEntityCN = "firefox-hotfix@mozilla.org"
	default:
		return nil, errors.Errorf("xpi: unknown signer mode %q, must be 'add-on', 'extension', 'system add-on' or 'hotfix'", conf.Mode)
	}
	s.Mode = conf.Mode

	// COSE Alg validation
	alg, algErr := cose.GetAlgByName(string(conf.Algorithm))
	if algErr != nil {
		err = errors.Wrapf(algErr, "xpi: unrecognized algorithm COSE Signing algorithm")
		return
	}
	if _, exists := supportedCOSEAlgorithms[alg]; !exists {
		err = errors.Wrapf(algErr, "xpi: COSE algorithm is not supported")
		return
	}

	return
}

// Config returns the configuration of the current signer
func (s *PKCS7Signer) Config() signer.Configuration {
	return signer.Configuration{
		ID:          s.ID,
		Type:        s.Type,
		Mode:        s.Mode,
		PrivateKey:  s.PrivateKey,
		Certificate: s.Certificate,
	}
}

// SignFile takes an unsigned zipped XPI file and returned a signed XPI file
func (s *PKCS7Signer) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	var (
		signedFile []byte
	)
	manifest, err := makeJARManifest(input)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot make JAR manifest from XPI")
	}

	eeCert, eeKey, err := s.makeEE(options)
	if err != nil {
		return nil, err
	}

	// TODO: COSE sign manifest
	// coseMsg, err := s.signDataCOSE(manifest, eeCert, eeKey)
	// if err != nil {
	// 	return nil, err
	// }

	// TODO: add entries for the cose files to the manifest as cose.manifest and cose.sig?
	sigfile, err := makeJARSignature(manifest)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot make JAR manifest signature from XPI")
	}

	// TODO: split this so we can use the certs in the XPI?
	p7sig, err := s.signDataWithEE(sigfile, eeCert, eeKey)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: failed to sign XPI")
	}

	// TODO: cose files to repackJAR and update it to add them to the ZIP/XPI
	signedFile, err = repackJAR(input, manifest, sigfile, p7sig)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: failed to repack XPI")
	}
	return signedFile, nil
}

func (s *PKCS7Signer) signDataCOSE(manifest []byte, eeCert *x509.Certificate, eeKey crypto.PrivateKey) (msg *cose.SignMessage, err error) {
	// create a slot for a COSE Signature
	sig := cose.NewSignature()
	sig.Headers.Protected["alg"] = "PS256" // TODO: parameterize
	sig.Headers.Protected["kid"] = "<DER encoded cert chain>" // NB: double check that kid should be in protected

	tmp := cose.NewSignMessage([]byte(""))
	msg = &tmp
	msg.Payload = manifest
	msg.AddSignature(sig)

	external := []byte("")
	randReader := rand.New(rand.NewSource(time.Now().UnixNano()))

	// create a COSE.Signer
	signer, err := cose.NewSigner(&eeKey)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: COSE signer creation failed")
	}

	err = msg.Sign(randReader, external, cose.SignOpts{
		HashFunc: crypto.SHA256,
		GetSigner: func(index int, signature cose.Signature) (cose.Signer, error) {
			return *signer, nil
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "xpi: COSE signing failed")
	}

	// don't include signature in payload
	// TODO: are we not using external bytes because it requires rolling our own authentication?
	msg.Payload = nil

	return
}

// SignData takes an input signature file and returns a PKCS7 detached signature
func (s *PKCS7Signer) SignData(sigfile []byte, options interface{}) (signer.Signature, error) {
	p7sig, err := s.signData(sigfile, options)
	if err != nil {
		return nil, err
	}
	sig := new(Signature)
	sig.Data = p7sig
	sig.Finished = true
	return sig, nil
}

func (s *PKCS7Signer) makeEE(options interface{}) (eeCert *x509.Certificate, eeKey crypto.PrivateKey, err error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, nil, errors.Wrap(err, "xpi: cannot get options")
	}
	cn := opt.ID
	if s.EndEntityCN != "" {
		cn = s.EndEntityCN
	}
	if cn == "" {
		return nil, nil, errors.New("xpi: missing common name")
	}
	eeCert, eeKey, err = s.MakeEndEntity(cn)
	if err != nil {
		return nil, nil, err
	}
	return
}

func (s *PKCS7Signer) signDataWithEE(sigfile []byte, eeCert *x509.Certificate, eeKey crypto.PrivateKey) ([]byte, error) {
	toBeSigned, err := pkcs7.NewSignedData(sigfile)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot initialize signed data")
	}
	// XPIs are signed with SHA1
	toBeSigned.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1)
	err = toBeSigned.AddSignerChain(eeCert, eeKey, []*x509.Certificate{s.issuerCert}, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot sign")
	}
	toBeSigned.Detach()
	p7sig, err := toBeSigned.Finish()
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot finish signing data")
	}
	return p7sig, nil
}

func (s *PKCS7Signer) signData(sigfile []byte, options interface{}) ([]byte, error) {
	eeCert, eeKey, err := s.makeEE(options)
	if err != nil {
		return nil, err
	}
	return s.signDataWithEE(sigfile, eeCert, eeKey)
}

// Options contains specific parameters used to sign XPIs
type Options struct {
	// ID is the add-on ID which is stored in the end-entity subject CN
	ID string `json:"id"`
}

// GetDefaultOptions returns default options of the signer
func (s *XPISigner) GetDefaultOptions() interface{} {
	return Options{ID: "test@example.net"}
}

// GetOptions takes a input interface and reflects it into a struct of options
func GetOptions(input interface{}) (options Options, err error) {
	buf, err := json.Marshal(input)
	if err != nil {
		return
	}
	err = json.Unmarshal(buf, &options)
	return
}

// Signature is a PKCS7 detached signature
type Signature struct {
	p7       *pkcs7.PKCS7
	Data     []byte
	Finished bool
}

// Marshal returns the base64 representation of a PKCS7 detached signature
func (sig *Signature) Marshal() (string, error) {
	if !sig.Finished {
		return "", errors.New("xpi: cannot marshal unfinished signature")
	}
	if len(sig.Data) == 0 {
		return "", errors.New("xpi: cannot marshal empty signature data")
	}
	return base64.StdEncoding.EncodeToString(sig.Data), nil
}

// Unmarshal takes the base64 representation of a PKCS7 detached signature
// and the content of the signed data, and returns a PKCS7 struct
func Unmarshal(signature string, content []byte) (sig *Signature, err error) {
	sig = new(Signature)
	sig.Data, err = base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return sig, errors.Wrap(err, "xpi.Unmarshal: failed to decode base64 signature")
	}
	sig.p7, err = pkcs7.Parse(sig.Data)
	if err != nil {
		return sig, errors.Wrap(err, "xpi.Unmarshal: failed to parse pkcs7 signature")
	}
	sig.p7.Content = content
	sig.Finished = true
	return
}

// VerifyWithChain verifies an xpi signature using the provided truststore
func (sig *Signature) VerifyWithChain(truststore *x509.CertPool) error {
	if !sig.Finished {
		return errors.New("xpi.VerifyWithChain: cannot verify unfinished signature")
	}
	return sig.p7.VerifyWithChain(truststore)
}

// String returns a PEM encoded PKCS7 block
func (sig *Signature) String() string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PKCS7", Bytes: sig.Data})
	return string(buf.Bytes())
}
