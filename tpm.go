// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package main

// TPM support.
//
// Two secrets never exist as plain files on a production node:
//
//   - the device key behind the mTLS certificate is created inside the TPM and
//     cannot leave it; the proxy signs TLS handshakes through the TPM
//   - the master key is sealed by the TPM; the sealed blob is useless on any
//     other machine
//
// Both are stored as TPM blobs (public + encrypted private part) wrapped in
// PEM. They are bound to this TPM's storage root key (SRK), which the TPM
// derives from its internal seed and which is never stored anywhere.
//
// The sealing policy is deliberately not bound to PCRs (measured boot), so
// kernel and OS updates on any distribution keep working. It protects against
// copying disks or backups to another machine, not against root on this node,
// which is the customer anyway.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	pemTPMKey    = "VEIL TPM KEY"    // TPM-wrapped ECDSA P-256 signing key
	pemTPMSealed = "VEIL TPM SEALED" // TPM-sealed secret (the master key)
)

// openTPM opens the TPM at path. A build with -tags tpmsim adds the
// "simulator:<seed>" pseudo path for tests (see tpmsim.go).
var openTPM = func(path string) (transport.TPMCloser, error) {
	return linuxtpm.Open(path)
}

type tpmDevice struct {
	mu  sync.Mutex // the TPM executes one command at a time
	tpm transport.TPMCloser
	srk tpm2.AuthHandle
}

func newTPMDevice(path string) (*tpmDevice, error) {
	t, err := openTPM(path)
	if err != nil {
		return nil, fmt.Errorf("open TPM %s: %v", path, err)
	}
	// The SRK is re-derived on every start from the TPM's seed; the same
	// template always yields the same key.
	rsp, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(t)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("TPM storage root key: %v", err)
	}
	return &tpmDevice{tpm: t, srk: tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)}}, nil
}

func (d *tpmDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tpm2.FlushContext{FlushHandle: d.srk.Handle}.Execute(d.tpm)
	return d.tpm.Close()
}

// blob layout: len(public) (2) | TPM2B_PUBLIC | TPM2B_PRIVATE
func encodeBlob(pub tpm2.TPM2BPublic, priv tpm2.TPM2BPrivate) []byte {
	p := tpm2.Marshal(pub)
	out := binary.BigEndian.AppendUint16(nil, uint16(len(p)))
	return append(append(out, p...), tpm2.Marshal(priv)...)
}

func decodeBlob(b []byte) (*tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, error) {
	if len(b) < 2 || len(b) < 2+int(binary.BigEndian.Uint16(b)) {
		return nil, nil, errors.New("truncated TPM blob")
	}
	n := 2 + int(binary.BigEndian.Uint16(b))
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b[2:n])
	if err != nil {
		return nil, nil, err
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b[n:])
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func (d *tpmDevice) create(pub tpm2.TPMTPublic, data []byte) ([]byte, error) {
	cmd := tpm2.Create{ParentHandle: d.srk, InPublic: tpm2.New2B(pub)}
	if data != nil {
		cmd.InSensitive = tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data})}}
	}
	d.mu.Lock()
	rsp, err := cmd.Execute(d.tpm)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return encodeBlob(rsp.OutPublic, rsp.OutPrivate), nil
}

func (d *tpmDevice) load(blob []byte) (tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	pub, priv, err := decodeBlob(blob)
	if err != nil {
		return tpm2.AuthHandle{}, nil, err
	}
	d.mu.Lock()
	rsp, err := tpm2.Load{ParentHandle: d.srk, InPrivate: *priv, InPublic: *pub}.Execute(d.tpm)
	d.mu.Unlock()
	if err != nil {
		return tpm2.AuthHandle{}, nil, fmt.Errorf("load TPM object (blob from another TPM?): %v", err)
	}
	contents, err := pub.Contents()
	if err != nil {
		return tpm2.AuthHandle{}, nil, err
	}
	return tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)}, contents, nil
}

func (d *tpmDevice) flush(h tpm2.AuthHandle) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tpm2.FlushContext{FlushHandle: h.Handle}.Execute(d.tpm)
}

// ---------------------------------------------------------------- device key

var signingKeyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true, NoDA: true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		CurveID: tpm2.TPMECCNistP256,
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
	}),
}

// tpmSigner is a crypto.Signer whose private key lives in the TPM.
type tpmSigner struct {
	d   *tpmDevice
	h   tpm2.AuthHandle
	pub *ecdsa.PublicKey
}

func (d *tpmDevice) signer(blob []byte) (*tpmSigner, error) {
	h, pub, err := d.load(blob)
	if err != nil {
		return nil, err
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	pk, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, err
	}
	return &tpmSigner{d: d, h: h, pub: pk}, nil
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }

// Sign is used by crypto/tls (ECDSA P-256 with SHA-256 in TLS 1.3) and for CSRs.
func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("TPM key signs SHA-256 digests only, not %v", opts.HashFunc())
	}
	s.d.mu.Lock()
	rsp, err := tpm2.Sign{
		KeyHandle: s.h,
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(s.d.tpm)
	s.d.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("TPM sign: %v", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer)})
}

// ---------------------------------------------------------------- sealed master key

var sealedDataTemplate = tpm2.TPMTPublic{
	Type:             tpm2.TPMAlgKeyedHash,
	NameAlg:          tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
		Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
}

func (d *tpmDevice) seal(secret []byte) ([]byte, error) {
	return d.create(sealedDataTemplate, secret)
}

func (d *tpmDevice) unseal(blob []byte) ([]byte, error) {
	h, _, err := d.load(blob)
	if err != nil {
		return nil, err
	}
	defer d.flush(h)
	d.mu.Lock()
	rsp, err := tpm2.Unseal{ItemHandle: h}.Execute(d.tpm)
	d.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("TPM unseal: %v", err)
	}
	return rsp.OutData.Buffer, nil
}

// ---------------------------------------------------------------- loading key material

// tpmOpener opens the TPM on first use and shares it between all users.
type tpmOpener struct {
	path string
	once sync.Once
	dev  *tpmDevice
	err  error
}

func (o *tpmOpener) get() (*tpmDevice, error) {
	o.once.Do(func() { o.dev, o.err = newTPMDevice(o.path) })
	return o.dev, o.err
}

func (o *tpmOpener) close() error {
	if o.dev != nil {
		return o.dev.Close()
	}
	return nil
}

// loadMasterKey reads the master key: TPM-sealed (production) or hex (development).
func loadMasterKey(file string, tpm *tpmOpener) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != pemTPMSealed {
			return nil, fmt.Errorf("%s: unexpected PEM type %q", file, block.Type)
		}
		dev, err := tpm.get()
		if err != nil {
			return nil, err
		}
		key, err := dev.unseal(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", file, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("%s: sealed master key has %d bytes, want 32", file, len(key))
		}
		return key, nil
	}
	key, err := hexKey(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", file, err)
	}
	return key, nil
}

func hexKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(key) != 32 {
		return nil, errors.New("must contain exactly 64 hex characters or a TPM-sealed key")
	}
	return key, nil
}

// ---------------------------------------------------------------- subcommands

// tpmCommand implements "veil-proxy tpm-keygen" and "veil-proxy tpm-seal".
// In production veil-agent does this during enrollment.
func tpmCommand(args []string) error {
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	path := fs.String("tpm", "/dev/tpmrm0", "TPM device")
	out := fs.String("out", "", "output file for the TPM blob")
	switch args[0] {
	case "tpm-keygen":
		csrFile := fs.String("csr", "", "write a certificate signing request (PEM) here")
		uri := fs.String("uri", "", "spiffe://<domain>/cluster/<id>/node/<name> for the CSR")
		ips := fs.String("ip", "", "comma separated IP SANs for the CSR")
		dns := fs.String("dns", "", "comma separated DNS SANs for the CSR")
		fs.Parse(args[1:])
		if *out == "" || *csrFile == "" || *uri == "" {
			return errors.New("tpm-keygen needs -out, -csr and -uri")
		}
		u, err := url.Parse(*uri)
		if err != nil {
			return err
		}
		dev, err := newTPMDevice(*path)
		if err != nil {
			return err
		}
		defer dev.Close()
		blob, err := dev.create(signingKeyTemplate, nil)
		if err != nil {
			return err
		}
		s, err := dev.signer(blob)
		if err != nil {
			return err
		}
		tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: u.Path}, URIs: []*url.URL{u}, DNSNames: splitList(*dns)}
		for _, ip := range splitList(*ips) {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
		}
		csr, err := x509.CreateCertificateRequest(nil, tmpl, s)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: pemTPMKey, Bytes: blob}), 0o600); err != nil {
			return err
		}
		return os.WriteFile(*csrFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o644)

	case "tpm-seal":
		in := fs.String("in", "", "hex master key to seal (the file should be deleted afterwards)")
		fs.Parse(args[1:])
		if *out == "" || *in == "" {
			return errors.New("tpm-seal needs -in and -out")
		}
		raw, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		key, err := hexKey(string(raw))
		if err != nil {
			return err
		}
		dev, err := newTPMDevice(*path)
		if err != nil {
			return err
		}
		defer dev.Close()
		blob, err := dev.seal(key)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: pemTPMSealed, Bytes: blob}), 0o600)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// publicKeysEqual compares the certificate's key with the TPM key.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok1 := a.(*ecdsa.PublicKey)
	eb, ok2 := b.(*ecdsa.PublicKey)
	return ok1 && ok2 && ea.Equal(eb)
}
