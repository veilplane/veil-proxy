// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// Subcommands that set up a node. veilctl calls them, so that every
// cryptographic operation and every TPM access stays in this (Go) program:
//
//	keygen       device key (in the TPM) and a certificate signing request
//	seal         new or given master key, sealed by the TPM
//	sign         sign a request to the backend with the device key
//	key-send     hand the master key to a new node of the same cluster (one time)
//	key-receive  fetch the master key from an existing node and seal it
//
// "-tpm none" uses plain files instead of a TPM (development and tests only).

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

// setupCommands lists the subcommands; tpm-keygen and tpm-seal are the old names.
var setupCommands = map[string]bool{"keygen": true, "seal": true, "sign": true, "key-send": true,
	"key-receive": true, "tpm-keygen": true, "tpm-seal": true}

const noTPM = "none"

func setupCommand(args []string) error {
	cmd := args[0]
	switch cmd {
	case "tpm-keygen":
		cmd = "keygen"
	case "tpm-seal":
		cmd = "seal"
	}
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	tpmPath := fs.String("tpm", "/dev/tpmrm0", `TPM device, or "none" for plain files (development only)`)
	switch cmd {
	case "keygen":
		out := fs.String("out", "", "device key: TPM blob, or PEM private key with -tpm none")
		csrFile := fs.String("csr", "", "write a certificate signing request (PEM) here")
		uri := fs.String("uri", "", "optional spiffe:// URI SAN for the CSR (the backend sets its own)")
		ips := fs.String("ip", "", "comma separated IP SANs for the CSR")
		dns := fs.String("dns", "", "comma separated DNS SANs for the CSR")
		fs.Parse(args[1:])
		if *out == "" || *csrFile == "" {
			return errors.New("keygen needs -out and -csr")
		}
		return keygen(*tpmPath, *out, *csrFile, *uri, splitList(*ips), splitList(*dns))
	case "seal":
		out := fs.String("out", "", "sealed master key (hex with -tpm none)")
		in := fs.String("in", "", "hex master key to seal (the file should be deleted afterwards)")
		newKey := fs.Bool("new", false, "seal a new random master key instead of -in")
		fs.Parse(args[1:])
		if *out == "" || (*in == "") == !*newKey {
			return errors.New("seal needs -out and either -in or -new")
		}
		var key []byte
		if *newKey {
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return err
			}
		} else {
			raw, err := os.ReadFile(*in)
			if err != nil {
				return err
			}
			if key, err = hexKey(string(raw)); err != nil {
				return err
			}
		}
		o := &tpmOpener{path: *tpmPath}
		defer o.close()
		return sealTo(o, *out, key)
	case "sign":
		keyFile := fs.String("key", "", "device key (TPM blob or PEM)")
		in := fs.String("in", "-", "data to sign, - for stdin")
		fs.Parse(args[1:])
		if *keyFile == "" {
			return errors.New("sign needs -key")
		}
		data, err := readInput(*in)
		if err != nil {
			return err
		}
		sig, err := signWith(*tpmPath, *keyFile, data)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
		return nil
	case "key-send", "key-receive":
		var t transferFlags
		fs.StringVar(&t.cert, "cert", "", "device certificate (PEM)")
		fs.StringVar(&t.key, "key", "", "device key (TPM blob or PEM)")
		fs.StringVar(&t.peerCA, "peer-ca", "", "CA that signs device certificates")
		fs.StringVar(&t.secretFile, "secret-file", "", "file with the invite secret (base64url, from the invite code)")
		fs.StringVar(&t.masterFile, "key-file", "", "master key: sealed or hex (key-send reads it, key-receive writes it)")
		listen := fs.String("listen", ":2391", "key-send: address to wait on")
		timeout := fs.Duration("timeout", time.Hour, "key-send: give up after this time")
		from := fs.String("from", "", "key-receive: address of the inviting node (host:port)")
		fs.Parse(args[1:])
		t.tpm = &tpmOpener{path: *tpmPath}
		defer t.tpm.close()
		if t.cert == "" || t.key == "" || t.peerCA == "" || t.secretFile == "" || t.masterFile == "" {
			return errors.New(cmd + " needs -cert, -key, -peer-ca, -secret-file and -key-file")
		}
		if cmd == "key-send" {
			return keySend(t, *listen, *timeout)
		}
		if *from == "" {
			return errors.New("key-receive needs -from")
		}
		return keyReceive(t, *from)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func readInput(name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(name)
}

// keygen creates the device key and a CSR for it. The CSR proves possession of the key; the
// backend puts the identity (spiffe:// URI) into the certificate itself.
func keygen(tpmPath, out, csrFile, uri string, ips, dns []string) error {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "veil-proxy device"}, DNSNames: dns}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			return err
		}
		tmpl.URIs, tmpl.Subject.CommonName = []*url.URL{u}, u.Path
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	var signer crypto.Signer
	var keyPEM []byte
	if tpmPath == noTPM {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		signer, keyPEM = k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	} else {
		dev, err := newTPMDevice(tpmPath)
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
		signer, keyPEM = s, pem.EncodeToMemory(&pem.Block{Type: pemTPMKey, Bytes: blob})
	}
	csr, err := x509.CreateCertificateRequest(nil, tmpl, signer)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(out, keyPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(csrFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o644)
}

// sealTo writes the master key sealed by the TPM, or as hex with -tpm none.
func sealTo(tpm *tpmOpener, out string, key []byte) error {
	if tpm.path == noTPM {
		return writeFileAtomic(out, []byte(hex.EncodeToString(key)+"\n"), 0o600)
	}
	dev, err := tpm.get()
	if err != nil {
		return err
	}
	blob, err := dev.seal(key)
	if err != nil {
		return err
	}
	return writeFileAtomic(out, pem.EncodeToMemory(&pem.Block{Type: pemTPMSealed, Bytes: blob}), 0o600)
}

// signWith signs SHA-256(data) with the device key: ECDSA, ASN.1 DER.
func signWith(tpmPath, keyFile string, data []byte) ([]byte, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", keyFile)
	}
	digest := sha256.Sum256(data)
	if block.Type == pemTPMKey {
		if tpmPath == noTPM {
			return nil, errors.New("TPM key given but -tpm none")
		}
		dev, err := newTPMDevice(tpmPath)
		if err != nil {
			return nil, err
		}
		defer dev.Close()
		s, err := dev.signer(block.Bytes)
		if err != nil {
			return nil, err
		}
		defer dev.flush(s.h)
		return s.Sign(nil, digest[:], crypto.SHA256)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if k, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("%s: %v", keyFile, err)
		}
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", keyFile)
	}
	return s.Sign(rand.Reader, digest[:], crypto.SHA256)
}

func writeFileAtomic(name string, data []byte, perm os.FileMode) error {
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// ---------------------------------------------------------------- master key transfer
//
// A new node gets the master key directly from an existing node, never through the backend.
// "veilctl invite" on the existing node creates a random secret and puts it into the invite
// code next to the backend's join token; the backend never sees the secret.
//
// Both sides authenticate with their device certificates (same cluster). That alone is not
// enough, because the hoster runs the device CA and could issue itself a certificate. So the
// request carries an HMAC and the answer is encrypted, both with keys derived from the secret,
// and both are bound to the requester's certificate:
//
//	request:  {"node": n, "nonce": r, "mac": HMAC(auth key, "veil key request" | r | n | fp)}
//	response: {"nonce": g, "box": AES-GCM(enc key, g, master key, aad = "veil key transfer" | r | fp)}
//
// fp is the SHA-256 of the requester's certificate as seen in the TLS handshake. The sender
// serves exactly one successful transfer, then exits.

type transferFlags struct {
	cert, key, peerCA, secretFile, masterFile string
	tpm                                       *tpmOpener
}

type transferRequest struct {
	Node  string `json:"node"`
	Nonce []byte `json:"nonce"`
	MAC   []byte `json:"mac"`
}

type transferResponse struct {
	Nonce []byte `json:"nonce"`
	Box   []byte `json:"box"`
}

const transferPath = "/veil/key-transfer"

func transferKeys(secret []byte) (auth, enc []byte, err error) {
	if len(secret) < 16 {
		return nil, nil, errors.New("invite secret too short")
	}
	if auth, err = hkdf.Key(sha256.New, secret, nil, "veil key transfer v1 auth", 32); err != nil {
		return nil, nil, err
	}
	enc, err = hkdf.Key(sha256.New, secret, nil, "veil key transfer v1 enc", 32)
	return auth, enc, err
}

func requestMAC(auth []byte, nonce []byte, node string, fp [32]byte) []byte {
	m := hmac.New(sha256.New, auth)
	m.Write([]byte("veil key request\x00"))
	m.Write(nonce)
	m.Write([]byte(node + "\x00"))
	m.Write(fp[:])
	return m.Sum(nil)
}

func transferAAD(nonce []byte, fp [32]byte) []byte {
	return append(append([]byte("veil key transfer\x00"), nonce...), fp[:]...)
}

func readSecret(file string) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(string(bytes.TrimSpace(raw)))
}

// transferTLS returns the device certificate source, the identity and the TLS config parts
// that make sure the other side is a device of the same cluster. Device certificates carry
// no host names, so the chain is verified against the device CA and the identity is the
// spiffe:// URI, not the address.
func transferTLS(t transferFlags) (*certSource, identity, func(tls.ConnectionState) error, error) {
	src := &certSource{certFile: t.cert, keyFile: t.key, tpm: t.tpm}
	cert, err := src.get()
	if err != nil {
		return nil, identity{}, nil, fmt.Errorf("device certificate: %v", err)
	}
	id, err := identityOf(cert.Leaf)
	if err != nil {
		return nil, identity{}, nil, err
	}
	pool, err := loadPool(t.peerCA)
	if err != nil {
		return nil, identity{}, nil, err
	}
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no certificate")
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return err
		}
		pid, err := identityOf(cs.PeerCertificates[0])
		if err != nil {
			return err
		}
		if pid.domain != id.domain || pid.cluster != id.cluster {
			return fmt.Errorf("device of cluster %q, not %q", pid.cluster, id.cluster)
		}
		return nil
	}
	return src, id, verify, nil
}

func keySend(t transferFlags, listen string, timeout time.Duration) error {
	secret, err := readSecret(t.secretFile)
	if err != nil {
		return err
	}
	auth, enc, err := transferKeys(secret)
	if err != nil {
		return err
	}
	master, err := loadMasterKey(t.masterFile, t.tpm)
	if err != nil {
		return err
	}
	src, _, verify, err := transferTLS(t)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	done := make(chan string, 1)
	var failures atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc(transferPath, func(w http.ResponseWriter, r *http.Request) {
		var req transferRequest
		if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) != nil || len(req.Nonce) != 16 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fp := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		pid, _ := identityOf(r.TLS.PeerCertificates[0])
		if req.Node != pid.node || !hmac.Equal(req.MAC, requestMAC(auth, req.Nonce, req.Node, fp)) {
			fmt.Fprintf(os.Stderr, "refused a request from node %q: wrong invite secret\n", pid.node)
			http.Error(w, "wrong invite secret", http.StatusForbidden)
			if failures.Add(1) >= 5 {
				select { // somebody is guessing: stop
				case done <- "":
				default:
				}
			}
			return
		}
		block, _ := aes.NewCipher(enc)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		resp := transferResponse{Nonce: nonce, Box: gcm.Seal(nil, nonce, master, transferAAD(req.Nonce, fp))}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		select {
		case done <- req.Node:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{
		MinVersion:       tls.VersionTLS13,
		ClientAuth:       tls.RequireAnyClientCert, // verified in VerifyConnection, against the device CA
		GetCertificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return src.get() },
		VerifyConnection: verify,
	}}
	go srv.ServeTLS(ln, "", "")
	fmt.Fprintf(os.Stderr, "waiting for the new node on %s (at most %v)\n", ln.Addr(), timeout)
	var node string
	select {
	case node = <-done:
	case <-time.After(timeout):
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	if node == "" {
		return errors.New("no master key handed over")
	}
	fmt.Println(node)
	return nil
}

func keyReceive(t transferFlags, from string) error {
	secret, err := readSecret(t.secretFile)
	if err != nil {
		return err
	}
	auth, enc, err := transferKeys(secret)
	if err != nil {
		return err
	}
	src, id, verify, err := transferTLS(t)
	if err != nil {
		return err
	}
	cert, err := src.get()
	if err != nil {
		return err
	}
	fp := sha256.Sum256(cert.Certificate[0])
	nonce := make([]byte, 16)
	rand.Read(nonce)
	body, _ := json.Marshal(transferRequest{Node: id.node, Nonce: nonce, MAC: requestMAC(auth, nonce, id.node, fp)})
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:           tls.VersionTLS13,
		InsecureSkipVerify:   true, // no host names in device certificates: verified in VerifyConnection
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return src.get() },
		VerifyConnection:     verify,
	}}}
	resp, err := client.Post("https://"+from+transferPath, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	var tr transferResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&tr); err != nil {
		return err
	}
	block, _ := aes.NewCipher(enc)
	gcm, _ := cipher.NewGCM(block)
	if len(tr.Nonce) != gcm.NonceSize() {
		return errors.New("malformed answer")
	}
	master, err := gcm.Open(nil, tr.Nonce, tr.Box, transferAAD(nonce, fp))
	if err != nil || len(master) != 32 {
		return errors.New("the answer is not encrypted with the invite secret (wrong code, or not the inviting node)")
	}
	return sealTo(t.tpm, t.masterFile, master)
}
