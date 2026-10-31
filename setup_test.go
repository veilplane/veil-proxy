// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeygenAndSignWithoutTPM(t *testing.T) {
	dir := t.TempDir()
	key, csrFile := filepath.Join(dir, "node.key"), filepath.Join(dir, "node.csr")
	if err := keygen(noTPM, key, csrFile, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(csrFile)
	block, _ := pem.Decode(raw)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR: %v", err)
	}
	data := []byte(`{"action":"renew"}`)
	sig, err := signWith(noTPM, key, data)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(csr.PublicKey.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature does not verify with the CSR's key")
	}
	if ecdsa.VerifyASN1(csr.PublicKey.(*ecdsa.PublicKey), digest[:], append(sig[:len(sig)-1], sig[len(sig)-1]^1)) {
		t.Fatal("tampered signature verifies")
	}
}

func TestSealNewWithoutTPM(t *testing.T) {
	file := filepath.Join(t.TempDir(), "master")
	if err := setupCommand([]string{"seal", "-tpm", "none", "-new", "-out", file}); err != nil {
		t.Fatal(err)
	}
	key, err := loadMasterKey(file, &tpmOpener{path: noTPM})
	if err != nil || len(key) != 32 {
		t.Fatalf("%v %d", err, len(key))
	}
	st, _ := os.Stat(file)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("master key file mode %v", st.Mode().Perm())
	}
}

// issueDevice writes a device certificate and key as the backend issues them: spiffe:// URI
// only, no host names or addresses.
func issueDevice(t *testing.T, ca *testCA, dir, name, uri string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	cf, kf := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	writePEM(t, cf, "CERTIFICATE", der)
	writePEM(t, kf, "PRIVATE KEY", kder)
	return cf, kf
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestKeyTransfer(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir, "device-ca")
	other := newTestCA(t, dir, "other-ca")
	device := func(name, uri string, c *testCA) transferFlags {
		cf, kf := issueDevice(t, c, dir, name, uri)
		return transferFlags{cert: cf, key: kf, peerCA: ca.file, tpm: &tpmOpener{path: noTPM},
			secretFile: filepath.Join(dir, name+".secret"), masterFile: filepath.Join(dir, name+".master")}
	}
	writeSecret := func(f transferFlags, secret []byte) {
		os.WriteFile(f.secretFile, []byte(base64.RawURLEncoding.EncodeToString(secret)+"\n"), 0o600)
	}
	secret := bytes.Repeat([]byte{9}, 32)
	a := device("a", "spiffe://veilplane.com/cluster/c1/node/a", ca)
	writeSecret(a, secret)
	if err := sealTo(&tpmOpener{path: noTPM}, a.masterFile, bytes.Repeat([]byte{0x5a}, 32)); err != nil {
		t.Fatal(err)
	}

	addr := freeAddr(t)
	sent := make(chan error, 1)
	go func() { sent <- keySend(a, addr, 20*time.Second) }()
	time.Sleep(200 * time.Millisecond)

	// wrong secret: refused, the sender keeps waiting
	guess := device("guess", "spiffe://veilplane.com/cluster/c1/node/guess", ca)
	writeSecret(guess, bytes.Repeat([]byte{8}, 32))
	if err := keyReceive(guess, addr); err == nil || !strings.Contains(err.Error(), "wrong invite secret") {
		t.Fatalf("wrong secret: %v", err)
	}
	// right secret, but a device of another cluster: refused by TLS
	foreign := device("foreign", "spiffe://veilplane.com/cluster/c2/node/x", ca)
	writeSecret(foreign, secret)
	if err := keyReceive(foreign, addr); err == nil {
		t.Fatal("device of another cluster got the key")
	}
	// right secret, but a certificate from another CA (not a device of this platform)
	stranger := device("stranger", "spiffe://veilplane.com/cluster/c1/node/s", other)
	writeSecret(stranger, secret)
	if err := keyReceive(stranger, addr); err == nil {
		t.Fatal("certificate of another CA got the key")
	}
	if _, err := os.Stat(guess.masterFile); err == nil {
		t.Fatal("a refused node wrote a master key")
	}

	b := device("b", "spiffe://veilplane.com/cluster/c1/node/b", ca)
	writeSecret(b, secret)
	if err := keyReceive(b, addr); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("sender: %v", err)
	}
	ka, _ := loadMasterKey(a.masterFile, a.tpm)
	kb, err := loadMasterKey(b.masterFile, b.tpm)
	if err != nil || !bytes.Equal(ka, kb) {
		t.Fatalf("master keys differ: %v", err)
	}
	// one transfer only: the sender is gone
	if err := keyReceive(b, addr); err == nil {
		t.Fatal("second transfer succeeded")
	}
}

func TestKeySendStopsAfterGuesses(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir, "device-ca")
	cf, kf := issueDevice(t, ca, dir, "a", "spiffe://veilplane.com/cluster/c1/node/a")
	a := transferFlags{cert: cf, key: kf, peerCA: ca.file, tpm: &tpmOpener{path: noTPM},
		secretFile: filepath.Join(dir, "a.secret"), masterFile: filepath.Join(dir, "a.master")}
	os.WriteFile(a.secretFile, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))), 0o600)
	sealTo(&tpmOpener{path: noTPM}, a.masterFile, bytes.Repeat([]byte{2}, 32))
	cf2, kf2 := issueDevice(t, ca, dir, "g", "spiffe://veilplane.com/cluster/c1/node/g")
	g := transferFlags{cert: cf2, key: kf2, peerCA: ca.file, tpm: &tpmOpener{path: noTPM},
		secretFile: filepath.Join(dir, "g.secret"), masterFile: filepath.Join(dir, "g.master")}
	os.WriteFile(g.secretFile, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))), 0o600)
	addr := freeAddr(t)
	sent := make(chan error, 1)
	go func() { sent <- keySend(a, addr, 20*time.Second) }()
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 5; i++ {
		keyReceive(g, addr)
	}
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("sender reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sender still waiting after 5 wrong secrets")
	}
}

func TestPeersFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "peers")
	f := &freshness{peers: []string{"10.0.0.1:2390"}, peersFile: file}
	if got := f.peerList(); len(got) != 1 {
		t.Fatalf("missing file: %v", got)
	}
	os.WriteFile(file, []byte("10.0.0.2:2390\n10.0.0.1:2390\n\n"), 0o644)
	if got := f.peerList(); strings.Join(got, ",") != "10.0.0.1:2390,10.0.0.2:2390" {
		t.Fatalf("got %v", got)
	}
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(file, []byte("10.0.0.3:2390"), 0o644)
	os.Chtimes(file, time.Now(), time.Now().Add(time.Second))
	if got := f.peerList(); strings.Join(got, ",") != "10.0.0.1:2390,10.0.0.3:2390" {
		t.Fatalf("after change: %v", got)
	}
}
