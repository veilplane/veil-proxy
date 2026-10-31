// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

//go:build tpmsim

package main

// Run with: go test -tags tpmsim -run TPM -v
// (E2E_ETCD_DIR=... additionally runs mTLS with a TPM key against etcd)

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
)

func simTPM(t *testing.T, seed string) *tpmOpener {
	t.Helper()
	o := &tpmOpener{path: "simulator:" + seed}
	if _, err := o.get(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.close() })
	return o
}

// issueFor signs a device certificate for a public key (the TPM's).
func (ca *testCA) issueFor(t *testing.T, file string, pub crypto.PublicKey, uri string) {
	t.Helper()
	u, _ := url.Parse(uri)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: uri},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, file, "CERTIFICATE", der)
}

func TestTPMSealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	o := simTPM(t, "1")
	dev, _ := o.get()
	secret := bytes.Repeat([]byte{0x42}, 32)
	blob, err := dev.seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, secret) {
		t.Fatal("sealed blob contains the secret in plain text")
	}
	file := filepath.Join(dir, "master.sealed")
	writePEM(t, file, pemTPMSealed, blob)
	got, err := loadMasterKey(file, o)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("unseal: %x %v", got, err)
	}
	tampered := append([]byte{}, blob...)
	tampered[len(tampered)-5] ^= 1
	if _, err := dev.unseal(tampered); err == nil {
		t.Fatal("tampered blob was unsealed")
	}
	o.close()

	// The same blob on another machine (another TPM seed) is useless.
	other := simTPM(t, "2")
	if _, err := loadMasterKey(file, other); err == nil {
		t.Fatal("blob unsealed on a different TPM")
	}
	t.Log("sealed master key is bound to its TPM")
}

func TestTPMSignerTLS(t *testing.T) {
	dir := t.TempDir()
	o := simTPM(t, "3")
	dev, _ := o.get()
	blob, err := dev.create(signingKeyTemplate, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, certFile := filepath.Join(dir, "node.tpmkey"), filepath.Join(dir, "node.pem")
	writePEM(t, keyFile, pemTPMKey, blob)
	s, err := dev.signer(blob)
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, dir, "device-ca")
	ca.issueFor(t, certFile, s.Public(), "spiffe://veilplane.example/cluster/c1/node/tpm")
	dev.flush(s.h)

	src := &certSource{certFile: certFile, keyFile: keyFile, tpm: o}
	kp, err := src.get()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kp.PrivateKey.(*tpmSigner); !ok {
		t.Fatal("private key is not TPM-backed")
	}
	// A certificate for a different key must be rejected.
	cf2, _ := ca.issue(t, dir, "other", "spiffe://veilplane.example/cluster/c1/node/other")
	if _, err := (&certSource{certFile: cf2, keyFile: keyFile, tpm: o}).get(); err == nil {
		t.Fatal("certificate of another key accepted for the TPM key")
	}
	// The key never appears in the blob in a usable form: the blob is the
	// TPM's encrypted private area, only this TPM can load it.
	b, _ := os.ReadFile(keyFile)
	if block, _ := pem.Decode(b); block == nil || block.Type != pemTPMKey {
		t.Fatal("unexpected key file format")
	}
}

// Full mTLS against etcd (client-cert-auth) with the device key in the TPM
// and the master key sealed by the TPM.
func TestAttackMTLSWithTPM(t *testing.T) {
	etcdDir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	serverCA, deviceCA := newTestCA(t, dir, "server-ca"), newTestCA(t, dir, "device-ca")
	sc, sk := serverCA.issue(t, dir, "etcd", "")
	addr := startEtcdTLS(t, etcdDir, 23860, sc, sk, deviceCA.file)

	o := simTPM(t, "4")
	dev, _ := o.get()
	blob, _ := dev.create(signingKeyTemplate, nil)
	s, _ := dev.signer(blob)
	keyFile, certFile, sealedFile := filepath.Join(dir, "n.tpmkey"), filepath.Join(dir, "n.pem"), filepath.Join(dir, "m.sealed")
	writePEM(t, keyFile, pemTPMKey, blob)
	deviceCA.issueFor(t, certFile, s.Public(), "spiffe://veilplane.example/cluster/c1/node/tpm-node")
	dev.flush(s.h)
	sealed, _ := dev.seal(bytes.Repeat([]byte{7}, 32))
	writePEM(t, sealedFile, pemTPMSealed, sealed)

	master, err := loadMasterKey(sealedFile, o)
	if err != nil {
		t.Fatal(err)
	}
	p, err := start(ctx, config{listen: "127.0.0.1:0", upstream: addr, stateFile: filepath.Join(dir, "state"),
		master: master, history: 10 * time.Minute, certFile: certFile, keyFile: keyFile, backendCA: serverCA.file, tpm: o})
	if err != nil {
		t.Fatal(err)
	}
	kv := dial(t, p.addr)
	if _, err := kv.Put(ctx, &pb.PutRequest{Key: []byte("/registry/x/y"), Value: []byte("signed by the TPM")}); err != nil {
		t.Fatal(err)
	}
	resp, err := kv.Range(ctx, &pb.RangeRequest{Key: []byte("/registry/x/y")})
	if err != nil || string(resp.Kvs[0].Value) != "signed by the TPM" {
		t.Fatalf("%v %v", resp, err)
	}
	t.Log("mTLS handshake signed inside the TPM, master key unsealed from the TPM")
}
