// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenAndSign(t *testing.T) {
	dir := t.TempDir()
	key, csrFile := filepath.Join(dir, "node.key"), filepath.Join(dir, "node.csr")
	if err := keygen(key, csrFile, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(csrFile)
	block, _ := pem.Decode(raw)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR: %v", err)
	}
	data := []byte(`{"action":"renew"}`)
	sig, err := signWith(key, data)
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

func TestKeyFileModes(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "node.key")
	if err := keygen(key, filepath.Join(dir, "node.csr"), "", nil, nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Errorf("device key mode %v", st.Mode().Perm())
	}
	master := filepath.Join(dir, "master.key")
	os.WriteFile(master, []byte("zz"+strings.Repeat("ab", 31)), 0o600)
	if _, err := loadMasterKey(master); err == nil {
		t.Error("non-hex master key accepted")
	}
	os.WriteFile(master, []byte(strings.Repeat("ab", 31)), 0o600)
	if _, err := loadMasterKey(master); err == nil {
		t.Error("short master key accepted")
	}
}

func TestInviteRoundTrip(t *testing.T) {
	master := bytes.Repeat([]byte{0x5a}, 32)
	sec, err := inviteSeal(master)
	if err != nil {
		t.Fatal(err)
	}
	got, err := inviteOpen(sec)
	if err != nil || !bytes.Equal(got, master) {
		t.Fatalf("round trip: %v", err)
	}
	// each half alone is useless
	other, _ := inviteSeal(master)
	for name, s := range map[string]inviteSecrets{
		"other server half": {FileSecret: sec.FileSecret, ServerSecret: other.ServerSecret, Box: sec.Box},
		"other file half":   {FileSecret: other.FileSecret, ServerSecret: sec.ServerSecret, Box: sec.Box},
		"other box":         {FileSecret: sec.FileSecret, ServerSecret: sec.ServerSecret, Box: other.Box},
		"no server half":    {FileSecret: sec.FileSecret, Box: sec.Box},
		"truncated box":     {FileSecret: sec.FileSecret, ServerSecret: sec.ServerSecret, Box: sec.Box[:10]},
	} {
		if _, err := inviteOpen(s); err == nil {
			t.Errorf("%s: decrypted", name)
		}
	}
	if sec.FileSecret == other.FileSecret || sec.ServerSecret == other.ServerSecret {
		t.Error("secrets repeat")
	}
}

// The subcommands as veilctl uses them: invite-seal prints JSON, invite-open reads it on
// stdin and writes the master key for the new node.
func TestInviteCommands(t *testing.T) {
	dir := t.TempDir()
	master := filepath.Join(dir, "master.key")
	os.WriteFile(master, []byte(strings.Repeat("5a", 32)+"\n"), 0o600)
	out := captureStdout(t, func() error {
		return setupCommand([]string{"invite-seal", "-key-file", master})
	})
	received := filepath.Join(dir, "received.key")
	withStdin(t, out, func() {
		if err := setupCommand([]string{"invite-open", "-out", received}); err != nil {
			t.Fatal(err)
		}
	})
	a, _ := loadMasterKey(master)
	b, err := loadMasterKey(received)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("received key differs: %v", err)
	}
	if st, _ := os.Stat(received); st.Mode().Perm() != 0o600 {
		t.Errorf("received master key mode %v", st.Mode().Perm())
	}
}

func captureStdout(t *testing.T, f func() error) []byte {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := f()
	os.Stdout = old
	w.Close()
	out, _ := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func withStdin(t *testing.T, data []byte, f func()) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "stdin")
	os.WriteFile(file, data, 0o600)
	in, _ := os.Open(file)
	defer in.Close()
	old := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = old }()
	f()
}
