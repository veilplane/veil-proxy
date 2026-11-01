// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// Subcommands that set up a node. veilctl calls them, so that every
// cryptographic operation stays in this (Go) program:
//
//	keygen       device key and a certificate signing request
//	sign         sign a request to the backend with the device key
//	invite-seal  encrypt the master key for an invite file
//	invite-open  decrypt the master key of an invite file
//
// All secrets are plain files with mode 0600: the device key as a PEM private key, the
// master key as 64 hex characters.

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
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
	"log"
	"net"
	"net/url"
	"os"
	"strings"
)

var setupCommands = map[string]bool{"keygen": true, "sign": true, "invite-seal": true, "invite-open": true}

func setupCommand(args []string) error {
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	switch args[0] {
	case "keygen":
		out := fs.String("out", "", "device key (PEM private key)")
		csrFile := fs.String("csr", "", "write a certificate signing request (PEM) here")
		uri := fs.String("uri", "", "optional spiffe:// URI SAN for the CSR (the backend sets its own)")
		ips := fs.String("ip", "", "comma separated IP SANs for the CSR")
		dns := fs.String("dns", "", "comma separated DNS SANs for the CSR")
		fs.Parse(args[1:])
		if *out == "" || *csrFile == "" {
			return errors.New("keygen needs -out and -csr")
		}
		return keygen(*out, *csrFile, *uri, splitList(*ips), splitList(*dns))
	case "sign":
		keyFile := fs.String("key", "", "device key (PEM)")
		in := fs.String("in", "-", "data to sign, - for stdin")
		fs.Parse(args[1:])
		if *keyFile == "" {
			return errors.New("sign needs -key")
		}
		data, err := readInput(*in)
		if err != nil {
			return err
		}
		sig, err := signWith(*keyFile, data)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
		return nil
	case "invite-seal":
		keyFile := fs.String("key-file", "", "master key file")
		fs.Parse(args[1:])
		if *keyFile == "" {
			return errors.New("invite-seal needs -key-file")
		}
		master, err := loadMasterKey(*keyFile)
		if err != nil {
			return err
		}
		sec, err := inviteSeal(master)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(sec)
	case "invite-open":
		out := fs.String("out", "", "where to write the master key (hex, mode 0600)")
		fs.Parse(args[1:])
		if *out == "" {
			return errors.New("invite-open needs -out")
		}
		var sec inviteSecrets
		if err := json.NewDecoder(io.LimitReader(os.Stdin, 8192)).Decode(&sec); err != nil {
			return fmt.Errorf("invite-open reads {fileSecret, serverSecret, box} as JSON on stdin: %v", err)
		}
		master, err := inviteOpen(sec)
		if err != nil {
			return err
		}
		return writeFileAtomic(*out, []byte(hex.EncodeToString(master)+"\n"), 0o600)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func readInput(name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(name)
}

// keygen creates the device key (ECDSA P-256) and a CSR for it. The CSR proves possession of
// the key; the backend puts the identity (spiffe:// URI) into the certificate itself.
func keygen(out, csrFile, uri string, ips, dns []string) error {
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
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(csrFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o644)
}

// signWith signs SHA-256(data) with the device key: ECDSA, ASN.1 DER.
func signWith(keyFile string, data []byte) ([]byte, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", keyFile)
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
	digest := sha256.Sum256(data)
	return s.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// loadMasterKey reads the master key: 64 hex characters. A file that others can read is
// reported, because the master key opens every value of the cluster.
func loadMasterKey(file string) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err := hexKey(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", file, err)
	}
	if st, err := os.Stat(file); err == nil && st.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: master key file %s has mode %v; it should be 0600", file, st.Mode().Perm())
	}
	return key, nil
}

func hexKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(key) != 32 {
		return nil, errors.New("must contain exactly 64 hex characters")
	}
	return key, nil
}

func writeFileAtomic(name string, data []byte, perm os.FileMode) error {
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// ---------------------------------------------------------------- invites
//
// A new node gets the master key from an invite file that an existing node writes
// ("veilctl invite"). The file holds the master key encrypted with a key made of two random
// halves: one is in the file, the other one goes to the backend with the invite token, which
// hands it out exactly once, to the node that redeems the token, and then deletes it.
//
//	key = HKDF-SHA256(file secret | server secret, "veil invite v1")
//	box = nonce | AES-256-GCM(key, nonce, master key, aad = "veil invite v1")
//
// The backend alone has one half and no box; the file alone is useless once the token was
// redeemed (or expired). Until then the file must be handled like a password. Neither node
// needs to accept connections: both only talk to the backend.

type inviteSecrets struct {
	FileSecret   string `json:"fileSecret"`    // base64url, in the invite file
	ServerSecret string `json:"serverSecret"`  // base64url, held by the backend until redeemed
	Box          string `json:"box,omitempty"` // base64url, in the invite file
}

const inviteInfo = "veil invite v1"

func inviteKey(fileSecret, serverSecret []byte) (cipher.AEAD, error) {
	if len(fileSecret) != 32 || len(serverSecret) != 32 {
		return nil, errors.New("invite secrets must be 32 bytes each")
	}
	k, err := hkdf.Key(sha256.New, append(append([]byte(nil), fileSecret...), serverSecret...), nil, inviteInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// inviteSeal encrypts the master key for an invite file.
func inviteSeal(master []byte) (inviteSecrets, error) {
	fileSecret, serverSecret := make([]byte, 32), make([]byte, 32)
	rand.Read(fileSecret)
	rand.Read(serverSecret)
	gcm, err := inviteKey(fileSecret, serverSecret)
	if err != nil {
		return inviteSecrets{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	box := gcm.Seal(nonce, nonce, master, []byte(inviteInfo))
	enc := base64.RawURLEncoding.EncodeToString
	return inviteSecrets{FileSecret: enc(fileSecret), ServerSecret: enc(serverSecret), Box: enc(box)}, nil
}

// inviteOpen decrypts the master key of an invite file.
func inviteOpen(s inviteSecrets) ([]byte, error) {
	dec := base64.RawURLEncoding.DecodeString
	fileSecret, err1 := dec(s.FileSecret)
	serverSecret, err2 := dec(s.ServerSecret)
	box, err3 := dec(s.Box)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("malformed invite: %v", err)
	}
	gcm, err := inviteKey(fileSecret, serverSecret)
	if err != nil {
		return nil, err
	}
	if len(box) < gcm.NonceSize() {
		return nil, errors.New("malformed invite")
	}
	master, err := gcm.Open(nil, box[:gcm.NonceSize()], box[gcm.NonceSize():], []byte(inviteInfo))
	if err != nil || len(master) != 32 {
		return nil, errors.New("the invite does not decrypt (damaged file, or not the backend's half for it)")
	}
	return master, nil
}
