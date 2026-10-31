// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// veil-proxy (Veilplane): an end-to-end encrypting, verifying etcd v3 gRPC proxy.
//
// It runs on the customer's side next to kube-apiserver. The API server talks
// plain etcd v3 gRPC to this proxy. The proxy encrypts every key and value
// before it reaches the hosted, untrusted etcd-compatible backend, and it
// verifies everything the backend says before believing it.
//
// Confidentiality
//   - Keys: every path segment is padded and encrypted deterministically with
//     AES-256-SIV (RFC 5297, Google Tink), bound to its plaintext parent path.
//     Segment boundaries survive, so prefix scans work on the backend, and all
//     instances sharing the master key produce identical ciphertext keys.
//   - Values: padded, then AES-256-GCM with a random nonce; the plaintext key
//     is bound as additional data.
//   - Lengths: Padmé padding, min 32 bytes per segment and 128 per value.
//
// Integrity and freshness (see replica.go)
//   - Every value names its predecessor revision; deletes carry a receipt.
//   - Each instance is a verified replica of the whole key space: it applies
//     the backend's change stream only after checking every change, and answers
//     reads and watches from that replica.
//   - A keyed digest of the full state is checkpointed to disk and compared
//     between instances, which catches rollbacks and forks (different
//     histories shown to different instances).
//
// PROTOTYPE, not audited.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/bits"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------- main

type config struct {
	listen, upstream      string
	stateFile             string
	peerListen            string
	peers                 []string
	peersFile             string
	master                []byte
	delay, history        time.Duration
	verbose, trustBackend bool

	// mTLS: the device certificate identifies this instance to the backend
	// and to its peers (see identityOf).
	certFile, keyFile string
	backendCA         string // CA that signed the backend's server certificate
	backendName       string // expected server name, default: host of -upstream
	peerCA            string // CA that signs device certificates

	tpm       *tpmOpener // used when -key or -key-file hold TPM blobs
	opsListen string     // /healthz, /readyz, /metrics
}

// version is set at build time: -ldflags "-X main.buildVersion=v1.2.3"
var buildVersion = "dev"

func main() {
	if len(os.Args) > 1 && setupCommands[os.Args[1]] {
		if err := setupCommand(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	var cfg config
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:2389", "address kube-apiserver connects to")
	flag.StringVar(&cfg.upstream, "upstream", "127.0.0.1:2379", "hosted etcd-compatible backend: host:port (all addresses of the name are used), or a comma separated list of host:port")
	flag.StringVar(&cfg.stateFile, "state-file", "veil.state", "where verified checkpoints are persisted")
	flag.StringVar(&cfg.peerListen, "peer-listen", "", "address to serve signed checkpoints to the other instances, e.g. 0.0.0.0:2390")
	flag.DurationVar(&cfg.delay, "delay", 0, "simulated round trip time to the backend, e.g. 30ms")
	flag.DurationVar(&cfg.history, "history", 10*time.Minute, "how much verified history to keep (must exceed the API server's compaction interval)")
	flag.BoolVar(&cfg.verbose, "v", false, "log every request with its plaintext key")
	flag.BoolVar(&cfg.trustBackend, "trust-backend", false, "accept the backend state without verification (only to recover after all checkpoints were lost)")
	flag.StringVar(&cfg.certFile, "cert", "", "device certificate (PEM) with a spiffe://<domain>/cluster/<id>/node/<name> URI SAN")
	flag.StringVar(&cfg.keyFile, "key", "", "private key of the device certificate (PEM)")
	flag.StringVar(&cfg.backendCA, "backend-ca", "", "CA bundle (PEM) that signed the backend's server certificate")
	flag.StringVar(&cfg.backendName, "backend-name", "", "server name expected in the backend certificate (default: host of -upstream)")
	flag.StringVar(&cfg.peerCA, "peer-ca", "", "CA bundle (PEM) that signs device certificates, used to authenticate peers")
	flag.StringVar(&cfg.opsListen, "ops-listen", "127.0.0.1:9390", "address for /healthz, /readyz and /metrics (empty: off)")
	keyFile := flag.String("key-file", "master.key", "master key: TPM-sealed (VEIL TPM SEALED) or 64 hex chars (development)")
	tpmPath := flag.String("tpm", "/dev/tpmrm0", "TPM device, used when -key or -key-file are TPM blobs")
	genKey := flag.Bool("gen-key", false, "print a new random master key and exit")
	peers := flag.String("peers", "", "comma separated peer-listen addresses of the other instances")
	flag.StringVar(&cfg.peersFile, "peers-file", "", "file with more peer addresses (one per line), read again when it changes")
	logFormat := flag.String("log-format", "json", "json or text")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("veil-proxy", buildVersion)
		return
	}
	if *genKey {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(k))
		return
	}
	var h slog.Handler = slog.NewJSONHandler(os.Stderr, nil)
	if *logFormat == "text" {
		h = slog.NewTextHandler(os.Stderr, nil)
	}
	slog.SetDefault(slog.New(h).With("version", buildVersion)) // also routes the log package through slog

	cfg.tpm = &tpmOpener{path: *tpmPath}
	var err error
	if cfg.master, err = loadMasterKey(*keyFile, cfg.tpm); err != nil {
		fatal("master key", err)
	}
	cfg.peers = splitList(*peers)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	p, err := start(ctx, cfg)
	if err != nil {
		fatal("start", err)
	}
	slog.Info("veil-proxy started", "listen", p.addr, "upstream", cfg.upstream, "revision", p.rep.current())
	<-ctx.Done()
	slog.Info("shutting down")
	p.shutdown()
}

func fatal(what string, err error) {
	slog.Error(what, "error", err)
	os.Exit(1)
}

// backendTarget turns -upstream into a gRPC target. Several backend instances can be given as
// one DNS name with several addresses ("backend.veilplane.com:443", resolved again whenever a
// connection fails) or as a list ("10.0.0.1:2379,10.0.0.2:2379"). firstHost is the default
// server name expected in the backend certificate.
func backendTarget(upstream string) (target string, opt grpc.DialOption, firstHost string) {
	addrs := splitList(upstream)
	if len(addrs) == 0 {
		addrs = []string{upstream}
	}
	firstHost = addrs[0]
	if h, _, err := net.SplitHostPort(addrs[0]); err == nil {
		firstHost = h
	}
	if len(addrs) == 1 {
		return "dns:///" + addrs[0], grpc.EmptyDialOption{}, firstHost
	}
	r := manual.NewBuilderWithScheme("veil-backends")
	state := resolver.State{}
	for _, a := range addrs {
		state.Addresses = append(state.Addresses, resolver.Address{Addr: a})
	}
	r.InitialState(state)
	return r.Scheme() + ":///backend", grpc.WithResolvers(r), firstHost
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// start connects to the backend, verifies and loads the replica and serves.
// Everything stops when ctx is canceled.
func start(ctx context.Context, cfg config) (*proxy, error) {
	s, err := newSealer(cfg.master)
	if err != nil {
		return nil, err
	}
	target, resolverOpt, firstHost := backendTarget(cfg.upstream)
	if cfg.backendName == "" {
		cfg.backendName = firstHost
	}
	ts, err := newTLSSetup(cfg)
	if err != nil {
		return nil, err
	}
	creds := insecure.NewCredentials()
	if ts != nil {
		creds = credentials.NewTLS(ts.backend)
		slog.Info("mTLS", "cluster", ts.id.cluster, "node", ts.id.node)
	} else {
		slog.Warn("no -cert given, the backend connection is NOT encrypted (development only)")
	}
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(creds), resolverOpt,
		// spread calls over all backend instances; a failed instance drops out until it is back
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
		// detect dead backend connections (the watch stream is long-lived)
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		// reconnect quickly after a backend restart (gRPC's default backoff grows to 2 minutes,
		// longer than the API server's leader election tolerates)
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{BaseDelay: 250 * time.Millisecond,
			Multiplier: 1.6, Jitter: 0.2, MaxDelay: 3 * time.Second}, MinConnectTimeout: 5 * time.Second}),
		// a snapshot load (Range over the whole key space) can be far larger than the 4 MB default
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxBackendMessage)))
	if err != nil {
		return nil, err
	}
	p := &proxy{
		s:       s,
		kv:      pb.NewKVClient(conn),
		watch:   pb.NewWatchClient(conn),
		lease:   pb.NewLeaseClient(conn),
		maint:   pb.NewMaintenanceClient(conn),
		rep:     newReplica(s, cfg.history),
		delay:   cfg.delay,
		verbose: cfg.verbose,
		metrics: &metrics{},
	}
	p.fresh = newFreshness(s.peerMAC, cfg.stateFile, cfg.peers, p.rep)
	p.fresh.peersFile = cfg.peersFile
	p.closers = append(p.closers, conn.Close)
	if cfg.tpm != nil {
		p.closers = append(p.closers, cfg.tpm.close)
	}
	if cfg.opsListen != "" {
		ln, err := net.Listen("tcp", cfg.opsListen)
		if err != nil {
			return nil, err
		}
		p.opsAddr = ln.Addr().String()
		ops := &http.Server{Handler: opsHandler(p)}
		go ops.Serve(ln)
		p.closers = append(p.closers, ops.Close)
	}
	if ts != nil && ts.peerClient != nil {
		p.fresh.scheme = "https"
		p.fresh.client.Transport = &http.Transport{TLSClientConfig: ts.peerClient}
	} else if ts != nil && (cfg.peerListen != "" || len(cfg.peers) > 0 || cfg.peersFile != "") {
		return nil, errors.New("-peer-ca is required for peers when mTLS is used")
	}

	if cfg.peerListen != "" {
		ln, err := net.Listen("tcp", cfg.peerListen)
		if err != nil {
			return nil, err
		}
		p.peerAddr = ln.Addr().String()
		srv := &http.Server{Handler: peerHandler(p.fresh)}
		if ts != nil {
			srv.TLSConfig = ts.peerServer
			go srv.ServeTLS(ln, "", "")
		} else {
			go srv.Serve(ln)
		}
		p.closers = append(p.closers, srv.Close)
	}
	for {
		err := p.verifyAndLoad(ctx, cfg.trustBackend)
		if err == nil {
			break
		}
		if c := status.Code(err); c != codes.Unavailable && c != codes.DeadlineExceeded {
			p.closeAll()
			return nil, err
		}
		slog.Warn("backend not reachable yet, retrying", "error", status.Convert(err).Message())
		select {
		case <-ctx.Done():
			p.closeAll()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if p.rep.err() == nil {
		go p.rep.follow(ctx, p)
	}
	go p.fresh.loop(ctx)

	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		p.closeAll()
		return nil, err
	}
	p.addr = lis.Addr().String()
	p.self = "http://" + p.addr
	p.srv = grpc.NewServer(grpc.MaxRecvMsgSize(16<<20), grpc.MaxSendMsgSize(maxBackendMessage),
		grpc.UnaryInterceptor(p.metrics.unary), grpc.StreamInterceptor(p.metrics.stream))
	pb.RegisterKVServer(p.srv, p)
	pb.RegisterWatchServer(p.srv, p)
	pb.RegisterLeaseServer(p.srv, p)
	pb.RegisterMaintenanceServer(p.srv, maintenance{p})
	pb.RegisterClusterServer(p.srv, cluster{p})
	go p.srv.Serve(lis)
	p.serving.Store(true)
	go func() { <-ctx.Done(); p.shutdown() }()
	return p, nil
}

// shutdown stops serving (waiting briefly for running requests), persists a
// final checkpoint and releases backend connection and TPM. Safe to call twice.
func (p *proxy) shutdown() {
	p.stopOnce.Do(func() {
		if p.srv != nil {
			done := make(chan struct{})
			go func() { p.srv.GracefulStop(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second): // watches never end on their own
				p.srv.Stop()
			}
		}
		p.fresh.persist()
		p.closeAll()
	})
}

func (p *proxy) closeAll() {
	for i := len(p.closers) - 1; i >= 0; i-- {
		p.closers[i]()
	}
	p.closers = nil
}

// ---------------------------------------------------------------- operations

// metrics counts gRPC requests per method and status code.
type metrics struct {
	mu       sync.Mutex
	requests map[string]*atomic.Int64 // "method code"
	watches  atomic.Int64
}

func (m *metrics) count(method string, err error) {
	k := method + " " + status.Code(err).String()
	m.mu.Lock()
	if m.requests == nil {
		m.requests = map[string]*atomic.Int64{}
	}
	c := m.requests[k]
	if c == nil {
		c = &atomic.Int64{}
		m.requests[k] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

func (m *metrics) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	resp, err := h(ctx, req)
	m.count(info.FullMethod, err)
	return resp, err
}

func (m *metrics) stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if info.FullMethod == "/etcdserverpb.Watch/Watch" {
		m.watches.Add(1)
		defer m.watches.Add(-1)
	}
	err := h(srv, ss)
	m.count(info.FullMethod, err)
	return err
}

// opsHandler serves /healthz (process alive), /readyz (replica verified and
// serving) and /metrics (Prometheus text format). A stopped replica is not
// "unhealthy": restarting would not help, it needs a human. It is "not ready"
// and veil_replica_failed is 1, which is what alerts should fire on.
func opsHandler(p *proxy) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := p.rep.err(); err != nil {
			http.Error(w, "replica stopped: "+status.Convert(err).Message(), http.StatusServiceUnavailable)
			return
		}
		if _, ok := p.rep.checkpoint(); !ok || !p.serving.Load() {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		failed := 0
		if p.rep.err() != nil {
			failed = 1
		}
		p.rep.mu.RLock()
		rev, base, keys := p.rep.rev, p.rep.base, len(p.rep.order)
		p.rep.mu.RUnlock()
		fmt.Fprintf(w, "# TYPE veil_build_info gauge\nveil_build_info{version=%q} 1\n", buildVersion)
		fmt.Fprintf(w, "# TYPE veil_replica_failed gauge\nveil_replica_failed %d\n", failed)
		fmt.Fprintf(w, "# TYPE veil_replica_revision gauge\nveil_replica_revision %d\n", rev)
		fmt.Fprintf(w, "# TYPE veil_replica_base_revision gauge\nveil_replica_base_revision %d\n", base)
		fmt.Fprintf(w, "# TYPE veil_replica_tracked_keys gauge\nveil_replica_tracked_keys %d\n", keys)
		fmt.Fprintf(w, "# TYPE veil_backend_floor_revision gauge\nveil_backend_floor_revision %d\n", p.fresh.floor())
		fmt.Fprintf(w, "# TYPE veil_watch_streams gauge\nveil_watch_streams %d\n", p.metrics.watches.Load())
		p.metrics.mu.Lock()
		keysSorted := make([]string, 0, len(p.metrics.requests))
		for k := range p.metrics.requests {
			keysSorted = append(keysSorted, k)
		}
		sort.Strings(keysSorted)
		fmt.Fprintf(w, "# TYPE veil_grpc_requests_total counter\n")
		for _, k := range keysSorted {
			method, code, _ := strings.Cut(k, " ")
			fmt.Fprintf(w, "veil_grpc_requests_total{method=%q,code=%q} %d\n", method, code, p.metrics.requests[k].Load())
		}
		p.metrics.mu.Unlock()
	})
	return mux
}

// verifyAndLoad loads the replica from a state the backend can prove: the
// newest checkpoint (own, a peer's, or the last compaction anchor) whose
// digest the backend's snapshot at that revision reproduces. Verification
// failures do not stop the process; the replica refuses to serve instead.
func (p *proxy) verifyAndLoad(ctx context.Context, trustBackend bool) error {
	own, anchor, haveFile, err := p.fresh.loadFile()
	if err != nil {
		return err
	}
	peerCps := p.fresh.pull()
	var cands []checkpoint
	for _, c := range append(append(peerCps, own), anchor) {
		if c.rev > 0 {
			cands = append(cands, c)
			p.fresh.observe(c.rev)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].rev > cands[j].rev })
	for _, c := range cands {
		err := p.rep.load(ctx, p.kv, c.rev)
		msg := status.Convert(err).Message()
		switch {
		case err != nil && strings.Contains(msg, "compacted"):
			log.Printf("checkpoint at revision %d is no longer available on the backend, trying older ones", c.rev)
			continue
		case err != nil && strings.Contains(msg, "future revision"):
			p.rep.fail(dataLoss("backend went back in time (revision %d was already verified, the backend has not reached it)", c.rev))
			return nil
		case err != nil:
			return err
		}
		if cp, _ := p.rep.checkpoint(); cp.digest != c.digest {
			p.rep.fail(dataLoss("backend state at revision %d does not match the verified checkpoint (forged or forked history)", c.rev))
			return nil
		}
		log.Printf("replica verified against checkpoint at revision %d", c.rev)
		return nil
	}
	// No checkpoint at all: only an empty backend (a brand-new cluster) is
	// accepted without -trust-backend. Anything else could be a rolled back or
	// forged state presented to an instance that has nothing to compare with.
	if !haveFile || trustBackend {
		if err := p.rep.load(ctx, p.kv, 0); err != nil {
			return err
		}
		if trustBackend {
			log.Printf("WARNING: -trust-backend: accepting the backend state at revision %d without verification", p.rep.current())
			return nil
		}
		if p.rep.size() == 0 {
			log.Printf("first start: the backend is empty (revision %d), nothing to verify", p.rep.current())
			return nil
		}
		p.rep.fail(dataLoss("the backend holds data, but there is no checkpoint (own or peer) to verify it; start once with -trust-backend if this is intended"))
		return nil
	}
	p.rep.fail(dataLoss("no verifiable checkpoint left (the backend compacted past all of them); restart with -trust-backend to accept its state"))
	return nil
}

// ---------------------------------------------------------------- mTLS

// identity is what the device certificate says about this instance. It is a
// SPIFFE-style URI SAN:
//
//	spiffe://<trust-domain>/cluster/<cluster-id>/node/<node-name>
//
// The backend reads the same SAN from the client certificate and routes the
// connection to the tenant's own emulated etcd cluster. The proxy never sends
// a tenant id itself: whoever holds the device key is the device.
type identity struct {
	domain, cluster, node string
}

func identityOf(cert *x509.Certificate) (identity, error) {
	for _, u := range cert.URIs {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if u.Scheme == "spiffe" && u.Host != "" && len(parts) == 4 && parts[0] == "cluster" && parts[2] == "node" &&
			parts[1] != "" && parts[3] != "" {
			return identity{domain: u.Host, cluster: parts[1], node: parts[3]}, nil
		}
	}
	return identity{}, errors.New("certificate has no spiffe://<domain>/cluster/<id>/node/<name> URI SAN")
}

// certSource hands out the device certificate and reloads it when the files
// change, so short-lived certificates can be rotated without a restart.
//
// The key file is either a PEM private key (development) or a TPM blob
// ("VEIL TPM KEY"); then every TLS handshake is signed inside the TPM.
type certSource struct {
	certFile, keyFile string
	tpm               *tpmOpener

	mu     sync.Mutex
	cert   *tls.Certificate
	mod    time.Time
	signer *tpmSigner // current TPM key, flushed when rotated
}

func (c *certSource) load() (tls.Certificate, error) {
	keyPEM, err := os.ReadFile(c.keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != pemTPMKey {
		return tls.LoadX509KeyPair(c.certFile, c.keyFile)
	}
	if c.tpm == nil {
		return tls.Certificate{}, errors.New("TPM key given but no TPM configured")
	}
	dev, err := c.tpm.get()
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err := os.ReadFile(c.certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	var kp tls.Certificate
	for rest := certPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			kp.Certificate = append(kp.Certificate, b.Bytes)
		}
	}
	if len(kp.Certificate) == 0 {
		return tls.Certificate{}, fmt.Errorf("%s: no certificate", c.certFile)
	}
	if kp.Leaf, err = x509.ParseCertificate(kp.Certificate[0]); err != nil {
		return tls.Certificate{}, err
	}
	s, err := dev.signer(block.Bytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	if !publicKeysEqual(kp.Leaf.PublicKey, s.Public()) {
		dev.flush(s.h)
		return tls.Certificate{}, errors.New("certificate does not belong to the TPM key")
	}
	if c.signer != nil {
		dev.flush(c.signer.h)
	}
	c.signer, kp.PrivateKey = s, s
	return kp, nil
}

func (c *certSource) get() (*tls.Certificate, error) {
	cs, err := os.Stat(c.certFile)
	if err != nil {
		return c.fallback(err)
	}
	ks, err := os.Stat(c.keyFile)
	if err != nil {
		return c.fallback(err)
	}
	mod := cs.ModTime()
	if ks.ModTime().After(mod) {
		mod = ks.ModTime()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && !mod.After(c.mod) {
		return c.cert, nil
	}
	kp, err := c.load()
	if err != nil {
		if c.cert != nil { // e.g. caught mid-rotation: keep the old pair for now
			log.Printf("mTLS: cannot reload certificate (%v), keeping the previous one", err)
			return c.cert, nil
		}
		return nil, err
	}
	if kp.Leaf == nil {
		if kp.Leaf, err = x509.ParseCertificate(kp.Certificate[0]); err != nil {
			return nil, err
		}
	}
	if c.cert != nil {
		log.Printf("mTLS: loaded rotated certificate, valid until %s", kp.Leaf.NotAfter.Format(time.RFC3339))
	}
	c.cert, c.mod = &kp, mod
	return c.cert, nil
}

func (c *certSource) fallback(err error) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil {
		return c.cert, nil
	}
	return nil, err
}

func loadPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificates found", file)
	}
	return pool, nil
}

type tlsSetup struct {
	id         identity
	backend    *tls.Config // client side, towards the backend
	peerServer *tls.Config // serving checkpoints to peers
	peerClient *tls.Config // fetching checkpoints from peers
}

// newTLSSetup returns nil without -cert (plaintext development mode).
func newTLSSetup(cfg config) (*tlsSetup, error) {
	if cfg.certFile == "" {
		return nil, nil
	}
	if cfg.keyFile == "" || cfg.backendCA == "" {
		return nil, errors.New("-cert needs -key and -backend-ca")
	}
	src := &certSource{certFile: cfg.certFile, keyFile: cfg.keyFile, tpm: cfg.tpm}
	cert, err := src.get()
	if err != nil {
		return nil, fmt.Errorf("device certificate: %v", err)
	}
	id, err := identityOf(cert.Leaf)
	if err != nil {
		return nil, err
	}
	backendCA, err := loadPool(cfg.backendCA)
	if err != nil {
		return nil, err
	}
	clientCert := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return src.get() }
	ts := &tlsSetup{id: id, backend: &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              backendCA,
		ServerName:           cfg.backendName, // default: host of the (first) -upstream address
		GetClientCertificate: clientCert,
	}}
	if cfg.peerCA == "" {
		return ts, nil
	}
	peerCA, err := loadPool(cfg.peerCA)
	if err != nil {
		return nil, err
	}
	// Peers must hold a device certificate of the same cluster. The chain is
	// verified by crypto/tls before this runs.
	sameCluster := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("peer sent no certificate")
		}
		pid, err := identityOf(cs.PeerCertificates[0])
		if err != nil {
			return err
		}
		if pid.domain != id.domain || pid.cluster != id.cluster {
			return fmt.Errorf("peer belongs to cluster %q, not %q", pid.cluster, id.cluster)
		}
		return nil
	}
	ts.peerServer = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        peerCA,
		GetCertificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return src.get() },
		VerifyConnection: sameCluster,
	}
	// Device certificates name no hosts (the backend issues them with the spiffe:// URI only),
	// so the client verifies the chain itself instead of matching the address.
	ts.peerClient = &tls.Config{
		MinVersion:           tls.VersionTLS13,
		InsecureSkipVerify:   true, // replaced by the chain check in VerifyConnection
		GetClientCertificate: clientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("peer sent no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: peerCA, Intermediates: inter,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			return sameCluster(cs)
		},
	}
	return ts, nil
}

// ---------------------------------------------------------------- crypto

// maxBackendMessage limits responses from the backend (snapshot loads of the whole key space)
// and to the API server (which pages, but can ask for everything at once).
const maxBackendMessage = 2<<30 - 1

const (
	minSegmentSize = 32  // padded plaintext size of a key segment, at least
	minValueSize   = 128 // padded plaintext size of a value record, at least
	valueVersion   = 3
)

type sealer struct {
	seg       *subtle.AESSIV // key segments: deterministic, AES-256-SIV
	val       cipher.AEAD    // values: AES-256-GCM, random nonce
	peerMAC   []byte         // authenticates checkpoints between instances
	digestKey []byte         // keys the state digest
}

func newSealer(master []byte) (*sealer, error) {
	derive := func(info string, n int) []byte {
		k, err := hkdf.Key(sha256.New, master, nil, "veil-proxy v1 "+info, n)
		if err != nil {
			panic(err)
		}
		return k
	}
	s := &sealer{peerMAC: derive("peer hmac", 32), digestKey: derive("state digest", 32)}
	var err error
	if s.seg, err = subtle.NewAESSIV(derive("segment aes-siv", subtle.AESSIVKeySize)); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derive("value aes-gcm", 32))
	if err != nil {
		return nil, err
	}
	if s.val, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return s, nil
}

// padme returns the Padmé size for length l (Nikitin et al., "Reducing
// Metadata Leakage from Encrypted Files and Communication with PURBs", 2019):
// at most ~12% overhead, and only O(log log l) bits of the length remain.
func padme(l int) int {
	if l < 2 {
		return l
	}
	e := bits.Len(uint(l)) - 1 // floor(log2 l)
	s := bits.Len(uint(e))     // floor(log2 e) + 1
	mask := 1<<(e-s) - 1
	return (l + mask) &^ mask
}

// pad appends 0x80 and zero bytes (ISO/IEC 7816-4) up to a Padmé size of at
// least min bytes. It is deterministic, which key segments require.
func pad(b []byte, min int) []byte {
	n := padme(len(b) + 1)
	if n < min {
		n = min
	}
	out := make([]byte, n)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

func unpad(b []byte) ([]byte, error) {
	for i := len(b) - 1; i >= 0; i-- {
		switch b[i] {
		case 0:
		case 0x80:
			return b[:i], nil
		default:
			return nil, errors.New("bad padding")
		}
	}
	return nil, errors.New("bad padding")
}

func (s *sealer) encSegment(parent, seg string) string {
	ct, err := s.seg.EncryptDeterministically(pad([]byte(seg), minSegmentSize), []byte(parent))
	if err != nil {
		panic(err) // only fails for absurdly large inputs
	}
	return base64.RawURLEncoding.EncodeToString(ct)
}

func (s *sealer) decSegment(parent, enc string) (string, error) {
	// Exactly one spelling per key: Strict() rejects non-zero padding bits, but the decoder
	// still skips '\r' and '\n', so the re-encoding must also match.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != enc {
		return "", errors.New("not an encrypted key segment")
	}
	pt, err := s.seg.DecryptDeterministically(raw, []byte(parent))
	if err != nil {
		return "", errors.New("key segment authentication failed")
	}
	pt, err = unpad(pt)
	if err != nil {
		return "", fmt.Errorf("key segment: %v", err)
	}
	return string(pt), nil
}

// encKey encrypts every "/"-separated segment, keeping the separators.
func (s *sealer) encKey(k string) string {
	segs := strings.Split(k, "/")
	out := make([]string, len(segs))
	for i, seg := range segs {
		if seg != "" {
			out[i] = s.encSegment(strings.Join(segs[:i], "/"), seg)
		}
	}
	return strings.Join(out, "/")
}

func (s *sealer) decKey(ek string) (string, error) {
	segs := strings.Split(ek, "/")
	plain := make([]string, len(segs))
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		pt, err := s.decSegment(strings.Join(plain[:i], "/"), seg)
		if err != nil {
			return "", err
		}
		plain[i] = pt
	}
	return strings.Join(plain, "/"), nil
}

// sealRecord encrypts a value together with its predecessor revision and
// lease. Layout inside the encryption: prev (8) | lease (8) | payload.
func (s *sealer) sealRecord(key string, prev, lease int64, payload []byte) []byte {
	rec := make([]byte, 16+len(payload))
	binary.BigEndian.PutUint64(rec[0:], uint64(prev))
	binary.BigEndian.PutUint64(rec[8:], uint64(lease))
	copy(rec[16:], payload)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out := append([]byte{valueVersion}, nonce...)
	return s.val.Seal(out, nonce, pad(rec, minValueSize), []byte(key))
}

func (s *sealer) openRecord(key string, ev []byte) (payload []byte, prev, lease int64, err error) {
	if len(ev) < 1+12+16 || ev[0] != valueVersion {
		return nil, 0, 0, errors.New("value is not encrypted with a known format")
	}
	pt, err := s.val.Open(nil, ev[1:13], ev[13:], []byte(key))
	if err != nil {
		return nil, 0, 0, errors.New("value authentication failed")
	}
	if pt, err = unpad(pt); err != nil || len(pt) < 16 {
		return nil, 0, 0, errors.New("malformed value record")
	}
	return pt[16:], int64(binary.BigEndian.Uint64(pt[0:])), int64(binary.BigEndian.Uint64(pt[8:])), nil
}

// A delete receipt lists the deleted keys with the revision each one had.
// Layout: repeated prev (8) | key length (4) | key.
func buildReceipt(m map[string]int64) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b []byte
	for _, k := range keys {
		b = binary.BigEndian.AppendUint64(b, uint64(m[k]))
		b = binary.BigEndian.AppendUint32(b, uint32(len(k)))
		b = append(b, k...)
	}
	return b
}

func parseReceipt(b []byte) (map[string]int64, error) {
	m := map[string]int64{}
	for len(b) > 0 {
		if len(b) < 12 {
			return nil, errors.New("truncated")
		}
		prev, n := int64(binary.BigEndian.Uint64(b)), int(binary.BigEndian.Uint32(b[8:]))
		if len(b) < 12+n {
			return nil, errors.New("truncated")
		}
		m[string(b[12:12+n])] = prev
		b = b[12+n:]
	}
	return m, nil
}

// ---------------------------------------------------------------- key ranges

// prefixEnd mirrors clientv3.GetPrefixRangeEnd.
func prefixEnd(k string) string {
	b := []byte(k)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b[:i+1])
		}
	}
	return "\x00"
}

// keyRange is a classified plaintext [key, end) range: a single key, the
// whole key space, or a prefix scan starting at the prefix itself or at a key
// inside it (pagination continues at lastKey + "\x00").
type keyRange struct {
	single bool
	all    bool
	prefix string
	start  string
}

func parseRange(key, end []byte) (keyRange, error) {
	k, e := string(key), string(end)
	if e == "" {
		return keyRange{single: true, start: k}, nil
	}
	if e == "\x00" && (k == "" || k == "\x00") {
		return keyRange{all: true}, nil
	}
	if last := e[len(e)-1]; last > 0 {
		prefix := e[:len(e)-1] + string([]byte{last - 1})
		if strings.HasPrefix(k, prefix) && !strings.HasSuffix(prefix, "\x00") {
			return keyRange{prefix: prefix, start: k}, nil
		}
	}
	return keyRange{}, status.Errorf(codes.InvalidArgument, "veil: unsupported key range [%q, %q)", k, e)
}

// ---------------------------------------------------------------- freshness and checkpoints

// freshness tracks the highest backend revision seen (the floor), persists
// verified checkpoints and exchanges them with the other instances.
//
// Rule: a request sent after revision R was seen must be answered with a
// revision >= R. Comparing against the floor taken *before* the request avoids
// false alarms when responses overtake each other.
type freshness struct {
	hwm    atomic.Int64
	mac    []byte
	file   string
	peers  []string
	client *http.Client

	peersFile string // -peers-file: re-read when it changes
	peersMu   sync.Mutex
	peersMod  time.Time
	extra     []string // -peers plus the file
	scheme    string   // "https" with mTLS
	rep       *replica

	mu     sync.Mutex
	last   checkpoint // last persisted own checkpoint
	anchor checkpoint // digest at the last compaction revision we forwarded
	saved  string
}

func newFreshness(mac []byte, file string, peers []string, rep *replica) *freshness {
	return &freshness{mac: mac, file: file, peers: peers, rep: rep, scheme: "http", client: &http.Client{Timeout: 2 * time.Second}}
}

func (f *freshness) floor() int64 { return f.hwm.Load() }

func (f *freshness) observe(rev int64) {
	for {
		cur := f.hwm.Load()
		if rev <= cur || f.hwm.CompareAndSwap(cur, rev) {
			return
		}
	}
}

func (f *freshness) check(before int64, h *pb.ResponseHeader) error {
	if h == nil {
		return nil
	}
	if h.Revision < before {
		log.Printf("ROLLBACK DETECTED: backend answered with revision %d after revision %d was already seen", h.Revision, before)
		return dataLoss("backend went back in time (revision %d, already seen %d)", h.Revision, before)
	}
	f.observe(h.Revision)
	return nil
}

func (f *freshness) sign(c checkpoint) string {
	m := hmac.New(sha256.New, f.mac)
	fmt.Fprintf(m, "veil-proxy checkpoint %d %x", c.rev, c.digest)
	return hex.EncodeToString(m.Sum(nil))
}

func formatCheckpoint(c checkpoint) string { return fmt.Sprintf("%d %x", c.rev, c.digest) }

func parseCheckpoint(s string) (checkpoint, error) {
	var c checkpoint
	var d string
	if _, err := fmt.Sscanf(s, "%d %s", &c.rev, &d); err != nil {
		return c, err
	}
	raw, err := hex.DecodeString(d)
	if err != nil || len(raw) != 32 {
		return c, errors.New("bad digest")
	}
	copy(c.digest[:], raw)
	return c, nil
}

// loadFile reads "latest <rev> <digest>" and "anchor <rev> <digest>".
func (f *freshness) loadFile() (latest, anchor checkpoint, exists bool, err error) {
	b, err := os.ReadFile(f.file)
	if os.IsNotExist(err) {
		return latest, anchor, false, nil
	}
	if err != nil {
		return latest, anchor, false, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, rest, _ := strings.Cut(line, " ")
		c, err := parseCheckpoint(rest)
		if err != nil {
			return latest, anchor, true, fmt.Errorf("state file %s: %v", f.file, err)
		}
		switch name {
		case "latest":
			latest = c
		case "anchor":
			anchor = c
		}
	}
	f.mu.Lock()
	f.last, f.anchor = latest, anchor
	f.mu.Unlock()
	return latest, anchor, true, nil
}

func (f *freshness) setAnchor(c checkpoint) {
	f.mu.Lock()
	f.anchor = c
	f.mu.Unlock()
}

func (f *freshness) persist() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cp, ok := f.rep.checkpoint(); ok {
		f.last = cp
	}
	content := "latest " + formatCheckpoint(f.last) + "\nanchor " + formatCheckpoint(f.anchor) + "\n"
	if content == f.saved || f.last.rev == 0 {
		return
	}
	tmp := f.file + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		log.Printf("persist checkpoint: %v", err)
		return
	}
	if err := os.Rename(tmp, f.file); err != nil {
		log.Printf("persist checkpoint: %v", err)
		return
	}
	f.saved = content
}

// peerHandler serves signed checkpoints: /checkpoint (latest) and
// /digest?rev=N (from the verified history window).
func peerHandler(f *freshness) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, c checkpoint) {
		fmt.Fprintf(w, "%s %s\n", formatCheckpoint(c), f.sign(c))
	}
	mux.HandleFunc("/checkpoint", func(w http.ResponseWriter, _ *http.Request) {
		c, ok := f.rep.checkpoint()
		if !ok {
			http.Error(w, "not available", http.StatusServiceUnavailable)
			return
		}
		reply(w, c)
	})
	mux.HandleFunc("/digest", func(w http.ResponseWriter, r *http.Request) {
		rev, _ := strconv.ParseInt(r.URL.Query().Get("rev"), 10, 64)
		d, ok := f.rep.digestAt(rev)
		if !ok {
			http.NotFound(w, r)
			return
		}
		reply(w, checkpoint{rev: rev, digest: d})
	})
	return mux
}

func (f *freshness) fetch(peer, path string) (checkpoint, bool) {
	resp, err := f.client.Get(f.scheme + "://" + peer + path)
	if err != nil {
		return checkpoint{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return checkpoint{}, false
	}
	fields := strings.Fields(string(body))
	if len(fields) != 3 {
		return checkpoint{}, false
	}
	c, err := parseCheckpoint(fields[0] + " " + fields[1])
	if err != nil || !hmac.Equal([]byte(fields[2]), []byte(f.sign(c))) {
		log.Printf("peer %s: invalid checkpoint signature, ignored", peer)
		return checkpoint{}, false
	}
	return c, true
}

// peerList returns -peers plus the addresses in -peers-file (one per line or comma
// separated), which is read again whenever it changes, so instances can be added without a
// restart. A missing file means no extra peers.
func (f *freshness) peerList() []string {
	if f.peersFile == "" {
		return f.peers
	}
	f.peersMu.Lock()
	defer f.peersMu.Unlock()
	st, err := os.Stat(f.peersFile)
	if err != nil {
		return f.peers
	}
	if !st.ModTime().Equal(f.peersMod) {
		raw, err := os.ReadFile(f.peersFile)
		if err == nil {
			list := append([]string(nil), f.peers...)
			for _, a := range splitList(strings.ReplaceAll(string(raw), "\n", ",")) {
				if !slices.Contains(list, a) {
					list = append(list, a)
				}
			}
			f.extra, f.peersMod = list, st.ModTime()
		}
	}
	if f.extra == nil {
		return f.peers
	}
	return f.extra
}

// pull fetches the latest checkpoint of every reachable peer, raises the floor
// and hands the digests to the replica for fork detection.
func (f *freshness) pull() []checkpoint {
	var mu sync.Mutex
	var out []checkpoint
	var wg sync.WaitGroup
	for _, peer := range f.peerList() {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			if c, ok := f.fetch(peer, "/checkpoint"); ok {
				f.observe(c.rev)
				f.rep.claim(c)
				mu.Lock()
				out = append(out, c)
				mu.Unlock()
			}
		}(peer)
	}
	wg.Wait()
	return out
}

func (f *freshness) loop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.pull()
			f.persist()
		}
	}
}

// ---------------------------------------------------------------- gRPC services

type proxy struct {
	s        *sealer
	kv       pb.KVClient
	watch    pb.WatchClient
	lease    pb.LeaseClient
	maint    pb.MaintenanceClient
	rep      *replica
	fresh    *freshness
	delay    time.Duration
	verbose  bool
	addr     string
	self     string
	peerAddr string
	opsAddr  string

	metrics  *metrics
	srv      *grpc.Server
	serving  atomic.Bool
	closers  []func() error
	stopOnce sync.Once
}

func (p *proxy) rtt() {
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
}

func (p *proxy) halfRTT() {
	if p.delay > 0 {
		time.Sleep(p.delay / 2)
	}
}

func (p *proxy) logf(format string, args ...any) {
	if p.verbose {
		log.Printf(format, args...)
	}
}

type withHeader interface{ GetHeader() *pb.ResponseHeader }

// forward runs one backend call and enforces the freshness rule on its answer.
func forward[R withHeader](p *proxy, call func() (R, error)) (R, error) {
	var zero R
	if err := p.rep.err(); err != nil {
		return zero, err
	}
	before := p.fresh.floor()
	p.rtt()
	resp, err := call()
	if err != nil {
		return zero, err
	}
	if err := p.fresh.check(before, resp.GetHeader()); err != nil {
		return zero, err
	}
	return resp, nil
}

// readIndex makes a read linearizable: ask the backend for its current
// revision (a cheap count on a key that never exists) and wait until the
// verified replica has caught up to it.
func (p *proxy) readIndex(ctx context.Context) error {
	resp, err := forward(p, func() (*pb.RangeResponse, error) {
		return p.kv.Range(ctx, &pb.RangeRequest{Key: []byte(p.s.encKey(readIndexKey)), CountOnly: true})
	})
	if err != nil {
		return err
	}
	return p.rep.waitFor(ctx, resp.Header.Revision)
}

// KV: reads come from the replica, writes go through txn().

func (p *proxy) Range(ctx context.Context, r *pb.RangeRequest) (*pb.RangeResponse, error) {
	p.logf("Range %q %q limit=%d rev=%d count=%v", r.Key, r.RangeEnd, r.Limit, r.Revision, r.CountOnly)
	kr, err := parseRange(r.Key, r.RangeEnd)
	if err != nil {
		return nil, err
	}
	switch {
	case r.Revision > 0:
		err = p.rep.waitFor(ctx, r.Revision)
	case !r.Serializable:
		err = p.readIndex(ctx)
	}
	if err != nil {
		return nil, err
	}
	return p.rep.serveRange(r, kr, r.Revision)
}

func (p *proxy) Put(ctx context.Context, r *pb.PutRequest) (*pb.PutResponse, error) {
	p.logf("Put %q (%d bytes)", r.Key, len(r.Value))
	resp, err := p.txn(ctx, &pb.TxnRequest{Success: []*pb.RequestOp{{Request: &pb.RequestOp_RequestPut{RequestPut: r}}}})
	if err != nil {
		return nil, err
	}
	return resp.Responses[0].GetResponsePut(), nil
}

func (p *proxy) DeleteRange(ctx context.Context, r *pb.DeleteRangeRequest) (*pb.DeleteRangeResponse, error) {
	p.logf("DeleteRange %q %q", r.Key, r.RangeEnd)
	resp, err := p.txn(ctx, &pb.TxnRequest{Success: []*pb.RequestOp{{Request: &pb.RequestOp_RequestDeleteRange{RequestDeleteRange: r}}}})
	if err != nil {
		return nil, err
	}
	return resp.Responses[0].GetResponseDeleteRange(), nil
}

func (p *proxy) Txn(ctx context.Context, r *pb.TxnRequest) (*pb.TxnResponse, error) {
	if p.verbose {
		var keys []string
		for _, c := range r.Compare {
			keys = append(keys, string(c.Key))
		}
		p.logf("Txn compare=%q", keys)
	}
	return p.txn(ctx, r)
}

// write is one key changed by a transaction's success branch.
type write struct {
	key string
	put *pb.PutRequest // nil for a delete
}

func unsupported(what string) error {
	return status.Errorf(codes.Unimplemented, "veil: %s are not supported", what)
}

// txn executes every write. It pins each written key to the revision it
// replaces (so the value can name its predecessor), adds a delete receipt,
// and then checks the backend's verdict and effects against the replica.
// All results sent back to the client come from the replica.
func (p *proxy) txn(ctx context.Context, r *pb.TxnRequest) (*pb.TxnResponse, error) {
	for _, c := range r.Compare {
		if len(c.RangeEnd) > 0 {
			return nil, unsupported("range compares")
		}
		if c.Target == pb.Compare_VALUE {
			return nil, unsupported("value compares")
		}
	}
	var writes []write
	for _, op := range r.Success {
		switch o := op.Request.(type) {
		case *pb.RequestOp_RequestPut:
			if o.RequestPut.IgnoreValue || o.RequestPut.IgnoreLease {
				return nil, unsupported("ignore_value/ignore_lease puts")
			}
			writes = append(writes, write{key: string(o.RequestPut.Key), put: o.RequestPut})
		case *pb.RequestOp_RequestDeleteRange:
			if len(o.RequestDeleteRange.RangeEnd) > 0 {
				return nil, unsupported("range deletes")
			}
			writes = append(writes, write{key: string(o.RequestDeleteRange.Key)})
		case *pb.RequestOp_RequestTxn:
			return nil, unsupported("nested transactions")
		}
	}
	for _, op := range r.Failure {
		if _, ok := op.Request.(*pb.RequestOp_RequestRange); !ok {
			return nil, unsupported("writes in the failure branch")
		}
	}
	for _, w := range writes {
		if strings.HasPrefix(w.key, "/veil/") {
			return nil, status.Error(codes.PermissionDenied, "veil: /veil/ is reserved")
		}
	}

	for attempt := 0; attempt < 50; attempt++ {
		pins := map[string]int64{}
		for _, c := range r.Compare {
			if c.Target == pb.Compare_MOD && c.Result == pb.Compare_EQUAL {
				pins[string(c.Key)] = c.GetModRevision()
			}
		}
		added := map[string]int64{}
		for _, w := range writes {
			if _, ok := pins[w.key]; !ok {
				v, _ := p.rep.latest(w.key)
				pins[w.key], added[w.key] = v.modRev, v.modRev
			}
		}

		enc := &pb.TxnRequest{}
		encCompare := func(c pb.Compare) {
			c.Key = []byte(p.s.encKey(string(c.Key)))
			enc.Compare = append(enc.Compare, &c)
		}
		for _, c := range r.Compare {
			encCompare(*c)
		}
		for k, m := range added {
			encCompare(pb.Compare{Key: []byte(k), Target: pb.Compare_MOD, Result: pb.Compare_EQUAL,
				TargetUnion: &pb.Compare_ModRevision{ModRevision: m}})
		}
		receipt := map[string]int64{}
		for _, w := range writes {
			ek := []byte(p.s.encKey(w.key))
			if w.put != nil {
				enc.Success = append(enc.Success, &pb.RequestOp{Request: &pb.RequestOp_RequestPut{RequestPut: &pb.PutRequest{
					Key: ek, Value: p.s.sealRecord(w.key, pins[w.key], w.put.Lease, w.put.Value), Lease: w.put.Lease}}})
			} else {
				enc.Success = append(enc.Success, &pb.RequestOp{Request: &pb.RequestOp_RequestDeleteRange{
					RequestDeleteRange: &pb.DeleteRangeRequest{Key: ek}}})
				if pins[w.key] != 0 {
					receipt[w.key] = pins[w.key]
				}
			}
		}
		if len(receipt) > 0 {
			enc.Success = append(enc.Success, &pb.RequestOp{Request: &pb.RequestOp_RequestPut{RequestPut: &pb.PutRequest{
				Key: []byte(p.s.encKey(receiptKey)), Value: p.s.sealRecord(receiptKey, 0, 0, buildReceipt(receipt))}}})
		}

		resp, err := forward(p, func() (*pb.TxnResponse, error) { return p.kv.Txn(ctx, enc) })
		if err != nil {
			return nil, err
		}
		if err := p.rep.waitFor(ctx, resp.Header.Revision); err != nil {
			return nil, err
		}
		out, retry, err := p.rep.checkTxn(r, writes, added, resp)
		if err != nil {
			p.rep.fail(err)
			return nil, err
		}
		if !retry {
			return out, nil
		}
	}
	return nil, status.Error(codes.Unavailable, "veil: too much write contention")
}

func evalCompare(c *pb.Compare, v version) bool {
	var val, want int64
	switch c.Target {
	case pb.Compare_VERSION:
		val, want = v.ver, c.GetVersion()
	case pb.Compare_CREATE:
		val, want = v.createRev, c.GetCreateRevision()
	case pb.Compare_MOD:
		val, want = v.modRev, c.GetModRevision()
	case pb.Compare_LEASE:
		val, want = v.lease, c.GetLease()
	default:
		return false
	}
	switch c.Result {
	case pb.Compare_EQUAL:
		return val == want
	case pb.Compare_GREATER:
		return val > want
	case pb.Compare_LESS:
		return val < want
	case pb.Compare_NOT_EQUAL:
		return val != want
	}
	return false
}

// checkTxn verifies the backend's answer to a transaction against the
// replica (which has already applied revision H = resp.Header.Revision):
//   - success: the conditions held before H, and every write is in H
//   - failure: the conditions really did not hold at H
//
// A failure caused only by pins the proxy added (its replica was behind)
// asks for a retry. The response is built from the replica.
func (r *replica) checkTxn(req *pb.TxnRequest, writes []write, added map[string]int64, resp *pb.TxnResponse) (*pb.TxnResponse, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	H := resp.Header.Revision
	bumped := false
	if resp.Succeeded && len(writes) > 0 {
		i := sort.Search(len(r.hist), func(i int) bool { return r.hist[i].rev >= H })
		if i < len(r.hist) && r.hist[i].rev == H {
			for _, c := range r.hist[i].changes {
				for _, w := range writes {
					bumped = bumped || c.key == w.key
				}
			}
		}
	}
	at := H
	if bumped {
		at = H - 1
	}
	if at < r.base {
		return nil, false, dataLoss("transaction at revision %d is outside the verified history", H)
	}
	holds := func(c *pb.Compare) bool {
		v, _ := r.atLocked(string(c.Key), at)
		return evalCompare(c, v)
	}
	origOK := true
	for _, c := range req.Compare {
		origOK = origOK && holds(c)
	}
	addedOK := true
	for k, m := range added {
		addedOK = addedOK && holds(&pb.Compare{Key: []byte(k), Target: pb.Compare_MOD, Result: pb.Compare_EQUAL,
			TargetUnion: &pb.Compare_ModRevision{ModRevision: m}})
	}

	if resp.Succeeded {
		if !origOK || !addedOK {
			return nil, false, dataLoss("backend executed a transaction whose condition was false at revision %d", at)
		}
		for _, w := range writes {
			v, ok := r.atLocked(w.key, H)
			before, existed := r.atLocked(w.key, at)
			switch {
			case w.put != nil && (!bumped || !ok || v.modRev != H || v.lease != w.put.Lease || !bytes.Equal(v.value, w.put.Value)):
				return nil, false, dataLoss("backend acknowledged a write to %q that is not in its history at revision %d", w.key, H)
			case w.put == nil && existed && ok:
				return nil, false, dataLoss("backend acknowledged a delete of %q (revision %d) that is not in its history", w.key, before.modRev)
			}
		}
	} else {
		if origOK && addedOK {
			return nil, false, dataLoss("backend rejected a transaction whose condition held at revision %d", at)
		}
		if origOK {
			return nil, true, nil // only our own pins failed: the replica was behind
		}
	}

	out := &pb.TxnResponse{Header: resp.Header, Succeeded: resp.Succeeded}
	ops := req.Failure
	if resp.Succeeded {
		ops = req.Success
	}
	for _, op := range ops {
		switch o := op.Request.(type) {
		case *pb.RequestOp_RequestRange:
			kr, err := parseRange(o.RequestRange.Key, o.RequestRange.RangeEnd)
			if err != nil {
				return nil, false, err
			}
			rr, err := r.serveRangeLocked(o.RequestRange, kr, H)
			if err != nil {
				return nil, false, err
			}
			rr.Header = resp.Header
			out.Responses = append(out.Responses, &pb.ResponseOp{Response: &pb.ResponseOp_ResponseRange{ResponseRange: rr}})
		case *pb.RequestOp_RequestPut:
			pr := &pb.PutResponse{Header: resp.Header}
			if v, ok := r.atLocked(string(o.RequestPut.Key), at); ok && o.RequestPut.PrevKv {
				pr.PrevKv = v.kv(string(o.RequestPut.Key), false)
			}
			out.Responses = append(out.Responses, &pb.ResponseOp{Response: &pb.ResponseOp_ResponsePut{ResponsePut: pr}})
		case *pb.RequestOp_RequestDeleteRange:
			dr := &pb.DeleteRangeResponse{Header: resp.Header}
			if v, ok := r.atLocked(string(o.RequestDeleteRange.Key), at); ok {
				dr.Deleted = 1
				if o.RequestDeleteRange.PrevKv {
					dr.PrevKvs = append(dr.PrevKvs, v.kv(string(o.RequestDeleteRange.Key), false))
				}
			}
			out.Responses = append(out.Responses, &pb.ResponseOp{Response: &pb.ResponseOp_ResponseDeleteRange{ResponseDeleteRange: dr}})
		}
	}
	return out, false, nil
}

// Compact first records the verified digest at the compaction revision as
// anchor, so a restart after a long outage can still verify the backend.
func (p *proxy) Compact(ctx context.Context, r *pb.CompactionRequest) (*pb.CompactionResponse, error) {
	p.logf("Compact rev=%d", r.Revision)
	d, ok := p.rep.digestAt(r.Revision)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "veil: will not compact to revision %d, it is outside this instance's verified history", r.Revision)
	}
	p.fresh.setAnchor(checkpoint{rev: r.Revision, digest: d})
	p.fresh.persist()
	return forward(p, func() (*pb.CompactionResponse, error) { return p.kv.Compact(ctx, r) })
}

// upstreamCtx forwards the etcd client's "hasleader" requirement.
func upstreamCtx(ctx context.Context) context.Context {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("hasleader"); len(v) > 0 {
			return metadata.AppendToOutgoingContext(ctx, "hasleader", v[0])
		}
	}
	return ctx
}

// Lease: no keys or values involved, except in TimeToLive.

func (p *proxy) LeaseGrant(ctx context.Context, r *pb.LeaseGrantRequest) (*pb.LeaseGrantResponse, error) {
	return forward(p, func() (*pb.LeaseGrantResponse, error) { return p.lease.LeaseGrant(ctx, r) })
}

func (p *proxy) LeaseRevoke(ctx context.Context, r *pb.LeaseRevokeRequest) (*pb.LeaseRevokeResponse, error) {
	return forward(p, func() (*pb.LeaseRevokeResponse, error) { return p.lease.LeaseRevoke(ctx, r) })
}

func (p *proxy) LeaseTimeToLive(ctx context.Context, r *pb.LeaseTimeToLiveRequest) (*pb.LeaseTimeToLiveResponse, error) {
	resp, err := forward(p, func() (*pb.LeaseTimeToLiveResponse, error) { return p.lease.LeaseTimeToLive(ctx, r) })
	if err != nil {
		return nil, err
	}
	for i, k := range resp.Keys {
		pk, err := p.s.decKey(string(k))
		if err != nil {
			return nil, dataLoss("lease key: %v", err)
		}
		resp.Keys[i] = []byte(pk)
	}
	return resp, nil
}

func (p *proxy) LeaseLeases(ctx context.Context, r *pb.LeaseLeasesRequest) (*pb.LeaseLeasesResponse, error) {
	return forward(p, func() (*pb.LeaseLeasesResponse, error) { return p.lease.LeaseLeases(ctx, r) })
}

func (p *proxy) LeaseKeepAlive(srv pb.Lease_LeaseKeepAliveServer) error {
	ctx, cancel := context.WithCancel(upstreamCtx(srv.Context()))
	defer cancel()
	up, err := p.lease.LeaseKeepAlive(ctx)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	floor := p.fresh.floor()
	go func() {
		for {
			req, err := srv.Recv()
			if err == io.EOF {
				up.CloseSend()
				return
			}
			if err != nil {
				errc <- err
				return
			}
			p.halfRTT()
			if err := up.Send(req); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		for {
			resp, err := up.Recv()
			if err != nil {
				errc <- err
				return
			}
			if err := p.fresh.check(floor, resp.Header); err != nil {
				errc <- err
				return
			}
			floor = max(floor, resp.Header.GetRevision())
			p.halfRTT()
			if err := srv.Send(resp); err != nil {
				errc <- err
				return
			}
		}
	}()
	err = <-errc
	if err == io.EOF || status.Code(err) == codes.Canceled {
		return nil
	}
	return err
}

// Maintenance: only Status is needed by kube-apiserver and k3s.

type maintenance struct {
	*proxy
}

func (m maintenance) Status(ctx context.Context, r *pb.StatusRequest) (*pb.StatusResponse, error) {
	return forward(m.proxy, func() (*pb.StatusResponse, error) { return m.maint.Status(ctx, r) })
}

func (m maintenance) Alarm(ctx context.Context, r *pb.AlarmRequest) (*pb.AlarmResponse, error) {
	return forward(m.proxy, func() (*pb.AlarmResponse, error) { return m.maint.Alarm(ctx, r) })
}

func (maintenance) Defragment(context.Context, *pb.DefragmentRequest) (*pb.DefragmentResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: defragmentation is done by the backend operator")
}

func (maintenance) Hash(context.Context, *pb.HashRequest) (*pb.HashResponse, error) {
	return nil, status.Error(codes.Unimplemented, "veil: not supported")
}

func (maintenance) HashKV(context.Context, *pb.HashKVRequest) (*pb.HashKVResponse, error) {
	return nil, status.Error(codes.Unimplemented, "veil: not supported")
}

func (maintenance) Snapshot(*pb.SnapshotRequest, pb.Maintenance_SnapshotServer) error {
	return status.Error(codes.Unimplemented, "veil: snapshots are taken by the backend operator (ciphertext only)")
}

func (maintenance) MoveLeader(context.Context, *pb.MoveLeaderRequest) (*pb.MoveLeaderResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: not supported")
}

func (maintenance) Downgrade(context.Context, *pb.DowngradeRequest) (*pb.DowngradeResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: not supported")
}

// Cluster: present the proxy as the only member, so clients never bypass it.

type cluster struct {
	*proxy
}

func (c cluster) MemberList(ctx context.Context, r *pb.MemberListRequest) (*pb.MemberListResponse, error) {
	st, err := forward(c.proxy, func() (*pb.StatusResponse, error) { return c.maint.Status(ctx, &pb.StatusRequest{}) })
	if err != nil {
		return nil, err
	}
	return &pb.MemberListResponse{
		Header:  st.Header,
		Members: []*pb.Member{{ID: st.Header.MemberId, Name: "veil-proxy", ClientURLs: []string{c.self}}},
	}, nil
}

func (cluster) MemberAdd(context.Context, *pb.MemberAddRequest) (*pb.MemberAddResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}

func (cluster) MemberRemove(context.Context, *pb.MemberRemoveRequest) (*pb.MemberRemoveResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}

func (cluster) MemberUpdate(context.Context, *pb.MemberUpdateRequest) (*pb.MemberUpdateResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}

func (cluster) MemberPromote(context.Context, *pb.MemberPromoteRequest) (*pb.MemberPromoteResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}
