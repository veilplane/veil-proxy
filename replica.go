// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package main

// The verified replica.
//
// Every proxy instance follows the backend's complete change stream and keeps
// its own copy of the (decrypted) key space plus a few minutes of history.
// Each change is checked before it is applied:
//
//   - revisions must be gap-free: r+1 follows r, nothing can be withheld
//   - a written value names its predecessor (the mod revision it replaced),
//     sealed inside the encryption: replaying an old ciphertext breaks the chain
//   - create revision, version and lease must follow from the previous state
//   - a delete needs a delete receipt written in the same transaction, unless
//     the key is attached to a lease (lease expiry is done by the backend)
//
// Reads and watches are answered from this replica, never from backend
// answers. A keyed set hash ("digest") of the whole state is maintained
// incrementally and compared with the other instances, so a backend that
// shows different histories to different instances is caught as well.
//
// On the first violation the replica fails permanently: every request is
// answered with DataLoss. Failing closed is the only safe reaction.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	receiptKey   = "/veil/delete-receipt" // written next to every delete, never shown to clients
	readIndexKey = "/veil/read-index"     // never written, only used to ask the backend for its revision
)

var (
	errCompacted = status.Error(codes.OutOfRange, "etcdserver: mvcc: required revision has been compacted")
	errFutureRev = status.Error(codes.OutOfRange, "etcdserver: mvcc: required revision is a future revision")
	mod256       = new(big.Int).Lsh(big.NewInt(1), 256)
)

// version is one state of a key. A delete is stored as a tombstone.
type version struct {
	modRev, createRev, ver, lease int64
	value                         []byte
	deleted                       bool
}

func (v version) kv(key string, keysOnly bool) *mvccpb.KeyValue {
	kv := &mvccpb.KeyValue{Key: []byte(key), ModRevision: v.modRev, CreateRevision: v.createRev, Version: v.ver, Lease: v.lease}
	if !keysOnly {
		kv.Value = v.value
	}
	return kv
}

// change is what one revision did to one key.
type change struct {
	key  string
	cur  version  // state after the change (tombstone for deletes)
	prev *version // state before, nil if the key did not exist
}

type revision struct {
	rev     int64
	at      time.Time
	digest  [32]byte
	changes []change
}

type checkpoint struct {
	rev    int64
	digest [32]byte
}

type replica struct {
	s       *sealer
	digKey  []byte
	window  time.Duration
	failure atomic.Pointer[error]

	mu         sync.RWMutex
	loaded     bool
	rev        int64                // last applied revision
	base       int64                // the state is known for every revision >= base
	baseDigest [32]byte             // digest at base
	keys       map[string][]version // versions ascending by modRev, tombstones included
	order      []string             // all keys of the map, sorted: prefix scans are a binary search
	hist       []revision           // revisions in (base, rev], ascending
	digest     *big.Int             // keyed set hash of the state at rev
	header     pb.ResponseHeader    // cluster/member ids of the backend
	claims     map[int64][32]byte   // digests reported by peers for revisions we have not reached
	changed    chan struct{}        // closed and replaced on every change
}

func newReplica(s *sealer, window time.Duration) *replica {
	return &replica{
		s: s, digKey: s.digestKey, window: window,
		keys: map[string][]version{}, digest: new(big.Int),
		claims: map[int64][32]byte{}, changed: make(chan struct{}),
	}
}

// ---------------------------------------------------------------- failing closed

func (r *replica) fail(err error) {
	if r.failure.CompareAndSwap(nil, &err) {
		log.Printf("REPLICA STOPPED, refusing to serve: %v", err)
		r.mu.Lock()
		r.notifyLocked()
		r.mu.Unlock()
	}
}

func (r *replica) err() error {
	if e := r.failure.Load(); e != nil {
		return *e
	}
	return nil
}

func dataLoss(format string, args ...any) error {
	return status.Errorf(codes.DataLoss, "veil: "+format, args...)
}

func (r *replica) notifyLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// ---------------------------------------------------------------- digest

// entryHash is keyed with a secret derived from the master key, so the backend
// can neither compute nor steer it. Summing entries modulo 2^256 gives a set
// hash that can be updated per change (subtract old entry, add new one).
func (r *replica) entryHash(key string, v version) *big.Int {
	m := hmac.New(sha256.New, r.digKey)
	var b [32]byte
	binary.BigEndian.PutUint64(b[0:], uint64(v.modRev))
	binary.BigEndian.PutUint64(b[8:], uint64(v.createRev))
	binary.BigEndian.PutUint64(b[16:], uint64(v.ver))
	binary.BigEndian.PutUint64(b[24:], uint64(v.lease))
	m.Write(b[:])
	vh := sha256.Sum256(v.value)
	m.Write(vh[:])
	m.Write([]byte(key))
	return new(big.Int).SetBytes(m.Sum(nil))
}

func (r *replica) digestBytes() [32]byte {
	var out [32]byte
	r.digest.FillBytes(out[:])
	return out
}

// checkpoint returns the last verified state. It stays available after the
// replica stopped: the last good state is exactly what other instances need
// to detect the attack themselves.
func (r *replica) checkpoint() (checkpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.loaded {
		return checkpoint{}, false
	}
	return checkpoint{rev: r.rev, digest: r.digestBytes()}, true
}

func (r *replica) digestAtLocked(rev int64) ([32]byte, bool) {
	if rev == r.base {
		return r.baseDigest, true
	}
	i := sort.Search(len(r.hist), func(i int) bool { return r.hist[i].rev >= rev })
	if i < len(r.hist) && r.hist[i].rev == rev {
		return r.hist[i].digest, true
	}
	return [32]byte{}, false
}

func (r *replica) digestAt(rev int64) ([32]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.digestAtLocked(rev)
}

// claim compares a digest another instance saw at some revision with ours.
func (r *replica) claim(c checkpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.rev > r.rev || !r.loaded {
		if len(r.claims) < 10000 {
			r.claims[c.rev] = c.digest
		}
		return
	}
	if d, ok := r.digestAtLocked(c.rev); ok && d != c.digest {
		go r.fail(dataLoss("another instance saw a different state at revision %d: the backend shows different histories (fork)", c.rev))
	}
}

// ---------------------------------------------------------------- loading a snapshot

// load replaces the replica with the backend's full key space at revision
// rev (0 = latest). It is only trusted if the resulting digest matches a
// checkpoint, which the caller checks.
func (r *replica) load(ctx context.Context, kv pb.KVClient, rev int64) error {
	resp, err := kv.Range(ctx, &pb.RangeRequest{Key: []byte{0}, RangeEnd: []byte{0}, Revision: rev})
	if err != nil {
		return err
	}
	at := rev
	if at == 0 {
		at = resp.Header.Revision
	}
	keys := map[string][]version{}
	digest := new(big.Int)
	for _, kv := range resp.Kvs {
		key, err := r.s.decKey(string(kv.Key))
		if err != nil {
			return dataLoss("snapshot key %q: %v", kv.Key, err)
		}
		if key == receiptKey {
			continue
		}
		payload, prev, lease, err := r.s.openRecord(key, kv.Value)
		if err != nil {
			return dataLoss("snapshot value of %q: %v", key, err)
		}
		if lease != kv.Lease || prev >= kv.ModRevision || kv.CreateRevision > kv.ModRevision {
			return dataLoss("snapshot metadata of %q is inconsistent", key)
		}
		v := version{modRev: kv.ModRevision, createRev: kv.CreateRevision, ver: kv.Version, lease: lease, value: payload}
		keys[key] = []version{v}
		digest.Add(digest, r.entryHash(key, v))
	}
	digest.Mod(digest, mod256)

	r.mu.Lock()
	defer r.mu.Unlock()
	order := make([]string, 0, len(keys))
	for k := range keys {
		order = append(order, k)
	}
	sort.Strings(order)
	r.loaded, r.rev, r.base, r.keys, r.order, r.hist, r.digest = true, at, at, keys, order, nil, digest
	r.baseDigest = r.digestBytes()
	r.header = *resp.Header
	for crev, d := range r.claims {
		if crev <= at {
			delete(r.claims, crev)
			if crev == at && d != r.baseDigest {
				go r.fail(dataLoss("another instance saw a different state at revision %d: the backend shows different histories (fork)", at))
			}
		}
	}
	r.notifyLocked()
	return nil
}

// ---------------------------------------------------------------- following the backend

// size counts live keys.
func (r *replica) size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for k := range r.keys {
		if _, ok := r.latestLocked(k); ok {
			n++
		}
	}
	return n
}

func (r *replica) current() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rev
}

func (r *replica) follow(ctx context.Context, p *proxy) {
	for ctx.Err() == nil && r.err() == nil {
		err := r.followOnce(ctx, p)
		if ctx.Err() != nil || r.err() != nil {
			return
		}
		log.Printf("replica: backend watch interrupted (%v), reconnecting", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (r *replica) followOnce(ctx context.Context, p *proxy) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := p.watch.Watch(sctx)
	if err != nil {
		return err
	}
	create := &pb.WatchCreateRequest{Key: []byte{0}, RangeEnd: []byte{0}, StartRevision: r.current() + 1, ProgressNotify: true}
	if err := st.Send(&pb.WatchRequest{RequestUnion: &pb.WatchRequest_CreateRequest{CreateRequest: create}}); err != nil {
		return err
	}
	for {
		resp, err := st.Recv()
		if err != nil {
			return err
		}
		p.halfRTT()
		if resp.CompactRevision != 0 {
			r.fail(dataLoss("the backend compacted its history (revision %d) before this instance could verify it", resp.CompactRevision))
			return nil
		}
		if resp.Canceled {
			return fmt.Errorf("watch canceled: %s", resp.CancelReason)
		}
		if h := resp.Header; h != nil {
			if cur := r.current(); h.Revision < cur {
				r.fail(dataLoss("backend went back in time (it reports revision %d, revision %d was already verified)", h.Revision, cur))
				return nil
			}
			p.fresh.observe(h.Revision)
		}
		for i := 0; i < len(resp.Events); {
			j := i
			rev := resp.Events[i].Kv.ModRevision
			for j < len(resp.Events) && resp.Events[j].Kv.ModRevision == rev {
				j++
			}
			if err := r.apply(rev, resp.Events[i:j]); err != nil {
				r.fail(err)
				return nil
			}
			i = j
		}
	}
}

// latestLocked returns the current live version of a key.
func (r *replica) latestLocked(key string) (version, bool) {
	vs := r.keys[key]
	if len(vs) == 0 || vs[len(vs)-1].deleted {
		return version{}, false
	}
	return vs[len(vs)-1], true
}

func (r *replica) latest(key string) (version, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.latestLocked(key)
}

// atLocked returns the live version of a key at revision rev.
func (r *replica) atLocked(key string, rev int64) (version, bool) {
	vs := r.keys[key]
	i := sort.Search(len(vs), func(i int) bool { return vs[i].modRev > rev }) - 1
	if i < 0 || vs[i].deleted {
		return version{}, false
	}
	return vs[i], true
}

// apply verifies all events of one revision and then applies them atomically.
func (r *replica) apply(rev int64, evs []*mvccpb.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.loaded {
		return errors.New("replica not loaded")
	}
	if rev != r.rev+1 {
		return dataLoss("revision gap: expected %d, the backend sent %d (withheld changes)", r.rev+1, rev)
	}

	type item struct {
		key string
		ev  *mvccpb.Event
	}
	receipts := map[string]int64{}
	var items []item
	for _, ev := range evs {
		key, err := r.s.decKey(string(ev.Kv.Key))
		if err != nil {
			return dataLoss("revision %d: key %q: %v", rev, ev.Kv.Key, err)
		}
		if key != receiptKey {
			items = append(items, item{key, ev})
			continue
		}
		if ev.Type != mvccpb.PUT {
			return dataLoss("revision %d: delete receipt was deleted", rev)
		}
		payload, _, _, err := r.s.openRecord(key, ev.Kv.Value)
		if err != nil {
			return dataLoss("revision %d: delete receipt: %v", rev, err)
		}
		entries, err := parseReceipt(payload)
		if err != nil {
			return dataLoss("revision %d: delete receipt: %v", rev, err)
		}
		for k, p := range entries {
			receipts[k] = p
		}
	}

	changes := make([]change, 0, len(items))
	for _, it := range items {
		prev, had := r.latestLocked(it.key)
		var cur version
		switch it.ev.Type {
		case mvccpb.PUT:
			payload, pred, lease, err := r.s.openRecord(it.key, it.ev.Kv.Value)
			if err != nil {
				return dataLoss("revision %d: value of %q: %v", rev, it.key, err)
			}
			want := int64(0)
			if had {
				want = prev.modRev
			}
			if pred != want {
				return dataLoss("revision %d: %q was written as successor of revision %d, but the current version is %d (replayed or reordered write)", rev, it.key, pred, want)
			}
			cur = version{modRev: rev, createRev: rev, ver: 1, lease: lease, value: payload}
			if had {
				cur.createRev, cur.ver = prev.createRev, prev.ver+1
			}
			if it.ev.Kv.Lease != lease || it.ev.Kv.CreateRevision != cur.createRev || it.ev.Kv.Version != cur.ver {
				return dataLoss("revision %d: forged metadata for %q", rev, it.key)
			}
		case mvccpb.DELETE:
			if !had {
				return dataLoss("revision %d: delete of %q, which does not exist", rev, it.key)
			}
			p, ok := receipts[it.key]
			switch {
			case ok && p == prev.modRev:
				delete(receipts, it.key)
			case !ok && prev.lease != 0:
				// lease expiry or revocation, carried out by the backend
			default:
				return dataLoss("revision %d: delete of %q without a valid receipt (forged delete)", rev, it.key)
			}
			cur = version{modRev: rev, deleted: true}
		}
		var pp *version
		if had {
			c := prev
			pp = &c
		}
		changes = append(changes, change{key: it.key, cur: cur, prev: pp})
	}
	if len(receipts) > 0 || len(changes) == 0 {
		return dataLoss("revision %d: delete receipt without matching delete", rev)
	}

	for _, c := range changes {
		if c.prev != nil {
			r.digest.Sub(r.digest, r.entryHash(c.key, *c.prev))
		}
		if !c.cur.deleted {
			r.digest.Add(r.digest, r.entryHash(c.key, c.cur))
		}
		if _, known := r.keys[c.key]; !known {
			i := sort.SearchStrings(r.order, c.key)
			r.order = append(r.order, "")
			copy(r.order[i+1:], r.order[i:])
			r.order[i] = c.key
		}
		r.keys[c.key] = append(r.keys[c.key], c.cur)
	}
	r.digest.Mod(r.digest, mod256)
	r.rev = rev
	d := r.digestBytes()
	r.hist = append(r.hist, revision{rev: rev, at: time.Now(), digest: d, changes: changes})
	if claimed, ok := r.claims[rev]; ok {
		delete(r.claims, rev)
		if claimed != d {
			return dataLoss("another instance saw a different state at revision %d: the backend shows different histories (fork)", rev)
		}
	}
	r.trimLocked()
	r.notifyLocked()
	return nil
}

// trimLocked forgets history older than the window.
func (r *replica) trimLocked() {
	cutoff := time.Now().Add(-r.window)
	n := 0
	for n < len(r.hist) && r.hist[n].at.Before(cutoff) {
		n++
	}
	if n == 0 {
		return
	}
	dropped := r.hist[:n]
	r.base, r.baseDigest = dropped[n-1].rev, dropped[n-1].digest
	r.hist = append([]revision(nil), r.hist[n:]...)
	for _, h := range dropped {
		for _, c := range h.changes {
			vs := r.keys[c.key]
			// keep the newest version <= base (the state at base) and everything after
			i := sort.Search(len(vs), func(i int) bool { return vs[i].modRev > r.base }) - 1
			if i < 0 {
				continue
			}
			switch {
			case len(vs)-i == 1 && vs[i].deleted:
				delete(r.keys, c.key)
				if i := sort.SearchStrings(r.order, c.key); i < len(r.order) && r.order[i] == c.key {
					r.order = append(r.order[:i], r.order[i+1:]...)
				}
			case i > 0:
				r.keys[c.key] = append([]version(nil), vs[i:]...)
			}
		}
	}
	for rev := range r.claims {
		if rev <= r.base {
			delete(r.claims, rev)
		}
	}
}

// waitFor blocks until the replica has applied revision rev.
func (r *replica) waitFor(ctx context.Context, rev int64) error {
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		if err := r.err(); err != nil {
			return err
		}
		r.mu.RLock()
		cur, ch := r.rev, r.changed
		r.mu.RUnlock()
		if cur >= rev {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return status.Errorf(codes.Unavailable, "veil: the backend does not deliver revision %d (replica at %d)", rev, cur)
		}
	}
}

// ---------------------------------------------------------------- serving reads

func (r *replica) headerLocked() *pb.ResponseHeader {
	h := r.header
	h.Revision = r.rev
	return &h
}

func (r *replica) matches(kr keyRange, key string) bool {
	switch {
	case kr.all:
		return true
	case kr.single:
		return key == kr.start
	}
	return strings.HasPrefix(key, kr.prefix) && key >= kr.start
}

// serveRange answers a read at revision at (0 = latest) from the replica.
func (r *replica) serveRange(req *pb.RangeRequest, kr keyRange, at int64) (*pb.RangeResponse, error) {
	if err := r.err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.serveRangeLocked(req, kr, at)
}

func (r *replica) serveRangeLocked(req *pb.RangeRequest, kr keyRange, at int64) (*pb.RangeResponse, error) {
	if at == 0 {
		at = r.rev
	}
	if at < r.base {
		return nil, errCompacted
	}
	if at > r.rev {
		return nil, errFutureRev
	}
	var kvs []*mvccpb.KeyValue
	add := func(key string) {
		v, ok := r.atLocked(key, at)
		if !ok ||
			(req.MinModRevision > 0 && v.modRev < req.MinModRevision) ||
			(req.MaxModRevision > 0 && v.modRev > req.MaxModRevision) ||
			(req.MinCreateRevision > 0 && v.createRev < req.MinCreateRevision) ||
			(req.MaxCreateRevision > 0 && v.createRev > req.MaxCreateRevision) {
			return
		}
		kvs = append(kvs, v.kv(key, req.KeysOnly))
	}
	switch {
	case kr.single:
		add(kr.start)
	case kr.all:
		for _, key := range r.order {
			add(key)
		}
	default:
		for i := sort.SearchStrings(r.order, max(kr.prefix, kr.start)); i < len(r.order) && strings.HasPrefix(r.order[i], kr.prefix); i++ {
			add(r.order[i])
		}
	}
	if req.SortOrder == pb.RangeRequest_DESCEND {
		for i, j := 0, len(kvs)-1; i < j; i, j = i+1, j-1 {
			kvs[i], kvs[j] = kvs[j], kvs[i]
		}
	}
	resp := &pb.RangeResponse{Header: r.headerLocked(), Count: int64(len(kvs))}
	if req.CountOnly {
		return resp, nil
	}
	if req.Limit > 0 && int64(len(kvs)) > req.Limit {
		kvs, resp.More = kvs[:req.Limit], true
	}
	resp.Kvs = kvs
	return resp, nil
}

// ---------------------------------------------------------------- serving watches

// Watch serves kube-apiserver's watches from the replica's verified history.
func (p *proxy) Watch(srv pb.Watch_WatchServer) error {
	ctx, cancelAll := context.WithCancel(srv.Context())
	defer cancelAll()
	var sendMu sync.Mutex
	send := func(resp *pb.WatchResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return srv.Send(resp)
	}
	type watcher struct {
		cancel context.CancelFunc
		next   atomic.Int64 // first revision not yet delivered
	}
	var mu sync.Mutex
	watchers := map[int64]*watcher{}
	var nextID int64
	rep := p.rep

	header := func() *pb.ResponseHeader {
		rep.mu.RLock()
		defer rep.mu.RUnlock()
		return rep.headerLocked()
	}

	for {
		req, err := srv.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := rep.err(); err != nil {
			return err
		}
		switch u := req.RequestUnion.(type) {
		case *pb.WatchRequest_CreateRequest:
			cr := u.CreateRequest
			mu.Lock()
			id := cr.WatchId
			if id == 0 {
				for watchers[nextID] != nil {
					nextID++
				}
				id = nextID
				nextID++
			}
			mu.Unlock()
			kr, err := parseRange(cr.Key, cr.RangeEnd)
			if err != nil {
				send(&pb.WatchResponse{Header: header(), WatchId: id, Created: true})
				send(&pb.WatchResponse{Header: header(), WatchId: id, Canceled: true, CancelReason: err.Error()})
				continue
			}
			p.logf("Watch %q %q from rev=%d", cr.Key, cr.RangeEnd, cr.StartRevision)
			rep.mu.RLock()
			start, base := cr.StartRevision, rep.base
			if start == 0 {
				start = rep.rev + 1
			}
			rep.mu.RUnlock()
			if err := send(&pb.WatchResponse{Header: header(), WatchId: id, Created: true}); err != nil {
				return err
			}
			if start <= base {
				send(&pb.WatchResponse{Header: header(), WatchId: id, CompactRevision: base, Canceled: true,
					CancelReason: "required revision has been compacted"})
				continue
			}
			wctx, cancel := context.WithCancel(ctx)
			w := &watcher{cancel: cancel}
			w.next.Store(start)
			mu.Lock()
			watchers[id] = w
			mu.Unlock()
			go p.runWatcher(wctx, id, &w.next, kr, cr, send)

		case *pb.WatchRequest_CancelRequest:
			id := u.CancelRequest.WatchId
			mu.Lock()
			w := watchers[id]
			delete(watchers, id)
			mu.Unlock()
			if w != nil {
				w.cancel()
				send(&pb.WatchResponse{Header: header(), WatchId: id, Canceled: true})
			}

		case *pb.WatchRequest_ProgressRequest:
			// Report revision R only once every watcher on this stream has
			// delivered everything up to R, exactly what the API server relies on.
			target := rep.current()
			go func() {
				for ctx.Err() == nil {
					done := true
					mu.Lock()
					for _, w := range watchers {
						if w.next.Load() <= target {
							done = false
						}
					}
					mu.Unlock()
					if done {
						h := header()
						h.Revision = target
						send(&pb.WatchResponse{Header: h, WatchId: -1})
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
		}
	}
}

func (p *proxy) runWatcher(ctx context.Context, id int64, next *atomic.Int64, kr keyRange, cr *pb.WatchCreateRequest,
	send func(*pb.WatchResponse) error) {
	rep := p.rep
	var progress <-chan time.Time
	if cr.ProgressNotify {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		progress = t.C
	}
	noPut, noDelete := false, false
	for _, f := range cr.Filters {
		noPut = noPut || f == pb.WatchCreateRequest_NOPUT
		noDelete = noDelete || f == pb.WatchCreateRequest_NODELETE
	}
	for {
		if err := rep.err(); err != nil {
			send(&pb.WatchResponse{WatchId: id, Canceled: true, CancelReason: err.Error()})
			return
		}
		rep.mu.RLock()
		from := next.Load()
		if from <= rep.base {
			h := rep.headerLocked()
			base := rep.base
			rep.mu.RUnlock()
			send(&pb.WatchResponse{Header: h, WatchId: id, CompactRevision: base, Canceled: true,
				CancelReason: "required revision has been compacted"})
			return
		}
		i := sort.Search(len(rep.hist), func(i int) bool { return rep.hist[i].rev >= from })
		var batches [][]*mvccpb.Event
		var batch []*mvccpb.Event
		for _, h := range rep.hist[i:] {
			for _, c := range h.changes {
				if !rep.matches(kr, c.key) {
					continue
				}
				ev := &mvccpb.Event{Type: mvccpb.PUT, Kv: c.cur.kv(c.key, false)}
				if c.cur.deleted {
					ev = &mvccpb.Event{Type: mvccpb.DELETE, Kv: &mvccpb.KeyValue{Key: []byte(c.key), ModRevision: h.rev}}
				}
				if (ev.Type == mvccpb.PUT && noPut) || (ev.Type == mvccpb.DELETE && noDelete) {
					continue
				}
				if cr.PrevKv && c.prev != nil {
					ev.PrevKv = c.prev.kv(c.key, false)
				}
				batch = append(batch, ev)
			}
			if len(batch) >= 1000 { // never split a revision across responses
				batches, batch = append(batches, batch), nil
			}
		}
		if len(batch) > 0 {
			batches = append(batches, batch)
		}
		upTo, h, ch := rep.rev, rep.headerLocked(), rep.changed
		rep.mu.RUnlock()

		for _, b := range batches {
			if err := send(&pb.WatchResponse{Header: h, WatchId: id, Events: b}); err != nil {
				return
			}
		}
		next.Store(upTo + 1)
		select {
		case <-ctx.Done():
			return
		case <-ch:
		case <-progress:
			send(&pb.WatchResponse{Header: h, WatchId: id})
		}
	}
}
