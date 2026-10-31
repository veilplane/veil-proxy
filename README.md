# veil-proxy

veil-proxy is the customer-side component of Veilplane. It runs next to
kube-apiserver on every control plane node and speaks the etcd v3 gRPC API to
it. Behind it is a hosted, untrusted etcd-compatible backend. veil-proxy
encrypts every key and value before it reaches the backend and verifies every
answer the backend gives, so that the operator of the backend can neither read
cluster data nor change it unnoticed.

This document describes how veil-proxy works, which formats it uses and what
has to be kept in mind when changing it.

Status: feature complete for kube-apiserver and k3s, not externally audited.
Tested with k3s v1.33, etcd v3.5 as a stand-in backend and the Microsoft TPM
2.0 reference implementation as a simulated TPM.

## Contents

1. Overview
2. Repository layout
3. Building and running
4. Threat model
5. Cryptography and data formats
6. The verified replica
7. Request handling
8. Freshness, checkpoints and peers
9. mTLS and device identity
10. TPM
11. Operations
12. Backend contract
13. Testing
14. Continuous integration and releases
15. Working on the code
16. Known limitations
17. License

## 1. Overview

```
 control plane node (customer)                         hosted (untrusted)
 +--------------------------------------------+
 | kube-apiserver / k3s                       |
 |      | etcd v3 gRPC, plaintext, localhost  |
 |      v                                     |
 | veil-proxy ---- verified replica (memory)  |      mTLS, etcd v3 gRPC
 |      |  \______________________________________> Veilplane backend
 |      |                                     |      (sees ciphertext only)
 |      +-- TPM: device key, sealed master key|
 |      +-- state file: verified checkpoints  |
 +------|-------------------------------------+
        | mTLS: signed checkpoints
        v
   other veil-proxy instances of the same cluster
```

The proxy has three jobs:

- Confidentiality: keys and values are encrypted with a master key that only
  the customer's nodes hold. The backend stores ciphertext.
- Integrity and freshness: every instance follows the backend's complete change
  stream, checks each change and keeps a verified copy (the replica). Reads and
  watches are answered from that copy, never from backend answers.
- Consistency between instances: instances exchange signed digests of their
  state, which detects a backend that shows different histories to different
  instances.

The proxy does not protect availability. The backend can always refuse to
serve. It can not make the proxy accept false data.

## 2. Repository layout

| File | Content |
|---|---|
| `main.go` | Entry point, startup and startup verification, mTLS, cryptography, key ranges, freshness and checkpoints, peer protocol, operations endpoints, gRPC services, write path |
| `replica.go` | Verified replica: data model, verification of changes, state digest, history window, serving reads and watches |
| `tpm.go` | TPM access: storage root key, device signing key, sealed master key |
| `setup.go` | Subcommands for setting up a node (used by veilctl): `keygen`, `seal`, `sign`, `key-send`, `key-receive` |
| `tpmsim.go` | Build tag `tpmsim` only: adds the `simulator:<seed>` TPM path for tests |
| `main_test.go` | Unit tests, attack tests against a real etcd, mTLS tests, operations, load test, fuzz targets |
| `setup_test.go` | Tests of the setup subcommands without TPM, including the master key transfer and its refusals |
| `tpm_test.go` | Build tag `tpmsim` only: TPM tests with the simulator |
| `test.sh` | End-to-end test with k3s, three instances, mTLS, TPM and a rollback attack |
| `Dockerfile`, `.dockerignore` | Container image built `FROM scratch` |
| `.github/workflows/` | CI (`test.yml`) and releases (`release.yml`) |
| `LICENSE.md`, `NOTICE.md` | License of veil-proxy and of third-party code |

Each source file is divided into sections marked with a comment line of the
form `// ------------- name`. `main.go` contains, in this order: main, mTLS,
crypto, key ranges, freshness and checkpoints, operations, gRPC services.

## 3. Building and running

Requirements: Go 1.24. The TPM simulator for tests additionally needs cgo and
the OpenSSL development headers (`libssl-dev`).

```bash
go mod tidy
go build -trimpath -ldflags "-X main.buildVersion=v0.1.0" -o veil-proxy .   # production
CGO_ENABLED=0 go build -trimpath -o veil-proxy .                            # fully static
go build -tags tpmsim -o veil-proxy-tpmsim .                                # with TPM simulator, tests only
```

The production binary does not contain the simulator (`tpmsim.go` is excluded
by its build tag). Builds are reproducible: the same source and Go version give
a bit-identical binary.

### Development setup without TPM and TLS

```bash
./veil-proxy -gen-key > master.key
./veil-proxy -key-file master.key -upstream 127.0.0.1:2379 -listen 127.0.0.1:2389 -log-format text
k3s server --datastore-endpoint http://127.0.0.1:2389
```

Without `-cert` the backend connection is plaintext and the proxy logs a
warning. A hex master key file is accepted for development; production uses a
TPM-sealed key.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `127.0.0.1:2389` | Address kube-apiserver connects to (plaintext gRPC, keep it local) |
| `-upstream` | `127.0.0.1:2379` | Backend: `host:port` (every address of the name is used) or a comma separated list of `host:port` |
| `-key-file` | `master.key` | Master key: PEM `VEIL TPM SEALED` or 64 hex characters |
| `-tpm` | `/dev/tpmrm0` | TPM device, used when `-key` or `-key-file` contain TPM blobs |
| `-cert`, `-key` | | Device certificate (PEM) and its key: PEM `VEIL TPM KEY` or a PEM private key |
| `-backend-ca` | | CA bundle that signed the backend's server certificate (required with `-cert`) |
| `-backend-name` | host of `-upstream` | Server name expected in the backend certificate |
| `-peer-ca` | | CA bundle that signs device certificates (required for peers with `-cert`) |
| `-peer-listen` | | Address to serve checkpoints to other instances |
| `-peers` | | Comma separated `-peer-listen` addresses of other instances |
| `-peers-file` | | File with more peer addresses (one per line); read again whenever it changes, so instances can be added without a restart (veilctl keeps it up to date) |
| `-state-file` | `veil.state` | Where verified checkpoints are persisted |
| `-history` | `10m` | Verified history kept in memory; must exceed the API server's compaction interval (5 min by default) |
| `-ops-listen` | `127.0.0.1:9390` | `/healthz`, `/readyz`, `/metrics`; empty disables |
| `-log-format` | `json` | `json` or `text` |
| `-trust-backend` | `false` | Accept the backend state without verification (recovery only, see section 8) |
| `-version` | | Print the version and exit |
| `-gen-key` | | Print a random master key (hex) and exit |
| `-delay` | `0` | Tests only: sleep this long per backend round trip |
| `-v` | `false` | Tests only: log every request including plaintext keys |

### Setup subcommands

Production nodes are set up with [veilctl](https://github.com/veilplane/veilctl), which calls
these subcommands, so that all cryptography and TPM access stays in this program. All of them
take `-tpm <device>`; `-tpm none` uses plain files instead (development and tests only).

```bash
veil-proxy keygen -out node.tpmkey -csr node.csr [-uri spiffe://...] [-ip ...] [-dns ...]
veil-proxy seal -new -out master.sealed            # new random master key, sealed by the TPM
veil-proxy seal -in master.hex -out master.sealed  # seal an existing hex key
veil-proxy sign -key node.tpmkey < request.json    # base64 ECDSA-SHA256 (DER) signature
veil-proxy key-send -cert node.pem -key node.tpmkey -peer-ca device-ca.pem \
  -secret-file secret -key-file master.sealed -listen :2391 -timeout 1h
veil-proxy key-receive -cert node.pem -key node.tpmkey -peer-ca device-ca.pem \
  -secret-file secret -key-file master.sealed -from 10.0.0.5:2391
```

`tpm-keygen` and `tpm-seal` are kept as old names of `keygen` and `seal`.

### Master key transfer

A new node of a cluster gets the master key directly from an existing node, never through
the backend (`key-send` on the existing node, `key-receive` on the new one, see `setup.go`).
The invite code that veilctl prints contains a random 32-byte secret that the backend never
sees. Both sides authenticate with their device certificates (verified against the device
CA, same trust domain and cluster). Because the hoster runs the device CA and could issue
itself a certificate, the transfer is additionally bound to the secret:

```
auth key, enc key = HKDF-SHA256(secret, "veil key transfer v1 auth" / "... enc")
request:  {node, nonce, mac = HMAC(auth key, "veil key request" | nonce | node | fp)}
response: {nonce', box = AES-256-GCM(enc key, nonce', master key, aad = "veil key transfer" | nonce | fp)}
```

`fp` is the SHA-256 of the requester's certificate as seen in the TLS handshake, so an
answer is only usable on that connection. The sender hands the key out once and exits; five
requests with a wrong secret also make it stop. The receiver seals the key with its own TPM.

## 4. Threat model

Trusted:

- The customer's control plane nodes, including root on them, the TPM and the
  code of veil-proxy itself. veil-proxy does not try to protect against the
  customer.
- The master key, which only exists on customer nodes (sealed by their TPMs).
- The CAs configured with `-backend-ca` and `-peer-ca`.

Untrusted:

- The backend and everything between proxy and backend. The backend may read
  and write its storage arbitrarily, delay, reorder, replay or withhold
  messages, answer differently to different instances, and restore old
  backups.

Goals:

- The backend learns nothing about keys and values except what section 16 lists
  (structure, counts, sizes, timing).
- Any deviation of the backend from an honest etcd that could change what the
  API server sees is detected, and the affected instance stops serving.

Non-goals:

- Availability. The backend can stop serving at any time.
- Protection of the worker nodes or of workloads. That is not the proxy's job.
- Protection against a compromised customer node.

## 5. Cryptography and data formats

### Key hierarchy

The 32-byte master key is the only long-term secret. All working keys are
derived with HKDF-SHA256, salt empty, info `"veil-proxy v1 " + purpose`:

| Purpose string | Length | Used for |
|---|---|---|
| `segment aes-siv` | 64 bytes | AES-256-SIV for key segments |
| `value aes-gcm` | 32 bytes | AES-256-GCM for values |
| `peer hmac` | 32 bytes | HMAC-SHA256 over checkpoints exchanged between instances |
| `state digest` | 32 bytes | HMAC-SHA256 key of the replica's state digest |

All instances of a cluster must use the same master key. Because the key
encryption is deterministic, they then produce identical ciphertext keys; this
is what lets any number of instances work against the same backend without
coordination.

### Keys

etcd keys are paths such as `/registry/pods/default/nginx`. The proxy splits a
key at `/`, encrypts every non-empty segment on its own and joins the results
with `/`. Empty segments (a leading `/`, `//`, a trailing `/`) stay empty.

For a segment `s` with plaintext parent path `p` (all segments before it,
joined with `/`):

```
ciphertext = AES-256-SIV(key = segment key, plaintext = pad(s, 32), associated data = p)
segment    = base64url(ciphertext), no padding, strict decoding
```

Properties this gives, and which the rest of the code relies on:

- Determinism: the same key always encrypts to the same ciphertext.
- Prefix preservation: the encryption of `/registry/pods/default/` is a prefix
  of the encryption of every key below it. Prefix scans therefore work on the
  backend.
- Context binding: the same name under different parents gives different
  ciphertext, so equal names in different namespaces are not linkable, and a
  segment moved under another parent fails authentication.
- One spelling per key: decoding is strict (`base64.RawURLEncoding.Strict()`),
  so a backend cannot create a second ciphertext key that decrypts to the same
  plaintext key.

AES-SIV comes from Google Tink (`github.com/tink-crypto/tink-go/v2/daead/subtle`,
RFC 5297, 512-bit key as Tink requires).

Prefix scans are only possible on whole segments. `/registry/pods/` and
`/bootstrap` work; a scan for `/registry/po` cannot be expressed.

### Values (records)

Every value is stored as a record:

```
plaintext = prev (8 bytes, big endian) | lease (8 bytes, big endian) | payload
stored    = 0x03 | nonce (12 bytes) | AES-256-GCM(value key, nonce, pad(plaintext, 128), associated data = plaintext key)
```

- `0x03` is the format version (`valueVersion`).
- `prev` is the mod revision of the version this write replaces (0 for a
  create). It is the basis of replay detection (section 6).
- `lease` is the lease the write was made with; it must match the lease the
  backend reports.
- The associated data binds a value to its key, so values cannot be moved
  between keys.

### Padding

`pad(b, min)` appends `0x80` and zero bytes (ISO/IEC 7816-4) up to
`max(min, padme(len(b)+1))`. Padmé (Nikitin et al., 2019) rounds lengths so
that at most O(log log n) bits of the length remain visible, with at most
about 12% overhead. Minimum sizes are 32 bytes for key segments and 128 bytes
for value records. Padding is deterministic, which key segments require.

### Delete receipts

A delete has no value that could carry `prev`. Therefore every transaction
that deletes keys also writes a receipt to the reserved key
`/veil/delete-receipt`:

```
receipt payload = repeated: prev (8 bytes) | key length (4 bytes) | plaintext key
```

The payload is stored as a normal record (with prev = 0, lease = 0) under the
encrypted receipt key. It lists each deleted key with the mod revision it had.
Deletes of keys that do not exist need no receipt. The receipt key is never
shown to clients and keys below `/veil/` cannot be written by clients.

`/veil/read-index` is another reserved key. It is never written; a count-only
range on it is the cheapest way to ask the backend for its current revision.

### TPM blobs

Both TPM-protected secrets are stored as PEM:

```
-----BEGIN VEIL TPM KEY-----      (or VEIL TPM SEALED)
base64( len(public) (2 bytes) | TPM2B_PUBLIC | TPM2B_PRIVATE )
-----END VEIL TPM KEY-----
```

The private part is encrypted by the TPM under its storage root key and can
only be loaded by the same TPM.

## 6. The verified replica

`replica.go`. Every instance keeps the complete decrypted key space in memory
plus a window of history.

### Data model

| Field | Meaning |
|---|---|
| `keys map[string][]version` | All versions per plaintext key, ascending by mod revision. A delete is stored as a tombstone (`deleted: true`). |
| `order []string` | All keys of the map, sorted. Prefix scans are a binary search plus a linear walk. |
| `hist []revision` | Revisions in `(base, rev]`, each with its changes and the digest after it |
| `rev` | Last applied revision |
| `base` | Oldest revision whose state is fully known. Reads below it fail with "compacted". |
| `digest` | Keyed set hash of the state at `rev` |
| `claims` | Digests other instances reported for revisions not yet reached |

A version has `modRev`, `createRev`, `ver` (etcd's per-key version counter),
`lease` and `value`.

### Following the backend

`follow` / `followOnce` open one watch on the whole key space (`\x00` to
`\x00`) starting at `rev + 1`, with progress notifications. Events of one
revision are grouped and passed to `apply`. Before that, the response header's
revision must not be lower than `rev` (rollback). A compaction response from
the backend makes the replica fail: the history it needed is gone. Any other
interruption reconnects after one second, continuing at `rev + 1`.

### Verification rules (`apply`)

`apply(rev, events)` first verifies all events of a revision without changing
anything, then applies them together.

1. Gap-free: `rev` must be exactly the last applied revision plus one. Every
   etcd revision contains at least one change, so a missing revision means a
   withheld change.
2. Every event key must decrypt (authentication of every segment).
3. Delete receipts in the revision are decrypted and collected.
4. For a put of key `k`:
   - the value must decrypt with `k` as associated data;
   - the record's `prev` must equal the current mod revision of `k`, or 0 if
     `k` does not exist. This is what catches a replayed old ciphertext: its
     `prev` points to an older state;
   - the event's lease must equal the record's lease;
   - create revision and version must follow from the previous state
     (`createRev` = previous createRev or `rev` for a create, `ver` = previous
     ver + 1 or 1).
5. For a delete of key `k`:
   - `k` must exist;
   - either a receipt in the same revision lists `k` with its current mod
     revision, or `k` is attached to a lease (lease expiry and revocation are
     carried out by the backend and cannot carry a receipt).
6. Every receipt entry must be used by a delete, and the revision must contain
   at least one change.
7. After applying, if another instance claimed a digest for this revision, it
   must equal ours (fork detection).

On any violation the replica fails permanently (`fail`). From then on every
request returns gRPC `DataLoss` with the reason, `/readyz` returns 503 and
`veil_replica_failed` is 1. There is no automatic recovery: the backend has
been caught lying or losing data, and a human has to decide what happens.

### State digest

```
entry(k, v) = HMAC-SHA256(digest key, modRev | createRev | ver | lease | SHA256(value) | k)   (integers 8 bytes big endian)
digest      = sum of entry(k, v) over all live keys, modulo 2^256
```

The digest can be updated per change (subtract the old entry, add the new
one) and equals a full recomputation (`TestDigestIncrementalEqualsFull`). It is
keyed, so the backend can neither compute it nor steer it towards collisions.
It covers metadata as well as values, so two replicas with the same digest at
the same revision hold the same state.

A digest is recorded for every revision in the history window and for `base`.

### History window

`trimLocked` drops revisions older than `-history` (default 10 minutes). For
every key changed in a dropped revision it keeps the newest version at or
below the new `base` and everything after it; a key whose only remaining
version is a tombstone is removed from `keys` and `order`. Watches and reads
need history back to the oldest revision the API server may ask for, which is
why `-history` has to be longer than the API server's compaction interval.

### Snapshot loading (`load`)

`load(rev)` reads the backend's whole key space at revision `rev` (0 = latest)
and replaces the replica with it, with `base = rev`. Each entry must decrypt
and be internally consistent (`lease` matches, `prev < modRev`,
`createRev <= modRev`). Whether the snapshot is genuine is decided by the
caller, which compares the resulting digest with a checkpoint (section 8).

## 7. Request handling

### Reads (`Range`)

All reads are answered by `replica.serveRange`:

- `revision > 0`: wait until the replica has applied that revision, then read
  at it. Revisions below `base` fail with etcd's "required revision has been
  compacted" error, which the API server handles like real etcd.
- `revision = 0`, linearizable (default): first a read index. The proxy asks
  the backend for its current revision with a count-only range on
  `/veil/read-index` and waits until the replica has applied that revision.
  This guarantees that the read reflects every write completed before it
  started, like etcd's linearizable reads.
- `revision = 0`, serializable: answered from the replica immediately.

`waitFor` gives up after 5 seconds with `Unavailable`. Results are returned in
plaintext key order with etcd's semantics for `limit`, `more`, `count`,
`keys_only`, `count_only`, min/max mod and create revision filters and
descending sort by key. Plaintext order matters: the API server mixes pages
served from its watch cache with pages served by etcd.

Supported key ranges (`parseRange`): a single key, the whole key space
(`\x00`, `\x00`), and a prefix scan on segment boundaries starting at the
prefix or at a key inside it (pagination continues at `lastKey + "\x00"`).

### Writes (`Put`, `DeleteRange`, `Txn`)

`Put` and `DeleteRange` are turned into transactions; everything goes through
`txn`:

1. Shape checks. Unsupported (returns `Unimplemented`): range compares, value
   compares, range deletes, nested transactions, writes in the failure branch,
   `ignore_value` / `ignore_lease`. Writes to `/veil/` are rejected.
2. Pins. Every written key needs the mod revision it replaces. kube-apiserver
   already compares `ModRevision(key) == X` on every write; that `X` is used.
   For keys without such a compare the proxy adds one, taking the revision from
   the replica.
3. The encrypted transaction is built: compares with encrypted keys, puts as
   records with `prev` = pin, deletes, and a delete receipt for every deleted
   key whose pin is not 0.
4. It is sent to the backend (`forward`, which checks freshness).
5. The proxy waits until the replica has applied the response revision `H`,
   then `checkTxn` checks the backend's verdict against the replica:
   - Did this transaction create revision `H`? Only if `H` exists in the
     history and changed one of the written keys.
   - Success: all compares (original and added) must hold at `H - 1` if the
     transaction wrote, otherwise at `H`; every put must be visible at `H` with
     the written value and lease; every delete of an existing key must have
     removed it. Otherwise the backend lied.
   - Failure: at least one compare must be false at `H`. If all hold, the
     backend lied. If only compares added by the proxy are false, the replica
     was behind and the transaction is retried (up to 50 times).
6. The response returned to the client is built from the replica (range
   results at `H`, previous key-values at `H - 1`), never from backend output.

Writes therefore cost one backend round trip plus the time until the change
arrives on the watch stream.

### Watches (`Watch`)

Watches are served from the replica's history (`Watch`, `runWatcher` in
`replica.go`), not proxied:

- Each watch gets its own goroutine that reads matching changes from `hist`
  starting at its next revision, sends them in batches of up to 1000 events
  without splitting a revision, and then waits for the next change.
- `prev_kv`, `NOPUT` / `NODELETE` filters and progress notifications (every 10
  minutes when requested) are supported.
- A start revision at or below `base` results in a canceled watch with
  `CompactRevision` set, as in etcd.
- A progress request (`WatchRequest_ProgressRequest`) is answered with
  `WatchId = -1` and revision `R` only after every watch on the stream has
  delivered everything up to `R`. kube-apiserver relies on exactly this to know
  that its watch cache is current.

### Leases, maintenance, cluster

- Lease calls are forwarded with freshness checks. `LeaseTimeToLive` decrypts
  the attached keys. `LeaseKeepAlive` is a proxied stream; its response
  revisions must not go backwards.
- `Status` and `Alarm` are forwarded. `Defragment`, `MoveLeader`, `Downgrade`
  are rejected (`PermissionDenied`), `Hash`, `HashKV`, `Snapshot` are
  `Unimplemented`: these are operations of the backend operator.
- `MemberList` returns the proxy itself as the only member, so etcd clients
  that sync endpoints never bypass the proxy. Member changes are rejected.
- `Compact` first records the digest at the compaction revision as anchor
  (section 8). It refuses revisions outside the verified history.

## 8. Freshness, checkpoints and peers

### Freshness rule

`freshness` keeps the floor: the highest backend revision seen. For every
backend call, the floor is read before sending; the response's revision must
be at least that value (`check`). Comparing with the floor taken before the
request avoids false alarms when responses overtake each other. The floor rises
with every response, with every revision the replica applies and with every
checkpoint received from a peer. A violation fails the request with
`DataLoss` ("backend went back in time").

### Checkpoints and the state file

A checkpoint is a revision and the replica's digest at it. The state file
(`-state-file`) holds two:

```
latest <revision> <digest hex>
anchor <revision> <digest hex>
```

- `latest` is the last verified state, written every second and on shutdown,
  atomically (temporary file and rename).
- `anchor` is the digest at the last compaction revision this instance
  forwarded. The backend keeps history from the compaction revision on, so the
  anchor stays verifiable even after a long outage, when `latest` has been
  compacted away.

The file is not secret (the backend knows revisions, and the digest is keyed).
It must be on persistent storage. Losing it is not data loss but means the
instance needs a peer to start against a non-empty backend.

### Peer protocol

Instances serve their checkpoints over HTTP(S) on `-peer-listen`:

```
GET /checkpoint      ->  "<revision> <digest hex> <signature hex>\n"   (latest)
GET /digest?rev=N    ->  same format for revision N, 404 if outside the window
signature = hex(HMAC-SHA256(peer key, "veil-proxy checkpoint <revision> <digest hex>"))
```

Every second each instance fetches `/checkpoint` from all configured peers
(`pull`, 2 second timeout, in parallel). A valid checkpoint raises the floor
and is handed to `replica.claim`: if the replica has a digest for that
revision, it must match; if the revision lies ahead, it is stored and checked
when reached. A replica that has failed keeps serving its last verified
checkpoint, because that is exactly what other instances need to detect the
same problem.

Peers do not need to form a full mesh. A connected graph is enough: an instance
between two diverging histories necessarily disagrees with at least one of
them. With mTLS, peers are authenticated by device certificate and cluster id
(section 9); the HMAC additionally protects the content.

### Startup verification (`verifyAndLoad`)

1. Read `latest` and `anchor` from the state file and fetch the checkpoints of
   all reachable peers.
2. Try the candidates in descending revision order: load the backend's
   snapshot at that revision and compare digests.
   - "compacted": try the next, older candidate.
   - "future revision": the backend is behind a verified revision. The replica
     fails ("backend went back in time").
   - digest mismatch: the replica fails (forged or forked history).
   - match: verified. The replica then follows the change stream from there and
     verifies every change up to the present.
3. No candidate could be verified (none exists, or all were compacted):
   - `-trust-backend`: the current backend state is accepted unverified;
   - no state file: only an empty backend is accepted (first start of a new
     cluster); a backend that holds data makes the replica fail;
   - state file present: the replica fails.

Infrastructure errors (backend unreachable) are retried every second.

Recovery after a deliberate restore of a backend backup: all instances will
refuse it. Delete the state files on all instances and start one instance with
`-trust-backend`, then the others with that instance as peer.

## 9. mTLS and device identity

With `-cert` the backend connection uses TLS 1.3 with a client certificate. The
device identity is a URI SAN in the certificate:

```
spiffe://<trust-domain>/cluster/<cluster-id>/node/<node-name>
```

`identityOf` extracts it; startup fails without it. The backend uses the
cluster id to route the connection to the customer's own emulated etcd. The
proxy never sends a tenant id itself.

Three TLS configurations exist (`newTLSSetup`):

- backend client: roots from `-backend-ca`, server name from `-backend-name`
  or the host of the (first) `-upstream` address;
- peer server: requires a client certificate from `-peer-ca` with the same
  trust domain and cluster id;
- peer client: verifies the peer's certificate chain against `-peer-ca` and the
  same cluster check. It does not match host names: the backend issues device
  certificates with the `spiffe://` URI as the only name, so the identity is the
  URI, not the address.

Device certificates therefore need the extended key usages `clientAuth` and
`serverAuth`.

`certSource` reloads certificate and key when their files change, so
short-lived certificates can be rotated without restart. If a reload fails
(for example during a half-finished rotation) the previous pair stays in use.

## 10. TPM

`tpm.go` uses `github.com/google/go-tpm` (TPM 2.0 "direct" API).

- Storage root key: re-created on every start with the standard ECC P-256 SRK
  template (`tpm2.ECCSRKTemplate`) under the owner hierarchy. The same template
  always gives the same key on the same TPM; it is never stored.
- Device key: ECDSA P-256 signing key under the SRK, attributes `fixedTPM`,
  `fixedParent`, `sensitiveDataOrigin`, `userWithAuth`, `sign`, `noDA`. The
  private key never leaves the TPM. `tpmSigner` implements `crypto.Signer`;
  it only signs SHA-256 digests, which is what TLS 1.3 with P-256 and CSR
  signing use. On certificate rotation the old key handle is flushed.
  `certSource` checks that the certificate's public key equals the TPM key.
- Master key: sealed as a keyed-hash data object under the SRK, attributes
  `fixedTPM`, `fixedParent`, `userWithAuth`, `noDA`, no authorization value and
  no PCR policy. Unsealing happens once at startup.

There is deliberately no PCR (measured boot) binding: it would break on every
kernel or firmware update and on arbitrary distributions. The protection is
that blobs are useless on any other machine (copied disks, backups). Root on
the node itself can use the TPM; that is the customer.

TPM commands are serialized with a mutex. The device is opened lazily on first
use and closed on shutdown.

For tests, `tpmsim.go` (build tag `tpmsim`) routes the TPM path
`simulator:<seed>` to the Microsoft TPM 2.0 reference implementation from
`github.com/google/go-tpm-tools/simulator`. With a fixed seed the simulated TPM
derives the same SRK in every process, so a blob created by `keygen` in one
process can be loaded by a later proxy process. Different seeds behave like
different machines. The simulator allows only one open instance per process.

## 11. Operations

### Endpoints (`-ops-listen`)

| Path | Meaning |
|---|---|
| `/healthz` | 200 while the process runs. Stays 200 after a detected attack, because a restart would not help. |
| `/readyz` | 200 when the replica is loaded, verified and the gRPC server is serving. 503 during startup and after a detected attack, with the reason in the body. |
| `/metrics` | Prometheus text format |

Metrics:

| Metric | Type | Meaning |
|---|---|---|
| `veil_build_info{version}` | gauge | Always 1 |
| `veil_replica_failed` | gauge | 1 after a detected violation. Alert on this. |
| `veil_replica_revision` | gauge | Last verified revision |
| `veil_replica_base_revision` | gauge | Oldest revision readable from the history window |
| `veil_replica_tracked_keys` | gauge | Keys in the replica, including tombstones within the window |
| `veil_backend_floor_revision` | gauge | Highest backend revision seen |
| `veil_watch_streams` | gauge | Open watch streams from the API server |
| `veil_grpc_requests_total{method,code}` | counter | gRPC requests by method and status code |

### Logging

`log/slog` with JSON (default) or text output on stderr. The standard `log`
package is routed through slog. Every line carries the version. Plaintext keys
are only logged with `-v`.

### Lifecycle

On SIGINT or SIGTERM the gRPC server stops gracefully (at most 5 seconds,
because watches never end on their own), a final checkpoint is written, and the
backend connection and the TPM are closed. The backend connection uses gRPC
keepalive (30 s interval, 10 s timeout) so that a dead connection is noticed
and the watch is re-established.

### Running

The proxy must not run inside the Kubernetes cluster it serves: the API server
cannot start without it, and without the API server the pod would not be
started. Run it as a systemd service or a container directly on the node, and
point k3s at it with `--datastore-endpoint http://127.0.0.1:2389`.

systemd:

```ini
[Unit]
Description=Veilplane proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/veil-proxy \
  -upstream backend.veilplane.com:443 -listen 127.0.0.1:2389 \
  -tpm /dev/tpmrm0 -key-file /var/lib/veil/master.sealed \
  -cert /var/lib/veil/node.pem -key /var/lib/veil/node.tpmkey \
  -backend-ca /etc/veil/server-ca.pem -peer-ca /etc/veil/device-ca.pem \
  -state-file /var/lib/veil/state \
  -peer-listen 0.0.0.0:2390 -peers 10.0.0.2:2390,10.0.0.3:2390 \
  -ops-listen 127.0.0.1:9390
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
StateDirectory=veil
ReadWritePaths=/var/lib/veil
DeviceAllow=/dev/tpmrm0 rw

[Install]
WantedBy=multi-user.target
```

Docker: the image is `FROM scratch` (only the static binary and the license
texts) and runs as user 65532.

```bash
docker build --build-arg VERSION=v0.1.0 -t veil-proxy:v0.1.0 .
sudo install -d -o 65532 -g 65532 -m 700 /var/lib/veil

docker run -d --name veil-proxy --restart unless-stopped --network host \
  --device /dev/tpmrm0 --group-add "$(getent group tss | cut -d: -f3)" \
  -v /var/lib/veil:/var/lib/veil -v /etc/veil:/etc/veil:ro \
  veil-proxy:v0.1.0 \
  -upstream backend.veilplane.com:443 -tpm /dev/tpmrm0 \
  -key-file /var/lib/veil/master.sealed -cert /var/lib/veil/node.pem -key /var/lib/veil/node.tpmkey \
  -backend-ca /etc/veil/server-ca.pem -peer-ca /etc/veil/device-ca.pem \
  -state-file /var/lib/veil/state -peer-listen 0.0.0.0:2390 -peers 10.0.0.2:2390,10.0.0.3:2390
```

- `--network host`: k3s on the host connects to `127.0.0.1:2389`, and peers
  must reach each other.
- The volume for `/var/lib/veil` is required: without the state file a new
  container has no checkpoint of its own.
- The TPM blobs are bound to the host's TPM, not to the container, so
  containers can be recreated freely.
- `docker stop` sends SIGTERM and waits 10 seconds by default, enough for the
  graceful shutdown.

## 12. Backend contract

Any backend works that behaves like a single etcd v3 cluster per tenant:

- etcd v3 gRPC: KV (Range, Txn, Put, DeleteRange, Compact), Watch (including
  progress notifications and watches over the whole key space), Lease,
  Maintenance.Status.
- Revisions: one strictly increasing counter per tenant; every revision
  contains at least one change; all events of a revision delivered in one watch
  response.
- History: keep history from the last compaction revision on; reads at older
  revisions answer etcd's "compacted" error, reads at future revisions etcd's
  "future revision" error. Compaction should only be done when the proxy asks
  for it.
- TLS 1.3 with required client certificates; the tenant is the cluster id from
  the `spiffe://` URI SAN. The backend should additionally keep a list of
  allowed devices per tenant so that a device can be revoked before its
  certificate expires.
- Request size: at least 2 MB (Kubernetes objects up to 1.5 MB plus padding).
- Allow gRPC client keepalive pings every 30 seconds.

Any deviation is detected by the proxy, so a buggy backend shows up as
`DataLoss` errors, not as silent corruption.

### Several backend instances

The backend may consist of several instances that share one state. `-upstream`
can name all of them, either as one DNS name with several addresses
(`backend.veilplane.com:443`, resolved again whenever a connection fails) or as
a list (`10.0.0.1:2379,10.0.0.2:2379`). The proxy spreads its calls over all
reachable instances (gRPC `round_robin`, see `backendTarget`); a failed instance
drops out and is retried with a backoff of at most 3 seconds. The instances must
behave as one: a write committed through one instance is visible to reads and
watches through all others. The watch stream may sit on a different instance
than the writes; the proxy waits until its replica has applied the revision of
its own write, so a backend that is slow to pass revisions between instances
makes writes slow, not wrong.

Responses from the backend may be up to 2 GB (`maxBackendMessage`), so loading
a large key space in one `Range` works.

## 13. Testing

```bash
go test .                                                     # unit tests, load test, fuzz seed corpus
E2E_ETCD_DIR=/path/to/etcd-release go test -race -v .         # + attacks and mTLS against a real etcd
E2E_ETCD_DIR=/path/to/etcd-release go test -tags tpmsim -v .  # + TPM tests with the simulator
go test -run '^$' -fuzz '^FuzzDecKey$' -fuzztime 5m .         # fuzzing, one target at a time
go build -tags tpmsim -o veil-proxy-tpmsim .
ETCD_DIR=/path/to/etcd-release K3S_BIN=/path/to/k3s ./test.sh [30ms]   # end-to-end, needs root for k3s
```

What is covered:

| Area | Tests |
|---|---|
| Cryptography | Padmé values, padding round trip, determinism, prefix preservation, linkability, hidden lengths, tampering, canonical ciphertext keys, receipt format |
| Replica rules | Valid history, replayed value, forged delete, replayed receipt, lease expiry, gaps, forged metadata, receipt without delete, digest consistency, fork claims, history trimming, compare evaluation |
| Checkpoints | Persistence, peer exchange, forged peer checkpoints, rollback rule |
| Against etcd (`E2E_ETCD_DIR`) | Two instances, replayed value, forged delete, new instance without checkpoint, fork with two backends, mTLS (valid, foreign CA, no certificate, untrusted server, other cluster as peer), operations endpoints and shutdown |
| TPM (`-tags tpmsim`) | Seal and unseal, binding to one TPM, tampered blobs, TPM-backed TLS key, mTLS with TPM key and sealed master key against etcd |
| Scale | 100,000 keys: apply, list one namespace, count all |
| Fuzzing | `FuzzDecKey` (also checks canonical form), `FuzzOpenRecord`, `FuzzParseReceipt`, `FuzzParseRange`, `FuzzParseCheckpoint`, `FuzzDecodeTPMBlob` |
| End-to-end (`test.sh`) | k3s on the proxy with mTLS and TPM keys: objects, controllers, pagination, watch, updates, cascading deletes, nothing readable in etcd, second instance, rollback attack against three instances including a new and a restarted one |

The attack tests play the malicious backend by writing to etcd directly with a
plain gRPC client.

## 14. Continuous integration and releases

`.github/workflows/test.yml` runs on pushes to `main`, on pull requests and as a
reusable workflow from the release: lint (module verification, tidy check,
gofmt, vet for both build variants, license headers), unit tests with race
detector, integration tests with etcd and the TPM simulator, 60 seconds of
fuzzing per target, the end-to-end test with k3s, and a Docker build for amd64
and arm64 with a smoke test.

`.github/workflows/release.yml` runs on version tags. Versions follow Go module
conventions (semantic versioning with a `v` prefix):

```bash
git tag v1.2.3 && git push origin v1.2.3
git tag v1.3.0-rc.1 && git push origin v1.3.0-rc.1
```

The workflow checks the tag format, runs all tests, builds the image for
linux/amd64 and linux/arm64 with SBOM and build provenance, pushes it to
`ghcr.io/<owner>/veil-proxy` and signs it with Sigstore (keyless, GitHub OIDC).
Image tags: `vX.Y.Z` always; `vX.Y`, `vX` and `latest` for stable releases only;
no `v0` tag. All actions are pinned to commit SHAs.

Verifying an image:

```bash
cosign verify ghcr.io/<owner>/veil-proxy:v1.2.3 \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 15. Working on the code

### Invariants

These properties are what the security rests on. A change that breaks one of
them breaks the product, even if all functional tests pass.

1. Nothing returned to a client comes from a backend answer directly. Reads,
   watches and transaction results come from the replica; backend answers are
   only compared with it.
2. The replica only changes in `apply` (verified changes) and `load` (a
   snapshot that the caller verifies against a checkpoint, or accepts under the
   explicit first-start and `-trust-backend` rules).
3. Every value written carries the correct `prev`, and every write is pinned by
   a mod revision compare on the backend. Otherwise honest writes fail
   verification or replays become possible.
4. Every delete of an existing key without a lease is accompanied by a receipt
   in the same transaction.
5. Key encryption stays deterministic and canonical: one plaintext key, exactly
   one ciphertext key, identical on all instances.
6. A failed replica never recovers by itself.
7. Every backend call goes through `forward` (or applies the same freshness
   check).

### Adding support for a new request type

Decide first whether it reads or writes. Reads must be answered from the
replica. Writes must go through `txn` so that pins, `prev` and receipts are
added and the result is checked. If the request cannot be expressed that way,
return `Unimplemented` rather than forwarding it. Add a test that runs it
through two proxy instances against etcd (see
`TestAttackNormalOperationTwoInstances`) and, if it changes data, a test in
which the backend misbehaves.

### Changing a format

Key encryption, records, receipts, the digest and the checkpoint signature are
persisted or shared between instances. Changing any of them affects data that
already exists and instances that run an older version:

- Records carry a version byte (`valueVersion`). A new record format needs a
  new version and reading support for the old one.
- The key encryption has no version marker. Changing it means re-encrypting
  all data, which is a migration, not a code change.
- The HKDF purpose strings include a version (`veil-proxy v1`). New derived
  keys get new purpose strings; existing ones must not change.
- Digest and checkpoint changes require that all instances of a cluster are
  updated together, or they will report each other as forks.

### Where to put tests

Pure functions and replica rules: unit tests in `main_test.go`, building events
with the `put`, `del` and `receipt` helpers and checking rejections with
`mustReject`. Behaviour against a real backend: a `TestAttack...` test using
`startEtcd` and `startProxy`. TPM: `tpm_test.go` with the `tpmsim` build tag.
New parsers of untrusted input get a fuzz target.

## 16. Known limitations

- Visible to the backend: the number of segments of every key (and with it the
  resource structure), the number of objects per prefix, the order of magnitude
  of large values, and when and how much is written.
- Keys attached to a lease (in Kubernetes mainly Events) can be deleted early by
  the backend, because lease expiry happens on the backend.
- Fork detection needs the checkpoint exchange between instances. Instances
  that cannot reach each other cannot detect different histories.
- An instance without checkpoint accepts an empty backend. A backend that shows
  an empty state to all instances at the same time can pretend a new cluster.
- Memory: every instance holds the decrypted key space in memory, roughly what
  the API server's watch cache holds. Measured with 100,000 keys: about 20 µs
  per key to apply (including decryption), 0.5 ms to list 1,000 keys.
- Not supported (not used by kube-apiserver and k3s): range deletes, value and
  range compares in transactions, writes in the failure branch, nested
  transactions, reads before writes in the same success branch.
- Not implemented yet: rotation of the master key, certificate revocation
  checks in the proxy, Kubernetes conformance tests with real worker nodes, an
  external security audit.

## 17. License

veil-proxy is licensed under the Functional Source License, Version 1.1, with
Apache 2.0 as future license (FSL-1.1-ALv2), see `LICENSE.md`. In short: use,
modification and internal production use are allowed; offering it in a
commercial product or service that competes with Veilplane is not. Each version
becomes available under the Apache License 2.0 two years after its release.

Third-party code and its licenses are listed in `NOTICE.md`. "Veilplane" is a
trademark; the license grants no rights to the name.
