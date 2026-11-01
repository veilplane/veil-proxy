#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
# End-to-end test: etcd <- veil-proxy <- k3s control plane.
#
# Usage: ETCD_DIR=/path/to/etcd-release K3S_BIN=/path/to/k3s ./test.sh [simulated-rtt]
#   e.g. ./test.sh 30ms
#
# Needs the binary: go build -o veil-proxy .
# shellcheck disable=SC2046 # $(mtls ...) is split into flags on purpose
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$HERE/.testrun}
DELAY=${1:-0s}
ETCD_DIR=${ETCD_DIR:?set ETCD_DIR to an extracted etcd release}
K3S_BIN=${K3S_BIN:?set K3S_BIN to a k3s binary}
PROXY=$HERE/veil-proxy
KC="$K3S_BIN kubectl --kubeconfig $WORK/kubeconfig"
PKI=$WORK/pki
# The hoster's view of the backend: etcd only accepts certificates from the device CA.
ETCDCTL="$ETCD_DIR/etcdctl --endpoints=https://127.0.0.1:2379 --cacert $PKI/server-ca.pem --cert $PKI/operator.pem --key $PKI/operator-key.pem"
ETCD_TLS="--cert-file $PKI/etcd.pem --key-file $PKI/etcd-key.pem --client-cert-auth --trusted-ca-file $PKI/device-ca.pem"
# mTLS flags and master key of each node
mtls() {
  echo "-cert $PKI/$1.pem -key $PKI/$1.key -key-file $PKI/$1-master.key -backend-ca $PKI/server-ca.pem"
}
PASS=0
FAIL=0

ok()   { echo "  PASS  $*"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }
stop() { for f in "$WORK"/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done; sleep 2; }
now()  { date +%s%N; }
ms()   { echo $(( ($2 - $1) / 1000000 )); }

stop
rm -rf "$WORK" && mkdir -p "$WORK" && cd "$WORK" || exit 1
[ -f "$HERE/master.key" ] || "$PROXY" -gen-key > "$HERE/master.key"
chmod 600 "$HERE/master.key"

echo "== certificates: hoster server CA, device CA, one device certificate per node"
mkdir -p "$PKI"
ca() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=$1" \
    -keyout "$PKI/$1-key.pem" -out "$PKI/$1.pem" 2> /dev/null
}
cert() { # name, issuing ca, subjectAltName (uses an existing $1.csr, e.g. from veil-proxy keygen)
  [ -f "$PKI/$1.csr" ] || openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
    -keyout "$PKI/$1-key.pem" -out "$PKI/$1.csr" 2> /dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=clientAuth,serverAuth\nkeyUsage=digitalSignature\n' "$3" > "$PKI/$1.ext"
  openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/$2.pem" -CAkey "$PKI/$2-key.pem" -CAcreateserial -days 1 \
    -extfile "$PKI/$1.ext" -out "$PKI/$1.pem" 2> /dev/null
}
ca server-ca
ca device-ca
cert etcd server-ca "IP:127.0.0.1"
cert operator device-ca "IP:127.0.0.1"
for n in node-a node-b node-c; do
  # device key generated on the node, only the CSR leaves it
  "$PROXY" keygen -out "$PKI/$n.key" -csr "$PKI/$n.csr" \
    -uri "spiffe://veilplane.com/cluster/demo/node/$n" -ip 127.0.0.1
  cert $n device-ca "IP:127.0.0.1,URI:spiffe://veilplane.com/cluster/demo/node/$n"
  # every node has its own copy of the shared master key
  install -m 600 "$HERE/master.key" "$PKI/$n-master.key"
done
[ "$(stat -c %a "$PKI/node-a.key")" = 600 ] && [ "$(stat -c %a "$PKI/node-a-master.key")" = 600 ] \
  && ok "device key and master key are only readable by their owner" || bad "key file modes"
openssl x509 -in "$PKI/node-a.pem" -noout -ext subjectAltName 2> /dev/null | grep -q "spiffe://veilplane.com/cluster/demo/node/node-a" \
  && ok "device certificate carries spiffe://veilplane.com/cluster/demo/node/node-a" || bad "device certificate"

echo "== starting stack (simulated backend RTT: $DELAY)"
"$ETCD_DIR/etcd" --data-dir etcd-data --listen-client-urls https://127.0.0.1:2379 $ETCD_TLS \
  --advertise-client-urls https://127.0.0.1:2379 --listen-peer-urls http://127.0.0.1:2380 > etcd.log 2>&1 &
echo $! > etcd.pid
# Two proxy instances, as on two different machines: k3s uses A, B only follows the backend.
# Both talk mTLS to the backend only; they learn of each other through checkpoint records.
"$PROXY" -delay "$DELAY" -v -state-file a.state $(mtls node-a) \
  -upstream 127.0.0.1:2379 -ops-listen 127.0.0.1:9390 > proxy.log 2>&1 &
echo $! > proxy.pid
"$PROXY" -listen 127.0.0.1:2399 -state-file b.state $(mtls node-b) \
  -ops-listen 127.0.0.1:9391 > proxy-b.log 2>&1 &
echo $! > proxy-b.pid
sleep 2
ENDPOINT=http://127.0.0.1:2389
DATASTORE_TLS=""
if [ -n "${DIRECT:-}" ]; then
  ENDPOINT=https://127.0.0.1:2379
  DATASTORE_TLS="--datastore-cafile $PKI/server-ca.pem --datastore-certfile $PKI/operator.pem --datastore-keyfile $PKI/operator-key.pem"
  echo "   DIRECT=1: k3s talks to etcd without the proxy (baseline, the leak checks are expected to fail)"
fi
T0=$(now)
"$K3S_BIN" server --disable-agent --data-dir "$WORK/k3s-data" --datastore-endpoint "$ENDPOINT" $DATASTORE_TLS \
  --disable traefik,servicelb,metrics-server,local-storage --write-kubeconfig "$WORK/kubeconfig" > k3s.log 2>&1 &
echo $! > k3s.pid
for _ in $(seq 1 120); do
  sleep 1
  $KC get --raw /readyz > /dev/null 2>&1 && break
done
if $KC get --raw /readyz > /dev/null 2>&1; then ok "API server ready after $(ms "$T0" "$(now)") ms"; else bad "API server not ready"; tail -20 k3s.log; stop; exit 1; fi

echo "== basic objects"
$KC create namespace demo > /dev/null && ok "create namespace" || bad "create namespace"
$KC -n demo create configmap app-config --from-literal=db-password=super-secret-app-value > /dev/null && ok "create configmap" || bad "create configmap"
$KC -n demo create secret generic api-token --from-literal=token=another-secret-value > /dev/null && ok "create secret" || bad "create secret"
[ "$($KC -n demo get cm app-config -o jsonpath='{.data.db-password}')" = "super-secret-app-value" ] && ok "read configmap back" || bad "read configmap back"

echo "== controllers (watch based): deployment -> replicaset -> pods"
T0=$(now)
$KC -n demo create deployment web --image=nginx --replicas=3 > /dev/null
for _ in $(seq 1 60); do
  [ "$($KC -n demo get pods --no-headers 2>/dev/null | wc -l)" -ge 3 ] && break
  sleep 0.2
done
N=$($KC -n demo get pods --no-headers 2>/dev/null | wc -l)
[ "$N" -ge 3 ] && ok "controller-manager created $N pods in $(ms "$T0" "$(now)") ms" || bad "only $N pods created"

echo "== pagination"
for i in $(seq -w 1 30); do
  printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm-%s\n  namespace: demo\ndata:\n  n: "%s"\n---\n' "$i" "$i"
done > many.yaml
T0=$(now)
$KC create -f many.yaml > /dev/null && ok "create 30 configmaps in one call: $(ms "$T0" "$(now)") ms" || bad "bulk create"
FULL=$($KC -n demo get cm --no-headers | wc -l)
PAGED=$($KC -n demo get cm --no-headers --chunk-size=4 | wc -l)
UNIQ=$($KC -n demo get cm --no-headers --chunk-size=4 | awk '{print $1}' | sort -u | wc -l)
[ "$FULL" -eq 32 ] && [ "$PAGED" -eq 32 ] && [ "$UNIQ" -eq 32 ] && ok "paged list (chunks of 4) returns all $PAGED objects, no duplicates" \
  || bad "paging mismatch: full=$FULL paged=$PAGED unique=$UNIQ (expected 32)"
ALL=$($KC get cm -A --no-headers --chunk-size=3 | wc -l)
ALLFULL=$($KC get cm -A --no-headers | wc -l)
[ "$ALL" -eq "$ALLFULL" ] && ok "cross-namespace paged list consistent ($ALL objects)" || bad "cross-namespace paging: $ALL vs $ALLFULL"

echo "== watch"
$KC -n demo get cm --watch-only --no-headers > watch.out 2>&1 &
WPID=$!
sleep 2
$KC -n demo create configmap watched --from-literal=a=b > /dev/null
sleep 2
kill $WPID 2>/dev/null
grep -q "^watched" watch.out && ok "watch delivered the new object" || { bad "watch missed the event"; cat watch.out; }

echo "== update and delete"
$KC -n demo patch cm app-config -p '{"data":{"db-password":"rotated"}}' > /dev/null
[ "$($KC -n demo get cm app-config -o jsonpath='{.data.db-password}')" = "rotated" ] && ok "update (optimistic concurrency via Txn)" || bad "update"
$KC -n demo delete cm watched > /dev/null && ! $KC -n demo get cm watched > /dev/null 2>&1 && ok "delete" || bad "delete"
T0=$(now)
$KC delete namespace demo --wait=true --timeout=90s > /dev/null 2>&1 && ok "namespace deletion (cascading, many deletes) in $(ms "$T0" "$(now)") ms" || bad "namespace deletion"

echo "== what the hoster sees in etcd"
TOTAL=$($ETCDCTL get "" --prefix --keys-only | grep -c .)
PLAINKEYS=$($ETCDCTL get "" --prefix --keys-only | grep -ac -E "registry|demo|bootstrap|configmaps|secrets")
PLAINVALS=$($ETCDCTL get "" --prefix --print-value-only | grep -ac -E "super-secret|another-secret|rotated|nginx|kube-system")
echo "  $TOTAL keys in etcd, sample:"
$ETCDCTL get "" --prefix --keys-only | grep . | head -3 | sed 's/^/    /'
[ "$PLAINKEYS" -eq 0 ] && ok "no readable key names in etcd" || bad "$PLAINKEYS readable key names"
[ "$PLAINVALS" -eq 0 ] && ok "no readable values in etcd" || bad "$PLAINVALS readable values"

echo "== mTLS"
OUT=$($ETCD_DIR/etcdctl --endpoints=https://127.0.0.1:2379 --cacert "$PKI/server-ca.pem" --dial-timeout=2s get x 2>&1)
[ $? -ne 0 ] && ok "backend refuses clients without a device certificate" || bad "backend accepted a client without certificate"
grep '"msg":"mTLS"' proxy.log | grep -q '"cluster":"demo","node":"node-a"' && ok "instance A identified as cluster demo / node-a" || bad "identity not logged"

echo "== operations"
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9390/readyz)" = 200 ] && ok "/readyz of A is ready" || bad "/readyz"
curl -s http://127.0.0.1:9390/metrics | grep -q '^veil_replica_failed 0' && ok "/metrics: replica healthy" || bad "/metrics"

echo "== proxy errors"
ERRS=$(grep -c "veil:" k3s.log)
[ "$ERRS" -eq 0 ] && ok "no veil errors reported to k3s" || { bad "$ERRS veil errors in k3s log"; grep "veil:" k3s.log | sort | uniq -c | head; }

if [ -z "${DIRECT:-}" ]; then
  echo "== horizontal scaling: second instance B"
  VIA_A=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2389 get /registry/namespaces/kube-system --print-value-only | md5sum)
  VIA_B=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2399 get /registry/namespaces/kube-system --print-value-only | md5sum)
  [ "$VIA_A" = "$VIA_B" ] && ok "instance B reads the same plaintext as A" || bad "A and B disagree"
  NA=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2389 get /registry/namespaces/ --prefix --keys-only | grep -c .)
  NB=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2399 get /registry/namespaces/ --prefix --keys-only | grep -c .)
  [ "$NA" -eq "$NB" ] && [ "$NA" -gt 0 ] && ok "prefix list via A and B identical ($NA namespaces)" || bad "prefix lists differ: $NA vs $NB"

  echo "== rollback attack: backend restores an old snapshot"
  $ETCDCTL snapshot save old.db > /dev/null 2>&1
  OLDREV=$($ETCDCTL endpoint status -w json | grep -o '"revision":[0-9]*' | cut -d: -f2)
  $KC create namespace created-after-snapshot > /dev/null
  $KC delete namespace created-after-snapshot --wait=false > /dev/null
  sleep 3 # the instances persist their checkpoints once per second
  NEWREV=$($ETCDCTL endpoint status -w json | grep -o '"revision":[0-9]*' | cut -d: -f2)
  kill "$(cat k3s.pid)" "$(cat etcd.pid)" 2>/dev/null
  while kill -0 "$(cat etcd.pid)" 2>/dev/null || kill -0 "$(cat k3s.pid)" 2>/dev/null; do sleep 0.2; done
  sleep 1
  "$ETCD_DIR/etcdutl" snapshot restore old.db --data-dir etcd-old > /dev/null 2>&1
  "$ETCD_DIR/etcd" --data-dir etcd-old --listen-client-urls https://127.0.0.1:2379 $ETCD_TLS \
    --advertise-client-urls https://127.0.0.1:2379 --listen-peer-urls http://127.0.0.1:2380 > etcd-old.log 2>&1 &
  echo $! > etcd.pid
  sleep 3
  ROLLREV=$($ETCDCTL endpoint status -w json | grep -o '"revision":[0-9]*' | cut -d: -f2)
  echo "   backend revision: $NEWREV before attack, $ROLLREV after restoring snapshot from revision $OLDREV"

  OUT=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2389 get /registry/namespaces/default 2>&1)
  echo "$OUT" | grep -q "went back in time" && ok "instance A refuses the old state" || bad "A accepted the rollback: $OUT"
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9390/readyz)" = 503 ] \
    && curl -s http://127.0.0.1:9390/metrics | grep -q '^veil_replica_failed 1' \
    && ok "A reports the attack: /readyz 503, veil_replica_failed 1" || bad "attack not visible in ops endpoints"
  OUT=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2399 get /registry/namespaces/default 2>&1)
  echo "$OUT" | grep -q "went back in time" && ok "instance B refuses too" || bad "B accepted the rollback: $OUT"

  # A brand new instance C, set up with the state of A as an invite does, refuses as well.
  cp a.state c.state
  "$PROXY" -listen 127.0.0.1:2409 -state-file c.state $(mtls node-c) \
    -ops-listen 127.0.0.1:9392 > proxy-c.log 2>&1 &
  echo $! > proxy-c.pid
  sleep 2
  OUT=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2409 get /registry/namespaces/default 2>&1)
  echo "$OUT" | grep -q "went back in time" && ok "brand new instance C refuses too" || bad "C accepted the rollback: $OUT"

  # A restarted instance remembers the mark from its state file.
  kill "$(cat proxy.pid)"
  sleep 1
  "$PROXY" -state-file a.state $(mtls node-a) -ops-listen 127.0.0.1:9390 > proxy-a2.log 2>&1 &
  echo $! > proxy.pid
  sleep 2
  OUT=$($ETCD_DIR/etcdctl --endpoints=127.0.0.1:2389 get /registry/namespaces/default 2>&1)
  echo "$OUT" | grep -q "went back in time" && ok "restarted instance A still refuses" || bad "restarted A accepted the rollback: $OUT"
fi

echo "== result: $PASS passed, $FAIL failed (logs in $WORK)"
stop
[ "$FAIL" -eq 0 ]
