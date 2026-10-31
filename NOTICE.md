# Third-party software

veil-proxy is licensed under FSL-1.1-ALv2 (see LICENSE.md). Binaries of
veil-proxy contain the following third-party software, which keeps its own
license. When distributing binaries, ship this file together with the license
texts of these modules (e.g. collected with `go-licenses save`).

| Module | License |
|---|---|
| github.com/tink-crypto/tink-go/v2 | Apache-2.0 |
| github.com/google/go-tpm | Apache-2.0 |
| go.etcd.io/etcd/api/v3 | Apache-2.0 |
| google.golang.org/grpc | Apache-2.0 |
| google.golang.org/genproto | Apache-2.0 |
| google.golang.org/protobuf | BSD-3-Clause |
| github.com/golang/protobuf | BSD-3-Clause |
| github.com/gogo/protobuf | BSD-3-Clause |
| golang.org/x/net, golang.org/x/sys, golang.org/x/text | BSD-3-Clause |

Test builds only (`-tags tpmsim`, never distributed): github.com/google/go-tpm-tools
(Apache-2.0), which includes Microsoft's TPM 2.0 reference implementation
(BSD-2-Clause style license, see its source).

## gRPC NOTICE

Copyright 2014 gRPC authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
