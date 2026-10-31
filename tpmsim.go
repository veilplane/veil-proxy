// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

//go:build tpmsim

package main

// Test builds only (go build -tags tpmsim): "-tpm simulator:<seed>" runs
// Microsoft's TPM 2.0 reference implementation in-process. With a fixed seed
// the simulated TPM derives the same storage root key in every process, so a
// blob created by "tpm-keygen" can be loaded by a later proxy process, like on
// a real machine. Different seeds behave like different machines.
// Never part of a production build.

import (
	"strconv"
	"strings"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
)

func init() {
	real := openTPM
	openTPM = func(path string) (transport.TPMCloser, error) {
		seed, ok := strings.CutPrefix(path, "simulator:")
		if !ok {
			return real(path)
		}
		n, err := strconv.ParseInt(seed, 10, 64)
		if err != nil {
			return nil, err
		}
		sim, err := simulator.GetWithFixedSeedInsecure(n)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(sim), nil
	}
}
