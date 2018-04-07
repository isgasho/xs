// Package hkexsh - socket lib conforming to
// golang.org/pkg/net Conn interface, with
// experimental key exchange algorithm by
// Omar Alejandro Herrera Reyna.
//
// (https://github.com/Caume/HerraduraKEx)
//
// The core HerraduraKEx algorithm is dual-licensed
// by the author (Omar Alejandro Herrera Reyna)
// under GPL3 and MIT licenses.
// See LICENSE.gpl and LICENSE.mit in this distribution
//
// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package hkexsh

/*  Herradura - a Key exchange scheme in the style of Diffie-Hellman Key Exchange.
    Copyright (C) 2017 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    golang implementation by Russ Magee (rmagee_at_gmail.com) */

/* This is the core KEx algorithm. For client/server net support code,
See hkexnet.go for a golang/pkg/net for the compatible Conn interface
using this to transparently negotiate keys and secure a network channel. */

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

// HerraduraKEx holds the session state for a key exchange.
type HerraduraKEx struct {
	intSz, pubSz int
	randctx      *rand.Rand
	a            *big.Int
	b            *big.Int
	d, PeerD     *big.Int
	fa           *big.Int
}

// New returns a HerraduraKEx struct.
//
//   i - internal (private) random nonce
//   p - public (exchanged) random nonce (typically 1/4 bitsize of i)
//
//   If i or p are passed as zero, they will default to 256 and 64,
//   respectively.
func New(i int, p int) (h *HerraduraKEx) {
	h = new(HerraduraKEx)

	if i == 0 {
		i = 256
	}
	if p == 0 {
		p = 64
	}

	h.intSz = i
	h.pubSz = p

	h.seed()
	h.a = h.rand()
	h.b = h.rand()

	h.d = h.fscxRevolve(h.a, h.b, h.pubSz)
	return h
}

func (h *HerraduraKEx) seed() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	h.randctx = r
}

func (h *HerraduraKEx) rand() (v *big.Int) {
	v = big.NewInt(0)
	v.Rand(h.randctx, h.getMax())
	return v
}

// getMax returns the max value for an n-bit big.Int
func (h *HerraduraKEx) getMax() (n *big.Int) {
	n = big.NewInt(0)
	var max big.Int

	for i := 0; i < h.intSz; i++ {
		max.SetBit(n, i, 1)
	}
	n = &max
	return n
}

func (h *HerraduraKEx) bitX(x *big.Int, pos int) (ret int64) {
	if pos < 0 {
		pos = h.intSz - pos
	}

	if pos == 0 {
		ret = int64(x.Bit(1) ^ x.Bit(0) ^ x.Bit(h.intSz-1))
	} else if pos == h.intSz-1 {
		ret = int64(x.Bit(0) ^ x.Bit(pos) ^ x.Bit(pos-1))
	} else {
		ret = int64(x.Bit((pos+1)%h.intSz) ^ x.Bit(pos) ^ x.Bit(pos-1))
	}
	return ret
}

func (h *HerraduraKEx) bit(up, down *big.Int, posU, posD int) (ret *big.Int) {
	return big.NewInt(h.bitX(up, posU) ^ h.bitX(down, posD))
}

func (h *HerraduraKEx) fscx(up, down *big.Int) (result *big.Int) {
	result = big.NewInt(0)

	for count := 0; count < h.intSz; count++ {
		result.Lsh(result, 1)
		result.Add(result, h.bit(up, down, count, count))
	}
	return result
}

// This is the iteration function using the result of the previous iteration
// as the first parameter and the second parameter of the first iteration.
func (h *HerraduraKEx) fscxRevolve(x, y *big.Int, passes int) (result *big.Int) {
	result = x
	for count := 0; count < passes; count++ {
		result = h.fscx(result, y)
	}
	return result
}

// D returns the D (FSCX Revolved) value, input to generate FA
// (the value for peer KEx)
func (h *HerraduraKEx) D() *big.Int {
	return h.d
}

// FA returns the FA value, which must be sent to peer for KEx.
func (h *HerraduraKEx) FA() {
	h.fa = h.fscxRevolve(h.PeerD, h.b, h.intSz-h.pubSz)
	h.fa.Xor(h.fa, h.a)
}

// Output HerraduraKEx type value as a string. Implements Stringer interface.
func (h *HerraduraKEx) String() string {
	return fmt.Sprintf("s:%d p:%d\na:%s\nb:%s\nd:->%s\n<-PeerD:%s\nfa:%s",
		h.intSz, h.pubSz,
		h.a.Text(16), h.b.Text(16),
		h.d.Text(16),
		h.PeerD.Text(16),
		h.fa.Text(16))
}
