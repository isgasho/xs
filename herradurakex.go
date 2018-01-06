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
package herradurakex

import (
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"time"
)

// This type holds the session state for a key exchange
type HerraduraKEx struct {
	intSz, pubSz int
	randctx      *rand.Rand
	a            *big.Int
	b            *big.Int
	d, PeerD     *big.Int
	fa           *big.Int
}

//// Returns a new HerraduraKEx struct with default intSz,pubSz
//func New() (h *HerraduraKEx) {
//	return New(256, 64)
//}

// Returns a new HerraduraKEx struct
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

// Return max value for an n-bit big.Int
func (h *HerraduraKEx) getMax() (v *big.Int) {
	v = big.NewInt(0)
	var max big.Int

	for i := 0; i < h.intSz; i++ {
		max.SetBit(v, i, 1)
	}
	v = &max
	return v
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

// This is the iteration function using the result of the previous iteration as the first
// parameter and the second parameter of the first iteration
func (h *HerraduraKEx) fscxRevolve(x, y *big.Int, passes int) (result *big.Int) {
	result = big.NewInt(0)

	result = x
	for count := 0; count < passes; count++ {
		result = h.fscx(result, y)
	}
	return result
}

func (h *HerraduraKEx) D() *big.Int {
	return h.d
}

func (h *HerraduraKEx) FA() {
	h.fa = h.fscxRevolve(h.PeerD, h.b, h.intSz-h.pubSz)
	h.fa.Xor(h.fa, h.a)
}

func (h *HerraduraKEx) String() string {
	return fmt.Sprintf("s:%d p:%d\na:%s\nb:%s\nd:->%s\n<-PeerD:%s\nfa:%s",
		h.intSz, h.pubSz,
		h.a.Text(16), h.b.Text(16),
		h.d.Text(16),
		h.PeerD.Text(16),
		h.fa.Text(16))
}
/*---------------------------------------------------------------------*/

type HKExConn struct {
	c net.Conn // which also implements io.Reader, io.Writer, ...
	h *HerraduraKEx
}

// Dial as net.Dial(), but with implicit HKEx PeerD read on connect
func Dial(protocol string, ipport string) (hc *HKExConn, err error) {
	c, err := net.Dial(protocol, ipport)
	if err != nil {
		return nil, err
	}
	hc = &HKExConn{c, New(0, 0)}

	// Stub KEx
	fmt.Fprintf(c, "0x%s\n", hc.h.d.Text(16))

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return nil, err
	}
	hc.h.PeerD = d
	fmt.Printf("**(c)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	fmt.Printf("**(c)** FA:%s\n", hc.h.fa)
	return
}

func (hc *HKExConn) Close() (err error) {
	err  = hc.c.Close()
	fmt.Println("[Conn Closing]")
        return
}
/*---------------------------------------------------------------------*/

type HKExListener struct {
	l net.Listener
}

func Listen(protocol string, ipport string) (hl HKExListener, e error) {
	l, err := net.Listen(protocol, ipport)
	if err != nil {
		return HKExListener{nil}, err
	}
	fmt.Println("[Listening]")
	hl.l = l
	return
}

func (hl *HKExListener) Close() {
	hl.l.Close()
	fmt.Println("[Listener Closed]")
}

func (hl *HKExListener) Accept() (hc HKExConn, err error) {
	c, err := hl.l.Accept()

	fmt.Println("[Accepted]")
	if err != nil {
		return HKExConn{nil, nil}, err
	}
	hc = HKExConn{c, New(0, 0)}

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return hc, err
	}
	hc.h.PeerD = d
	fmt.Printf("**(s)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	fmt.Printf("**(s)** FA:%s\n", hc.h.fa)

	// Stub KEx
	fmt.Fprintf(c, "0x%s\n", hc.h.d.Text(16))

	return
}

/*---------------------------------------------------------------------*/

func (hc HKExConn) Read(b []byte) (n int, err error) {
	n, err = hc.c.Read(b)
	if n > 0 {
		fmt.Println("** hc.Read() wraps c.Read() **")
	}
	return
}

func (hc HKExConn) Write(b []byte) (n int, err error) {
	n, err = hc.c.Write(b)
	if n > 0 {
		//fmt.Printf("** hc.Write('%s') wraps c.Write() **\n", b)
	}
	return
}

// Return c coerced into a HKExConn (which implements interface net.Conn)
//   Only useful if one wants to convert an open connection later to HKEx
//   (Use Dial() instead to start with HKEx automatically.)
func NewHKExConn(c *net.Conn) (hc *HKExConn) {
	hc = new(HKExConn)

	hc.c = *c
	hc.h = New(0, 0)
	d := big.NewInt(0)
	_, err := fmt.Fscanln(hc.c, d)
	if err != nil {
		//
	}
	hc.h.PeerD = d
	fmt.Printf("** peerD:%s\n", hc.h.PeerD.Text(16))
	return
}
