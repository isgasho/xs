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

// Implementation of HKEx-wrapped versions of the golang standard
// net package interfaces, allowing clients and servers to simply replace
// 'net.Dial' and 'net.Listen' with 'hkex.Dial' and 'hkex.Listen'.
import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"math/big"
	"net"
)

/*---------------------------------------------------------------------*/

// A HKex connection - drop-in replacement for net.Conn
type Conn struct {
	c          net.Conn // which also implements io.Reader, io.Writer, ...
	h          *HerraduraKEx
	cipheropts uint32 // post-KEx cipher/hmac options
	opts       uint32 // post-KEx protocol options
	r          cipher.Stream
	w          cipher.Stream
}

// Return the cipher/hmac options value, which is sent to the peer but is
// not itself part of the KEx.
// (Used for protocol-level negotiations after KEx such as
// cipher/HMAC algorithm options etc.)
func (c *Conn) ConnOpts() uint32 {
	return c.cipheropts
}

// Set cipher/hmac options value, which is sent to the peer as part of
// KEx but not part of the KEx itself.
//
// opts - bitfields for cipher and hmac alg. to use after KEx
func (c *Conn) SetConnOpts(copts uint32) {
	c.cipheropts = copts
}

// Return the protocol options value, which is sent to the peer but is
// not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this for protocol-level options not part
// of the KEx or encryption info used by the connection.
func (c *Conn) Opts() uint32 {
	return c.opts
}

// Set the protocol options value, which is sent to the peer but is
// not itself part of the KEx or connection (cipher/hmac) setup.

// Consumers of this lib may use this for protocol-level options not part
// of the KEx of encryption info used by the connection.
//
// opts - a uint32, caller-defined
func (c *Conn) SetOpts(opts uint32) {
	c.opts = opts
}

func (hc *Conn) applyConnExtensions(extensions ...string) {
	for _, s := range extensions {
		switch s {
		case "C_AES_256":
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= C_AES_256
			break
		case "C_TWOFISH_128":
			fmt.Println("[extension arg = C_TWOFISH_128]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= C_TWOFISH_128
			break
		case "H_SHA256":
			hc.cipheropts &= (0xFFFF00FF)
			hc.cipheropts |= (H_SHA256 << 8)
			break
		default:
			fmt.Printf("[Dial ext \"%s\" ignored]\n", s)
			break
		}
	}
}

// Dial as net.Dial(), but with implicit HKEx PeerD read on connect
//   Can be called like net.Dial(), defaulting to C_AES_256/H_SHA256,
//   or additional option arguments can be passed amongst the following:
//
//   "C_AES_256" | "C_TWOFISH_128"
//
//   "H_SHA256"
func Dial(protocol string, ipport string, extensions ...string) (hc *Conn, err error) {
	c, err := net.Dial(protocol, ipport)
	if err != nil {
		return nil, err
	}
	hc = &Conn{c: c, h: New(0, 0), cipheropts: 0, opts: 0, r: nil, w: nil}

	hc.applyConnExtensions(extensions...)

	fmt.Fprintf(c, "0x%s\n%08x:%08x\n", hc.h.d.Text(16),
		hc.cipheropts, hc.opts)

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fscanf(c, "%08x:%08x\n",
		&hc.cipheropts, &hc.opts)
	if err != nil {
		return nil, err
	}

	hc.h.PeerD = d
	fmt.Printf("** D:%s\n", hc.h.d.Text(16))
	fmt.Printf("**(c)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	fmt.Printf("**(c)** FA:%s\n", hc.h.fa)

	hc.r = hc.getStream(hc.h.fa)
	hc.w = hc.getStream(hc.h.fa)
	return
}

// Close a hkex.Conn
func (hc *Conn) Close() (err error) {
	err = hc.c.Close()
	fmt.Println("[Conn Closing]")
	return
}

/*---------------------------------------------------------------------*/

// A hkex Listener, conforming to net.Listener - returns a hkex.Conn
type HKExListener struct {
	l net.Listener
}

// hkex.Listen, a drop-in replacement for net.Conn.Listen
func Listen(protocol string, ipport string) (hl HKExListener, e error) {
	l, err := net.Listen(protocol, ipport)
	if err != nil {
		return HKExListener{nil}, err
	}
	fmt.Println("[Listening]")
	hl.l = l
	return
}

// Close a hkex Listener
func (hl *HKExListener) Close() {
	hl.l.Close()
	fmt.Println("[Listener Closed]")
}

// Accept a client connection, conforming to net.Listener.Accept()
func (hl *HKExListener) Accept() (hc Conn, err error) {
	c, err := hl.l.Accept()
	if err != nil {
		return Conn{c: nil, h: nil, cipheropts: 0, opts: 0,
			r: nil, w: nil}, err
	}
	fmt.Println("[Accepted]")

	hc = Conn{c: c, h: New(0, 0), cipheropts: 0, opts: 0, r: nil, w: nil}

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return hc, err
	}
	_, err = fmt.Fscanf(c, "%08x:%08x\n",
		&hc.cipheropts, &hc.opts)
	if err != nil {
		return hc, err
	}
	hc.h.PeerD = d
	fmt.Printf("** D:%s\n", hc.h.d.Text(16))
	fmt.Printf("**(s)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	fmt.Printf("**(s)** FA:%s\n", hc.h.fa)

	fmt.Fprintf(c, "0x%s\n%08x:%08x\n", hc.h.d.Text(16),
		hc.cipheropts, hc.opts)

	hc.r = hc.getStream(hc.h.fa)
	hc.w = hc.getStream(hc.h.fa)
	return
}

/*---------------------------------------------------------------------*/
func (hc Conn) Read(b []byte) (n int, err error) {
	fmt.Printf("[Decrypting...]\n")
	n, err = hc.c.Read(b)
	if err != nil && err.Error() != "EOF" {
		panic(err)
	}
	fmt.Printf("  ctext:%+v\n", b[:n]) // print only used portion
	db := bytes.NewBuffer(b[:n])
	// The StreamReader acts like a pipe, decrypting
	// whatever is available and forwarding the result
	// to the parameter of Read() as a normal io.Reader
	rs := &cipher.StreamReader{S: hc.r, R: db}
	n, err = rs.Read(b)
	fmt.Printf("  ptext:%+v\n", b[:n])
	return
}

func (hc Conn) Write(b []byte) (n int, err error) {
	fmt.Printf("[Encrypting...]\n")
	fmt.Printf("  ptext:%+v\n", b)
	var wb bytes.Buffer
	// The StreamWriter acts like a pipe, forwarding whatever is
	// written to it through the cipher, encrypting as it goes
	ws := &cipher.StreamWriter{S: hc.w, W: &wb}
	n, err = ws.Write(b)
	fmt.Printf("  ctext:%+v\n", wb.Bytes())
	n, err = hc.c.Write(wb.Bytes())
	return
}

// Return c coerced into a HKEx Conn (which implements interface net.Conn)
//   Only useful if one wants to convert an open connection later to HKEx
//   (Use Dial() instead to start with HKEx automatically.)
/*
 func NewHKExConn(c *net.Conn) (hc *Conn) {
	hc = new(Conn)

	hc.c = *c
	hc.h = New(0, 0)
	d := big.NewInt(0)
	_, err := fmt.Fscanln(hc.c, d)
	if err != nil {
		//
	}
	hc.h.PeerD = d
	fmt.Printf("** D:%s\n", hc.h.d.Text(16))
	fmt.Printf("** peerD:%s\n", hc.h.PeerD.Text(16))
	return
}
*/
