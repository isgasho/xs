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

// Conn is a HKex connection - a drop-in replacement for net.Conn
type Conn struct {
	c          net.Conn // which also implements io.Reader, io.Writer, ...
	h          *HerraduraKEx
	cipheropts uint32 // post-KEx cipher/hmac options
	opts       uint32 // post-KEx protocol options (caller-defined)
	op uint8 // post-KEx 'op' (caller-defined)
	r          cipher.Stream
	w          cipher.Stream
}

// ConnOpts returns the cipher/hmac options value, which is sent to the
// peer but is not itself part of the KEx.
//
// (Used for protocol-level negotiations after KEx such as
// cipher/HMAC algorithm options etc.)
func (c *Conn) ConnOpts() uint32 {
	return c.cipheropts
}

// SetConnOpts sets the cipher/hmac options value, which is sent to the
// peer as part of KEx but not part of the KEx itself.
//
// opts - bitfields for cipher and hmac alg. to use after KEx
func (c *Conn) SetConnOpts(copts uint32) {
	c.cipheropts = copts
}

// Opts returns the protocol options value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this for protocol-level options not part
// of the KEx or encryption info used by the connection.
func (c *Conn) Opts() uint32 {
	return c.opts
}

// SetOpts sets the protocol options value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this for protocol-level options not part
// of the KEx of encryption info used by the connection.
//
// opts - a uint32, caller-defined
func (c *Conn) SetOpts(opts uint32) {
	c.opts = opts
}

// Op returns the 'op' value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this to indicate connection-specific
// operations not part of the KEx or encryption info used by the connection.
func (c *Conn) Op() uint8 {
	return c.op
}

// SetOp sets the 'op' value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this to indicate connection-specific
// operations not part of the KEx or encryption info used by the connection.
//
// op - a uint8, caller-defined
func (c *Conn) SetOp(op uint8) {
	c.op = op
}

func (c *Conn) applyConnExtensions(extensions ...string) {
	for _, s := range extensions {
		switch s {
		case "C_AES_256":
			fmt.Println("[extension arg = C_AES_256]")
			c.cipheropts &= (0xFFFFFF00)
			c.cipheropts |= CAlgAES256
			break
		case "C_TWOFISH_128":
			fmt.Println("[extension arg = C_TWOFISH_128]")
			c.cipheropts &= (0xFFFFFF00)
			c.cipheropts |= CAlgTwofish128
			break
		case "C_BLOWFISH_64":
			fmt.Println("[extension arg = C_BLOWFISH_64]")
			c.cipheropts &= (0xFFFFFF00)
			c.cipheropts |= CAlgBlowfish64
			break
		case "H_SHA256":
			fmt.Println("[extension arg = H_SHA256]")
			c.cipheropts &= (0xFFFF00FF)
			c.cipheropts |= (HmacSHA256 << 8)
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
	hc = &Conn{c: c, h: New(0, 0), cipheropts: 0, opts: 0, op:0, r: nil, w: nil}

	hc.applyConnExtensions(extensions...)

	fmt.Fprintf(c, "0x%s\n%08x:%08x:%02x\n", hc.h.d.Text(16),
		hc.cipheropts, hc.opts, hc.op)

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fscanf(c, "%08x:%08x:%02x\n",
		&hc.cipheropts, &hc.opts, &hc.op)
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
func (c *Conn) Close() (err error) {
	err = c.c.Close()
	fmt.Println("[Conn Closing]")
	return
}

/*---------------------------------------------------------------------*/

// HKExListener is a Listener conforming to net.Listener
//
// See go doc net.Listener
type HKExListener struct {
	l net.Listener
}

// Listen for a connection
//
// See go doc net.Listen
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
//
// See go doc io.Close
func (hl *HKExListener) Close() error {
	fmt.Println("[Listener Closed]")
	return hl.l.Close()
}

// Accept a client connection, conforming to net.Listener.Accept()
//
// See go doc net.Listener.Accept
func (hl *HKExListener) Accept() (hc Conn, err error) {
	c, err := hl.l.Accept()
	if err != nil {
		return Conn{c: nil, h: nil, cipheropts: 0, opts: 0,
			r: nil, w: nil}, err
	}
	fmt.Println("[Accepted]")

	hc = Conn{c: c, h: New(0, 0), cipheropts: 0, opts: 0, op:0, r: nil, w: nil}

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return hc, err
	}
	_, err = fmt.Fscanf(c, "%08x:%08x:%02x\n",
		&hc.cipheropts, &hc.opts, &hc.op)
	if err != nil {
		return hc, err
	}
	hc.h.PeerD = d
	fmt.Printf("** D:%s\n", hc.h.d.Text(16))
	fmt.Printf("**(s)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	fmt.Printf("**(s)** FA:%s\n", hc.h.fa)

	fmt.Fprintf(c, "0x%s\n%08x:%08x:%02x\n", hc.h.d.Text(16),
		hc.cipheropts, hc.opts, hc.op)

	hc.r = hc.getStream(hc.h.fa)
	hc.w = hc.getStream(hc.h.fa)
	return
}
/*---------------------------------------------------------------------*/

// Read into a byte slice
//
// See go doc io.Reader
func (c Conn) Read(b []byte) (n int, err error) {
	fmt.Printf("[Decrypting...]\n")
	n, err = c.c.Read(b)
	if err != nil && err.Error() != "EOF" {
		panic(err)
	}
	fmt.Printf("  ctext:%+v\n", b[:n]) // print only used portion
	db := bytes.NewBuffer(b[:n])
	// The StreamReader acts like a pipe, decrypting
	// whatever is available and forwarding the result
	// to the parameter of Read() as a normal io.Reader
	rs := &cipher.StreamReader{S: c.r, R: db}
	n, err = rs.Read(b)
	fmt.Printf("  ptext:%+v\n", b[:n])
	return
}

// Write a byte slice
//
// See go doc io.Writer
func (c Conn) Write(b []byte) (n int, err error) {
	fmt.Printf("[Encrypting...]\n")
	fmt.Printf("  ptext:%+v\n", b)
	var wb bytes.Buffer
	// The StreamWriter acts like a pipe, forwarding whatever is
	// written to it through the cipher, encrypting as it goes
	ws := &cipher.StreamWriter{S: c.w, W: &wb}
	_, err = ws.Write(b)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  ctext:%+v\n", wb.Bytes())
	n, err = c.c.Write(wb.Bytes())
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
