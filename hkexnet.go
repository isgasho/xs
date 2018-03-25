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
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
)

/*---------------------------------------------------------------------*/

// Conn is a HKex connection - a drop-in replacement for net.Conn
type Conn struct {
	c          net.Conn // which also implements io.Reader, io.Writer, ...
	h          *HerraduraKEx
	hmacOn     bool          // turned on once channel param negotiation is done
	cipheropts uint32        // post-KEx cipher/hmac options
	opts       uint32        // post-KEx protocol options (caller-defined)
	r          cipher.Stream //read cipherStream
	rm         hash.Hash
	w          cipher.Stream //write cipherStream
	wm         hash.Hash
}

func (c *Conn) EnableHMAC() {
	c.hmacOn = true
}

// ConnOpts returns the cipher/hmac options value, which is sent to the
// peer but is not itself part of the KEx.
//
// (Used for protocol-level negotiations after KEx such as
// cipher/HMAC algorithm options etc.)
func (c Conn) ConnOpts() uint32 {
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
func (c Conn) Opts() uint32 {
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

func (c *Conn) applyConnExtensions(extensions ...string) {
	for _, s := range extensions {
		switch s {
		case "C_AES_256":
			log.Println("[extension arg = C_AES_256]")
			c.cipheropts &= (0xFFFFFF00)
			c.cipheropts |= CAlgAES256
			break
		case "C_TWOFISH_128":
			log.Println("[extension arg = C_TWOFISH_128]")
			c.cipheropts &= (0xFFFFFF00)
			c.cipheropts |= CAlgTwofish128
			break
		case "C_BLOWFISH_64":
			log.Println("[extension arg = C_BLOWFISH_64]")
			c.cipheropts &= (0xFFFFFF00)
			c.cipheropts |= CAlgBlowfish64
			break
		case "H_SHA256":
			log.Println("[extension arg = H_SHA256]")
			c.cipheropts &= (0xFFFF00FF)
			c.cipheropts |= (HmacSHA256 << 8)
			break
		default:
			log.Printf("[Dial ext \"%s\" ignored]\n", s)
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
	// Open raw Conn c
	c, err := net.Dial(protocol, ipport)
	if err != nil {
		return nil, err
	}
	// Init hkexnet.Conn hc over net.Conn c
	hc = &Conn{c: c, h: New(0, 0)}
	hc.applyConnExtensions(extensions...)

	// Send hkexnet.Conn parameters to remote side
	// d is value for Herradura key exchange
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
	log.Printf("** D:%s\n", hc.h.d.Text(16))
	log.Printf("**(c)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	log.Printf("**(c)** FA:%s\n", hc.h.fa)

	hc.r, hc.rm = hc.getStream(hc.h.fa)
	hc.w, hc.wm = hc.getStream(hc.h.fa)
	return
}

// Close a hkex.Conn
func (c Conn) Close() (err error) {
	err = c.c.Close()
	log.Println("[Conn Closing]")
	return
}

// LocalAddr returns the local network address.
func (c Conn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c Conn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c Conn) SetDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c Conn) SetWriteDeadline(t time.Time) error {
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c Conn) SetReadDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
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
	log.Println("[Listening]")
	hl.l = l
	return
}

// Close a hkex Listener - closes the Listener.
// Any blocked Accept operations will be unblocked and return errors.
//
// See go doc net.Listener.Close
func (hl HKExListener) Close() error {
	log.Println("[Listener Closed]")
	return hl.l.Close()
}

// Addr returns a the listener's network address.
//
// See go doc net.Listener.Addr
func (hl HKExListener) Addr() net.Addr {
	return hl.l.Addr()
}

// Accept a client connection, conforming to net.Listener.Accept()
//
// See go doc net.Listener.Accept
func (hl HKExListener) Accept() (hc Conn, err error) {
	// Open raw Conn c
	c, err := hl.l.Accept()
	if err != nil {
		return Conn{c: nil, h: nil, cipheropts: 0, opts: 0,
			r: nil, w: nil}, err
	}
	log.Println("[Accepted]")

	hc = Conn{c: c, h: New(0, 0)}

	// Read in hkexnet.Conn parameters over raw Conn c
	// d is value for Herradura key exchange
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
	log.Printf("** D:%s\n", hc.h.d.Text(16))
	log.Printf("**(s)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	log.Printf("**(s)** FA:%s\n", hc.h.fa)

	fmt.Fprintf(c, "0x%s\n%08x:%08x\n", hc.h.d.Text(16),
		hc.cipheropts, hc.opts)

	hc.r, hc.rm = hc.getStream(hc.h.fa)
	hc.w, hc.wm = hc.getStream(hc.h.fa)
	return
}

/*---------------------------------------------------------------------*/

// Read into a byte slice
//
// See go doc io.Reader
func (c Conn) Read(b []byte) (n int, err error) {
	//log.Printf("[Decrypting...]\r\n")
	var hIn []byte = make([]byte, 1, 1)

	if c.hmacOn {
		_ = hIn
		//_, _ = io.ReadFull(c.c, hIn)
		//if e != nil {
		//	panic(e)
		//}
	}
	n, err = c.c.Read(b)

	// Normal client 'exit' from interactive session will cause
	// (on server side) err.Error() == "<iface/addr info ...>: use of closed network connection"
	if err != nil && err.Error() != "EOF" {
		if !strings.HasSuffix(err.Error(), "use of closed network connection") {
			log.Println("unexpected Read() err:", err)
		} else {
			log.Println("[Client hung up]")
		}
	}

	log.Printf("  <:ctext:\r\n%s\r\n", hex.Dump(b[:n])) //EncodeToString(b[:n])) // print only used portion

	db := bytes.NewBuffer(b[:n])
	// The StreamReader acts like a pipe, decrypting
	// whatever is available and forwarding the result
	// to the parameter of Read() as a normal io.Reader
	rs := &cipher.StreamReader{S: c.r, R: db}
	// FIXME: Possibly the bug here -- Read() may get grouped writes from
	// server side, causing loss of hmac sync. -rlm 2018-01-16
	n, err = rs.Read(b)
	log.Printf("  <-ptext:\r\n%s\r\n", hex.Dump(b[:n])) //EncodeToString(b[:n]))

    // Re-calculate hmac, compare with received value
	if c.hmacOn {
		c.rm.Write(b[:n])
		hTmp := c.rm.Sum(nil)[0]
		log.Printf("<%04x) HMAC:(i)%02x (c)%02x\r\n", len(b[:n]), hIn, hTmp)
	}

	return
}

// Write a byte slice
//
// See go doc io.Writer
func (c Conn) Write(b []byte) (n int, err error) {
	//log.Printf("[Encrypting...]\r\n")
	//var pLen uint32
	var hTmp = make([]byte, 1, 1)

	log.Printf("  :>ptext:\r\n%s\r\n", hex.Dump(b)) //EncodeToString(b))

	if c.hmacOn {
		_ = hTmp
		//pLen = uint32(len(b))
		//_ = binary.Write(c.c, binary.BigEndian, &pLen)

		c.wm.Write(b)
		hTmp[0] = c.wm.Sum(nil)[0]
		//_, e := c.c.Write(hTmp)
		//if e != nil {
		//	panic(e)
		//}
		log.Printf("  (%04x> HMAC(o):%02x\r\n", len(b) /*pLen*/, hTmp)
	}

	var wb bytes.Buffer
	// The StreamWriter acts like a pipe, forwarding whatever is
	// written to it through the cipher, encrypting as it goes
	ws := &cipher.StreamWriter{S: c.w, W: &wb}
	_, err = ws.Write(b)
	if err != nil {
		panic(err)
	}
	log.Printf("  ->ctext:\r\n%s\r\n", hex.Dump(wb.Bytes())) //EncodeToString(b)) // print only used portion

	n, err = c.c.Write(wb.Bytes())
	if err != nil {
		panic(err)
	}
	return
}
