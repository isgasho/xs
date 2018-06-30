// hkexnet.go - net.Conn compatible channel setup with encrypted/HMAC
// negotiation

// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

package hkexsh

// Implementation of HKEx-wrapped versions of the golang standard
// net package interfaces, allowing clients and servers to simply replace
// 'net.Dial' and 'net.Listen' with 'hkex.Dial' and 'hkex.Listen'
// (though some extra methods are implemented and must be used
//  for things outside of the scope of plain sockets).
import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	CSONone        = iota // No error, normal packet
	CSOHmacInvalid        // HMAC mismatch detected on remote end
	CSOTermSize           // set term size (rows:cols)
	CSOExitStatus         // Remote cmd exit status (TODO)
	CSOChaff              // Dummy packet, do not pass beyond decryption
)

/*---------------------------------------------------------------------*/

type WinSize struct {
	Rows uint16
	Cols uint16
}

type ChaffConfig struct {
	shutdown bool //set to inform chaffHelper to shut down
	enabled  bool
	msecsMin uint //msecs min interval
	msecsMax uint //msecs max interval
	szMax    uint // max size in bytes
}

// Conn is a HKex connection - a superset of net.Conn
type Conn struct {
	m          *sync.Mutex
	c          net.Conn // which also implements io.Reader, io.Writer, ...
	h          *HerraduraKEx
	cipheropts uint32 // post-KEx cipher/hmac options
	opts       uint32 // post-KEx protocol options (caller-defined)
	WinCh      chan WinSize
	Rows       uint16
	Cols       uint16

	chaff ChaffConfig

	closeStat *uint8        // close status (shell exit status: UNIX uint8)
	r         cipher.Stream //read cipherStream
	rm        hash.Hash
	w         cipher.Stream //write cipherStream
	wm        hash.Hash
	dBuf      *bytes.Buffer //decrypt buffer for Read()
}

func (hc Conn) GetStatus() uint8 {
	return *hc.closeStat
}

func (hc *Conn) SetStatus(stat uint8) {
	*hc.closeStat = stat
	log.Println("closeStat:", *hc.closeStat)
}

// ConnOpts returns the cipher/hmac options value, which is sent to the
// peer but is not itself part of the KEx.
//
// (Used for protocol-level negotiations after KEx such as
// cipher/HMAC algorithm options etc.)
func (hc Conn) ConnOpts() uint32 {
	return hc.cipheropts
}

// SetConnOpts sets the cipher/hmac options value, which is sent to the
// peer as part of KEx but not part of the KEx itself.
//
// opts - bitfields for cipher and hmac alg. to use after KEx
func (hc *Conn) SetConnOpts(copts uint32) {
	hc.cipheropts = copts
}

// Opts returns the protocol options value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this for protocol-level options not part
// of the KEx or encryption info used by the connection.
func (hc Conn) Opts() uint32 {
	return hc.opts
}

// SetOpts sets the protocol options value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this for protocol-level options not part
// of the KEx of encryption info used by the connection.
//
// opts - a uint32, caller-defined
func (hc *Conn) SetOpts(opts uint32) {
	hc.opts = opts
}

func (hc *Conn) applyConnExtensions(extensions ...string) {
	for _, s := range extensions {
		switch s {
		case "C_AES_256":
			log.Println("[extension arg = C_AES_256]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgAES256
			break
		case "C_TWOFISH_128":
			log.Println("[extension arg = C_TWOFISH_128]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgTwofish128
			break
		case "C_BLOWFISH_64":
			log.Println("[extension arg = C_BLOWFISH_64]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgBlowfish64
			break
		case "H_SHA256":
			log.Println("[extension arg = H_SHA256]")
			hc.cipheropts &= (0xFFFF00FF)
			hc.cipheropts |= (HmacSHA256 << 8)
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
	hc = &Conn{m: &sync.Mutex{}, c: c, closeStat: new(uint8), h: New(0, 0), dBuf: new(bytes.Buffer)}
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

	hc.r, hc.rm, err = hc.getStream(hc.h.fa)
	hc.w, hc.wm, err = hc.getStream(hc.h.fa)

	*hc.closeStat = 99 // open or prematurely-closed status
	return
}

// Close a hkex.Conn
func (hc Conn) Close() (err error) {
	hc.DisableChaff()
	hc.WritePacket([]byte{byte(*hc.closeStat)}, CSOExitStatus)
	*hc.closeStat = 0
	err = hc.c.Close()
	log.Println("[Conn Closing]")
	return
}

// LocalAddr returns the local network address.
func (hc Conn) LocalAddr() net.Addr {
	return hc.c.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (hc Conn) RemoteAddr() net.Addr {
	return hc.c.RemoteAddr()
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
func (hc Conn) SetDeadline(t time.Time) error {
	return hc.c.SetDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (hc Conn) SetWriteDeadline(t time.Time) error {
	return hc.c.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (hc Conn) SetReadDeadline(t time.Time) error {
	return hc.c.SetReadDeadline(t)
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
		hc := Conn{m: &sync.Mutex{}, c: nil, h: nil, closeStat: new(uint8), cipheropts: 0, opts: 0,
			r: nil, w: nil}
		return hc, err
	}
	log.Println("[Accepted]")

	hc = Conn{m: &sync.Mutex{}, c: c, h: New(0, 0), closeStat: new(uint8), WinCh: make(chan WinSize, 1),
		dBuf: new(bytes.Buffer)}

	// Read in hkexnet.Conn parameters over raw Conn c
	// d is value for Herradura key exchange
	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	log.Printf("[Got d:%v]", d)
	if err != nil {
		return hc, err
	}
	_, err = fmt.Fscanf(c, "%08x:%08x\n",
		&hc.cipheropts, &hc.opts)
	log.Printf("[Got cipheropts, opts:%v, %v]", hc.cipheropts, hc.opts)
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

	hc.r, hc.rm, err = hc.getStream(hc.h.fa)
	hc.w, hc.wm, err = hc.getStream(hc.h.fa)
	return
}

/*---------------------------------------------------------------------*/

// Read into a byte slice
//
// See go doc io.Reader
func (hc Conn) Read(b []byte) (n int, err error) {
	//log.Printf("[Decrypting...]\r\n")
	for {
		//log.Printf("hc.dBuf.Len(): %d\n", hc.dBuf.Len())
		if hc.dBuf.Len() > 0 /* len(b) */ {
			break
		}

		var ctrlStatOp uint8
		var hmacIn [4]uint8
		var payloadLen uint32

		// Read ctrl/status opcode (CSOHmacInvalid on hmac mismatch)
		err = binary.Read(hc.c, binary.BigEndian, &ctrlStatOp)
		log.Printf("[ctrlStatOp: %v]\n", ctrlStatOp)
		if ctrlStatOp == CSOHmacInvalid {
			// Other side indicated channel tampering, close channel
			hc.Close()
			return 1, errors.New("** ALERT - remote end detected HMAC mismatch - possible channel tampering **")
		}

		// Read the hmac and payload len first
		err = binary.Read(hc.c, binary.BigEndian, &hmacIn)
		// Normal client 'exit' from interactive session will cause
		// (on server side) err.Error() == "<iface/addr info ...>: use of closed network connection"
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				log.Println("unexpected Read() err:", err)
			} else {
				log.Println("[Client hung up]")
			}
			return 0, err
		}

		err = binary.Read(hc.c, binary.BigEndian, &payloadLen)
		if err != nil {
			if err.Error() != "EOF" {
				log.Println("unexpected Read() err:", err)
				//panic(err)
				// Cannot just return 0, err here - client won't hang up properly
				// when 'exit' from shell. TODO: try server sending ctrlStatOp to
				// indicate to Reader? -rlm 20180428
			}
		}

		if payloadLen > 16384 {
			log.Printf("[Insane payloadLen:%v]\n", payloadLen)
			hc.Close()
			return 1, errors.New("Insane payloadLen")
		}
		//log.Println("payloadLen:", payloadLen)

		var payloadBytes = make([]byte, payloadLen)
		n, err = io.ReadFull(hc.c, payloadBytes)
		//log.Print(" << Read ", n, " payloadBytes")

		// Normal client 'exit' from interactive session will cause
		// (on server side) err.Error() == "<iface/addr info ...>: use of closed network connection"
		if err != nil && err.Error() != "EOF" {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				log.Println("unexpected Read() err:", err)
			} else {
				log.Println("[Client hung up]")
			}
		}

		log.Printf("  <:ctext:\r\n%s\r\n", hex.Dump(payloadBytes[:n]))

		db := bytes.NewBuffer(payloadBytes[:n]) //copying payloadBytes to db
		// The StreamReader acts like a pipe, decrypting
		// whatever is available and forwarding the result
		// to the parameter of Read() as a normal io.Reader
		rs := &cipher.StreamReader{S: hc.r, R: db}
		// The caller isn't necessarily reading the full payload so we need
		// to decrypt ot an intermediate buffer, draining it on demand of caller
		decryptN, err := rs.Read(payloadBytes)
		log.Printf("  <-ptext:\r\n%s\r\n", hex.Dump(payloadBytes[:n]))
		if err != nil {
			panic(err)
		}

		// Throw away pkt if it's chaff (ie., caller to Read() won't see this data)
		if ctrlStatOp == CSOChaff {
			log.Printf("[Chaff pkt, discarded (len %d)]\n", decryptN)
		} else if ctrlStatOp == CSOTermSize {
			fmt.Sscanf(string(payloadBytes), "%d %d", &hc.Rows, &hc.Cols)
			log.Printf("[TermSize pkt: rows %v cols %v]\n", hc.Rows, hc.Cols)
			hc.WinCh <- WinSize{hc.Rows, hc.Cols}
		} else if ctrlStatOp == CSOExitStatus {
			*hc.closeStat = uint8(payloadBytes[0])
		} else {
			hc.dBuf.Write(payloadBytes)
			//log.Printf("hc.dBuf: %s\n", hex.Dump(hc.dBuf.Bytes()))
		}

		// Re-calculate hmac, compare with received value
		hc.rm.Write(payloadBytes)
		hTmp := hc.rm.Sum(nil)[0:4]
		log.Printf("<%04x) HMAC:(i)%s (c)%02x\r\n", decryptN, hex.EncodeToString([]byte(hmacIn[0:])), hTmp)

		// Log alert if hmac didn't match, corrupted channel
		if !bytes.Equal(hTmp, []byte(hmacIn[0:])) /*|| hmacIn[0] > 0xf8*/ {
			fmt.Println("** ALERT - detected HMAC mismatch, possible channel tampering **")
			_, _ = hc.c.Write([]byte{CSOHmacInvalid})
		}
	}

	retN := hc.dBuf.Len()
	if retN > len(b) {
		retN = len(b)
	}

	log.Printf("Read() got %d bytes\n", retN)
	copy(b, hc.dBuf.Next(retN))
	//log.Printf("As Read() returns, hc.dBuf is %d long: %s\n", hc.dBuf.Len(), hex.Dump(hc.dBuf.Bytes()))
	return retN, nil
}

// Write a byte slice
//
// See go doc io.Writer
func (hc Conn) Write(b []byte) (n int, err error) {
	n, err = hc.WritePacket(b, CSONone)
	return n, err
}

// Write a byte slice with specified ctrlStatusOp byte
func (hc Conn) WritePacket(b []byte, op byte) (n int, err error) {
	//log.Printf("[Encrypting...]\r\n")
	var hmacOut []uint8
	var payloadLen uint32

	// N.B. Originally this Lock() surrounded only the
	// calls to binary.Write(hc.c ..) however there appears
	// to be some other unshareable state in the Conn
	// struct that must be protected to serialize main and
	// chaff data written to it.
	//
	// Would be nice to determine if the mutex scope
	// could be tightened.
	hc.m.Lock()
	{
		log.Printf("  :>ptext:\r\n%s\r\n", hex.Dump(b))

		payloadLen = uint32(len(b))

		// Calculate hmac on payload
		hc.wm.Write(b)
		hmacOut = hc.wm.Sum(nil)[0:4]

		log.Printf("  (%04x> HMAC(o):%s\r\n", payloadLen, hex.EncodeToString(hmacOut))

		var wb bytes.Buffer
		// The StreamWriter acts like a pipe, forwarding whatever is
		// written to it through the cipher, encrypting as it goes
		ws := &cipher.StreamWriter{S: hc.w, W: &wb}
		_, err = ws.Write(b)
		if err != nil {
			panic(err)
		}
		log.Printf("  ->ctext:\r\n%s\r\n", hex.Dump(wb.Bytes()))

		ctrlStatOp := op

		err = binary.Write(hc.c, binary.BigEndian, &ctrlStatOp)
		if err == nil {
			// Write hmac LSB, payloadLen followed by payload
			err = binary.Write(hc.c, binary.BigEndian, hmacOut)
			if err == nil {
				err = binary.Write(hc.c, binary.BigEndian, payloadLen)
				if err == nil {
					n, err = hc.c.Write(wb.Bytes())
				}
			}
		}
	}
	hc.m.Unlock()

	if err != nil {
		//panic(err)
		log.Println(err)
	}
	return
}

func (hc *Conn) EnableChaff() {
	hc.chaff.shutdown = false
	hc.chaff.enabled = true
	log.Println("Chaffing ENABLED")
	hc.chaffHelper()
}

func (hc *Conn) DisableChaff() {
	hc.chaff.enabled = false
	log.Println("Chaffing DISABLED")
}

func (hc *Conn) ShutdownChaff() {
	hc.chaff.shutdown = true
	log.Println("Chaffing SHUTDOWN")
}

func (hc *Conn) SetupChaff(msecsMin uint, msecsMax uint, szMax uint) {
	hc.chaff.msecsMin = msecsMin //move these to params of chaffHelper() ?
	hc.chaff.msecsMax = msecsMax
	hc.chaff.szMax = szMax
}

// Helper routine to spawn a chaffing goroutine for each Conn
func (hc *Conn) chaffHelper() {
	go func() {
		for {
			var nextDuration int
			if hc.chaff.enabled {
				bufTmp := make([]byte, rand.Intn(int(hc.chaff.szMax)))
				min := int(hc.chaff.msecsMin)
				nextDuration = rand.Intn(int(hc.chaff.msecsMax)-min) + min
				_, _ = rand.Read(bufTmp)
				_, err := hc.WritePacket(bufTmp, CSOChaff)
				if err != nil {
					log.Println("[ *** error - chaffHelper quitting *** ]")
					hc.chaff.enabled = false
					break
				}
			}
			time.Sleep(time.Duration(nextDuration) * time.Millisecond)
			if hc.chaff.shutdown {
				log.Println("*** chaffHelper shutting down")
				break
			}

		}
	}()
}
