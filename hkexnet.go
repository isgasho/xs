/* -*- go -*-
 *  $RCSfile$ $Revision$ : $Date$ : $Author$
 *
 *  Description
 *
 *  Notes
 *
 **************
 *
 *  Copyright (c) 2018 Russtopia Labs. All Rights Reserved.
 *
 * This document may not, in whole or in part, be copied, photocopied,
 * reproduced, translated, or reduced to any electronic medium or machine
 * readable form without prior written consent from Russtopia Labs.
 */
package herradurakex

import (
	"fmt"
	"math/big"
	"net"
)

/*---------------------------------------------------------------------*/

type Conn struct {
	c net.Conn // which also implements io.Reader, io.Writer, ...
	h *HerraduraKEx
}

// Dial as net.Dial(), but with implicit HKEx PeerD read on connect
func Dial(protocol string, ipport string) (hc *Conn, err error) {
	c, err := net.Dial(protocol, ipport)
	if err != nil {
		return nil, err
	}
	hc = &Conn{c, New(0, 0)}

	// KEx
	fmt.Fprintf(c, "0x%s\n", hc.h.d.Text(16))

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return nil, err
	}
	hc.h.PeerD = d
	fmt.Printf("** D:%s\n", hc.h.d.Text(16))
	fmt.Printf("**(c)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	fmt.Printf("**(c)** FA:%s\n", hc.h.fa)
	return
}

func (hc *Conn) Close() (err error) {
	err = hc.c.Close()
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

func (hl *HKExListener) Accept() (hc Conn, err error) {
	c, err := hl.l.Accept()

	fmt.Println("[Accepted]")
	if err != nil {
		return Conn{nil, nil}, err
	}
	hc = Conn{c, New(0, 0)}

	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		fmt.Println("[Error]")
		return hc, err
	}
	hc.h.PeerD = d
	fmt.Printf("** D:%s\n", hc.h.d.Text(16))
	fmt.Printf("**(s)** peerD:%s\n", hc.h.PeerD.Text(16))
	hc.h.FA()
	fmt.Printf("**(s)** FA:%s\n", hc.h.fa)

	// KEx
	fmt.Fprintf(c, "0x%s\n", hc.h.d.Text(16))

	return
}

/*---------------------------------------------------------------------*/
func (hc Conn) Read(b []byte) (n int, err error) {
	n, err = hc.c.Read(b)
	fmt.Printf("[Decrypting...]\n")
	fmt.Printf("[ciphertext:%+v]\n", b[0:n])
	for i := 0; i < n; i++ {
		//for i, _ := range b {
		// FOR TESTING ONLY!! USE REAL CRYPTO HERE
		//b[i] ^= byte( hc.h.d.Mod(hc.h.d, big.NewInt(int64(c))).Int64() )
		b[i] ^= hc.h.fa.Bytes()[0]
	}
	fmt.Printf("[plaintext:%+v]\n", b[0:n])
	return
}

func (hc Conn) Write(b []byte) (n int, err error) {
	fmt.Printf("[Encrypting...]\n")
	for i, _ := range b {
		// FOR TESTING ONLY!! USE REAL CRYPTO HERE
		//b[i] ^= byte( hc.h.d.Mod(hc.h.d, big.NewInt(int64(c))).Int64() )
		b[i] ^= hc.h.fa.Bytes()[0]
	}
	fmt.Printf("[ciphertext:%+v]\n", b)
	n, err = hc.c.Write(b)
	return
}

// Return c coerced into a HKEx Conn (which implements interface net.Conn)
//   Only useful if one wants to convert an open connection later to HKEx
//   (Use Dial() instead to start with HKEx automatically.)
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
