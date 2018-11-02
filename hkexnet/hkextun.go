// hkextun.go - Tunnel setup using an established hkexnet.Conn

// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

package hkexnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"blitter.com/go/hkexsh/logger"
)

type (
	// Tunnels
	// --
	// 1. client is given (lport, remhost, rport) by local user
	// 2. client sends [CSOTunReq:rport] to server
	// client=> [CSOTunReq:rport] =>remhost
	//
	// remhost starts worker to receive/send data using rport
	// remhost replies to client with rport to acknowledge tun is ready
	// client<= [CSOTunAck:rport] <=remhost
	//   ... or if rhost rport refuses connection, sends
	//   [CSOTunRefused:rport]
	//
	// client starts worker to receive/send data using lport
	// ... client disconnects: sends remhost [CSOTunClose:rport]
	// ... or server disconnects: sends client [CSOTunClose:lport]
	//     server at any time sends [CSOTunRefused:rport] if daemon died
	// --

	// TunEndpoint [securePort:peer:dataPort]
	TunEndpoint struct {
		Rport uint16    // Names are from client's perspective
		Lport uint16    // ... ie., RPort is on server, LPort is on client
		Peer  string    //net.Addr
		Ctl   chan rune //See TunCtl_* consts
		Data  chan []byte
	}
)

func (hc *Conn) InitTunEndpoint(lp uint16, p string /* net.Addr */, rp uint16) {
	if hc.tuns == nil {
		hc.tuns = make(map[uint16]*TunEndpoint)
	}
	if hc.tuns[rp] == nil {
		var addrs []net.Addr
		if p == "" {
			addrs, _ = net.InterfaceAddrs()
			p = addrs[0].String()
		}
		hc.tuns[rp] = &TunEndpoint{ /*Status: CSOTunSetup,*/ Peer: p,
			Lport: lp, Rport: rp, Data: make(chan []byte, 1),
			Ctl: make(chan rune, 1)}
		logger.LogDebug(fmt.Sprintf("InitTunEndpoint [%d:%s:%d]\n", lp, p, rp))
	}
	return
}

func (hc *Conn) StartClientTunnel(lport, rport uint16) {
	hc.InitTunEndpoint(lport, "", rport)
	t := hc.tuns[rport] // for convenience

	go func() {
		logger.LogDebug(fmt.Sprintf("Listening for client tunnel port %d", lport))
		l, e := net.Listen("tcp", fmt.Sprintf(":%d", lport))
		if e != nil {
			logger.LogDebug(fmt.Sprintf("[Could not get lport %d! (%s)", lport, e))
		} else {
			defer l.Close()
			for {
				c, e := l.Accept()

				defer func() {
					c.Close()
				}()

				if e != nil {
					logger.LogDebug(fmt.Sprintf("Accept() got error(%v), hanging up.", e))
					break
				} else {
					logger.LogDebug(fmt.Sprintln("Accepted tunnel client"))

					// outside client -> tunnel lport
					go func() {
						var tunDst bytes.Buffer
						binary.Write(&tunDst, binary.BigEndian, lport)
						binary.Write(&tunDst, binary.BigEndian, rport)
						for {
							rBuf := make([]byte, 1024)
							//Read data from c, encrypt/write via hc to client(lport)
							n, e := c.Read(rBuf)
							if e != nil {
								if e == io.EOF {
									logger.LogDebug(fmt.Sprintf("lport Disconnected: shutting down tunnel [%d:%d]", lport, rport))
								} else {
									logger.LogDebug(fmt.Sprintf("Read error from lport of tun [%d:%d]\n%s", lport, rport, e))
								}
								hc.WritePacket(tunDst.Bytes(), CSOTunHangup)
								break
							}
							if n > 0 {
								rBuf = append(tunDst.Bytes(), rBuf[:n]...)
								hc.WritePacket(rBuf[:n+4], CSOTunData)
							}
						}
					}()

					// tunnel lport -> outside client (c)
					go func() {
						defer func() {
							c.Close()
						}()

						for {
							bytes, ok := <-t.Data
							if ok {
								c.Write(bytes)
							} else {
								logger.LogDebug(fmt.Sprintf("[Channel closed?]\n"))
								break
							}
						}
					}()

				}
			}
		}
	}()
}

func (hc *Conn) StartServerTunnel(lport, rport uint16) {
	hc.InitTunEndpoint(lport, "", rport)
	t := hc.tuns[rport] // for convenience

	//go func() {
	//	for cmd := range t.Ctl {
	//		var c net.Conn
	//		if cmd == 'a' {
	logger.LogDebug("Server dialling...")
	c, err := net.Dial("tcp", fmt.Sprintf(":%d", rport))
	if err != nil {
		logger.LogDebug(fmt.Sprintf("Nothing is serving at rport :%d!", rport))
		var resp bytes.Buffer
		binary.Write(&resp, binary.BigEndian, /*lport*/uint16(0))
		binary.Write(&resp, binary.BigEndian, rport)
		hc.WritePacket(resp.Bytes(), CSOTunRefused)
	} else {
		logger.LogDebug(fmt.Sprintf("[Tunnel Opened - %d:%s:%d]", lport, t.Peer, rport))
		var resp bytes.Buffer
		binary.Write(&resp, binary.BigEndian, lport)
		binary.Write(&resp, binary.BigEndian, rport)
		logger.LogDebug(fmt.Sprintf("[Writing CSOTunSetupAck[%d:%d]", lport, rport))
		hc.WritePacket(resp.Bytes(), CSOTunSetupAck)

		//
		// worker to read data from the rport (to encrypt & send to client)
		//
		go func() {
			defer func() {
				c.Close()
			}()

			var tunDst bytes.Buffer
			binary.Write(&tunDst, binary.BigEndian, t.Lport)
			binary.Write(&tunDst, binary.BigEndian, t.Rport)
			for {
				rBuf := make([]byte, 1024)
				// Read data from c, encrypt/write via hc to client(lport)
				n, e := c.Read(rBuf)
				if e != nil {
					if e == io.EOF {
						logger.LogDebug(fmt.Sprintf("rport Disconnected: shutting down tunnel %v\n", t))
					} else {
						logger.LogDebug(fmt.Sprintf("Read error from rport of tun %v\n%s", t, e))
					}
					var resp bytes.Buffer
					binary.Write(&resp, binary.BigEndian, lport)
					binary.Write(&resp, binary.BigEndian, rport)
					hc.WritePacket(resp.Bytes(), CSOTunDisconn)
					logger.LogDebug(fmt.Sprintf("Closing server rport %d net.Dial()", t.Rport))
					break
				}
				if n > 0 {
					rBuf = append(tunDst.Bytes(), rBuf[:n]...)
					hc.WritePacket(rBuf[:n+4], CSOTunData)
				}
			}
		}()

		// worker to read data from client (already decrypted) & fwd to rport
		go func() {
			defer func() {
				c.Close()
			}()

			for {
				rData, ok := <-t.Data
				if ok {
					c.Write(rData)
				} else {
					logger.LogDebug("[ERROR reading from hc.tuns[] channel - closed?]")
					break
				}
			}
		}()
	}
	//		} else if cmd == 'h' {
	//			logger.LogDebug("[Server hanging up on rport on behalf of client]")
	//			c.Close()
	//		} else {
	//			logger.LogDebug("[ERR: this should be unreachable]")
	//		}
	//	} // t.Ctl read loop
	//	logger.LogDebug("[ServerTunnel() exiting t.Ctl read loop - channel closed??]")
	//}()
}
