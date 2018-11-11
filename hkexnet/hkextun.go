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
	if (*hc.tuns) == nil {
		(*hc.tuns) = make(map[uint16]*TunEndpoint)
	}
	if (*hc.tuns)[rp] == nil {
		var addrs []net.Addr
		if p == "" {
			addrs, _ = net.InterfaceAddrs()
			p = addrs[0].String()
		}
		(*hc.tuns)[rp] = &TunEndpoint{ /*Status: CSOTunSetup,*/ Peer: p,
			Lport: lp, Rport: rp, Data: make(chan []byte, 1),
			Ctl: make(chan rune, 1)}
		logger.LogDebug(fmt.Sprintf("InitTunEndpoint [%d:%s:%d]", lp, p, rp))
	} else {
		logger.LogDebug(fmt.Sprintf("InitTunEndpoint [reusing] [%d:%s:%d]", (*hc.tuns)[rp].Lport, (*hc.tuns)[rp].Peer, (*hc.tuns)[rp].Rport))
	}
	return
}

func (hc *Conn) StartClientTunnel(lport, rport uint16) {
	hc.InitTunEndpoint(lport, "", rport)
	t := (*hc.tuns)[rport] // for convenience
	var l HKExListener
	go func() {
		weAreListening := false
		for cmd := range t.Ctl {
			logger.LogDebug(fmt.Sprintf("[ClientTun] Listening for client tunnel port %d", lport))

			if cmd == 'a' && !weAreListening {
				l, e := net.Listen("tcp", fmt.Sprintf(":%d", lport))
				if e != nil {
					logger.LogDebug(fmt.Sprintf("[ClientTun] Could not get lport %d! (%s)", lport, e))
				} else {
					weAreListening = true
					for {
						c, e := l.Accept()
						var tunDst bytes.Buffer
						// ask server to dial() its side, rport
						binary.Write(&tunDst, binary.BigEndian, lport)
						binary.Write(&tunDst, binary.BigEndian, rport)
						hc.WritePacket(tunDst.Bytes(), CSOTunSetup)

						if e != nil {
							logger.LogDebug(fmt.Sprintf("[ClientTun] Accept() got error(%v), hanging up.", e))
							break
						} else {
							logger.LogDebug(fmt.Sprintf("[ClientTun] Accepted tunnel client %v", t))

							// outside client -> tunnel lport
							go func() {
								defer func() {
									c.Close()
								}()

								var tunDst bytes.Buffer
								binary.Write(&tunDst, binary.BigEndian, lport)
								binary.Write(&tunDst, binary.BigEndian, rport)
								for {
									rBuf := make([]byte, 1024)
									//Read data from c, encrypt/write via hc to client(lport)
									n, e := c.Read(rBuf)
									if e != nil {
										if e == io.EOF {
											logger.LogDebug(fmt.Sprintf("[ClientTun] lport Disconnected: shutting down tunnel %v", t))
										} else {
											logger.LogDebug(fmt.Sprintf("[ClientTun] Read error from lport of tun %v\n%s", t, e))
										}
										hc.WritePacket(tunDst.Bytes(), CSOTunHangup)
										break
									}
									if n > 0 {
										rBuf = append(tunDst.Bytes(), rBuf[:n]...)
										_, de := hc.WritePacket(rBuf[:n+4], CSOTunData)
										if de != nil {
											logger.LogDebug(fmt.Sprintf("[ClientTun] Error writing to tunnel %v, %s]\n", t, de))
											break
										}
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
										_, e := c.Write(bytes)
										if e != nil {
											logger.LogDebug(fmt.Sprintf("[ClientTun] lport conn closed"))
											break
										}
									} else {
										logger.LogDebug(fmt.Sprintf("[ClientTun] Channel closed?"))
										break
									}
								}
							}()

						} // end Accept() worker block
					} // end for-accept
				} // end Listen() block
			} else if cmd == 'r' {
				logger.LogDebug(fmt.Sprintf("[ClientTun] Server replied TunRefused %v\n", t))
			} else if cmd == 'x' {
				logger.LogDebug(fmt.Sprintf("[ClientTun] Server replied TunDisconn, closing lport %v\n", t))
				l.Close()
				weAreListening = false
			}
		} // end t.Ctl for
	}()
}

func (hc *Conn) StartServerTunnel(lport, rport uint16) {
	hc.InitTunEndpoint(lport, "", rport)
	t := (*hc.tuns)[rport] // for convenience
	var err error

	go func() {
		weAreDialled := false
		for cmd := range t.Ctl {
			var c net.Conn
			logger.LogDebug(fmt.Sprintf("[ServerTun] got Ctl '%c'. weAreDialled: %v", cmd, weAreDialled))
			if cmd == 'd' && !weAreDialled {
				logger.LogDebug("[ServerTun] dialling...")
				c, err = net.Dial("tcp", fmt.Sprintf(":%d", rport))
				if err != nil {
					logger.LogDebug(fmt.Sprintf("[ServerTun] Dial() error for tun %v: %s", t, err))
					var resp bytes.Buffer
					binary.Write(&resp, binary.BigEndian /*lport*/, uint16(0))
					binary.Write(&resp, binary.BigEndian, rport)
					hc.WritePacket(resp.Bytes(), CSOTunRefused)
				} else {
					logger.LogDebug(fmt.Sprintf("[ServerTun] Tunnel Opened - %v", t))
					weAreDialled = true
					var resp bytes.Buffer
					binary.Write(&resp, binary.BigEndian, lport)
					binary.Write(&resp, binary.BigEndian, rport)
					logger.LogDebug(fmt.Sprintf("[ServerTun] Writing CSOTunSetupAck %v", t))
					hc.WritePacket(resp.Bytes(), CSOTunSetupAck)

					//
					// worker to read data from the rport (to encrypt & send to client)
					//
					go func() {
						defer func() {
							logger.LogDebug("[ServerTun] (deferred hangup workerA)")
							c.Close()
							weAreDialled = false
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
									logger.LogDebug(fmt.Sprintf("[ServerTun] rport Disconnected: shutting down tunnel %v", t))
								} else {
									logger.LogDebug(fmt.Sprintf("[ServerTun] Read error from rport of tun %v: %s", t, e))
								}
								var resp bytes.Buffer
								binary.Write(&resp, binary.BigEndian, lport)
								binary.Write(&resp, binary.BigEndian, rport)
								hc.WritePacket(resp.Bytes(), CSOTunDisconn)
								logger.LogDebug(fmt.Sprintf("[ServerTun] Closing server rport %d net.Dial()", t.Rport))
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
							logger.LogDebug("[ServerTun] (deferred hangup workerB)")
							c.Close()
							weAreDialled = false
						}()

						for {
							rData, ok := <-t.Data
							if ok {
								_, e := c.Write(rData)
								if e != nil {
									logger.LogDebug(fmt.Sprintf("[ServerTun] ERROR writing to rport conn"))
									break
								}
							} else {
								logger.LogDebug("[ServerTun] ERROR reading from hc.tuns[] channel - closed?")
								break
							}
						}
					}()
				}
			} else if cmd == 'h' {
				// client side has hung up
				logger.LogDebug(fmt.Sprintf("[ServerTun] Client hung up on rport %v", t))
			}
		} // t.Ctl read loop
		logger.LogDebug("[ServerTun] Tunnel exiting t.Ctl read loop - channel closed??")
	}()
}
