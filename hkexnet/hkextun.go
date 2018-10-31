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
	"log"
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
		Rport  uint16      // Names are from client's perspective
		Lport  uint16      // ... ie., RPort is on server, LPort is on client
		Peer   string      //net.Addr
		tunCtl chan<- rune //See TunCtl_* consts
	}

	TunPacket struct {
		n    uint32
		data []byte
	}
)

func startServerTunnel(hc *Conn, lport, rport uint16) {
	if hc.tuns == nil {
		hc.tuns = make(map[uint16]chan []byte)
	}
	if hc.tuns[rport] == nil {
		hc.tuns[rport] = make(chan []byte, 32)
	}

	addrs, _ := net.InterfaceAddrs()
	t := TunEndpoint{Peer: addrs[0].String(), Lport: lport, Rport: rport}
	var resp bytes.Buffer
	binary.Write(&resp, binary.BigEndian, t.Lport)

	//var dialHangup chan<- bool

	c, err := net.Dial("tcp", fmt.Sprintf(":%d", rport))
	if err != nil {
		logger.LogErr(fmt.Sprintf("Nothing is serving at rport :%d!", rport))
		binary.Write(&resp, binary.BigEndian, uint16(0))
		// Inform client of the tunPort
		hc.WritePacket(resp.Bytes(), CSOTunRefused)
	} else {
		binary.Write(&resp, binary.BigEndian, t.Rport)
		logger.LogNotice(fmt.Sprintf("[Tunnel Opened - %d:%s:%d]", t.Lport, t.Peer, t.Rport))

		//
		// worker to read data from the rport (to encrypt & send to client)
		//
		go func() {
			defer func() {
				//if hc.tuns[rport] != nil {
				//	close(hc.tuns[rport])
				//	hc.tuns[rport] = nil
				//}
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
						logger.LogNotice(fmt.Sprintf("rport Disconnected: shutting down tunnel %v\n", t))
					} else {
						logger.LogErr(fmt.Sprintf("Read error from rport of tun %v\n%s", t, e))
					}
					hc.WritePacket(resp.Bytes(), CSOTunClose)
					fmt.Printf("Closing server rport net.Dial()\n")
					break
				}
				if n > 0 {
					rBuf = append(tunDst.Bytes(), rBuf[:n]...)
					logger.LogNotice(fmt.Sprintf("Got rport data:%v", tunDst.Bytes()))
					hc.WritePacket(rBuf[:n+4], CSOTunData)
				}
			}
		}()

		// worker to read data from client (already decrypted) & fwd to rport
		go func() {
			defer func() {
				//if hc.tuns[rport] != nil {
				//close(hc.tuns[rport])
				//hc.tuns[rport] = nil
				//}
				c.Close()
			}()

			for {
				rData, ok := <-hc.tuns[rport]
				if ok {
					logger.LogNotice(fmt.Sprintf("Got client data:%v", rData))
					c.Write(rData)
				} else {
					logger.LogErr("!!! ERROR reading from hc.tuns[] channel !!!")
					break
				}
			}
		}()

		// Inform client of the tunPort
		hc.WritePacket(resp.Bytes(), CSOTunAck)
	}
}

func StartClientTunnel(hc *Conn, lport, rport uint16) {
	go func() {
		if hc.tuns == nil {
			hc.tuns = make(map[uint16]chan []byte)
		}
		if hc.tuns[rport] == nil {
			hc.tuns[rport] = make(chan []byte, 32)
		}

		l, e := net.Listen("tcp", fmt.Sprintf(":%d", lport))
		if e != nil {
			fmt.Printf("[Could not get lport %d! (%s)\n", lport, e)
		} else {
			defer l.Close()
			for {
				c, e := l.Accept()

				defer func() {
					//if hc.tuns[rport] != nil {
					//	close(hc.tuns[rport])
					//	hc.tuns[rport] = nil
					//}
					c.Close()
				}()

				if e != nil {
					log.Printf("Accept() got error(%v), hanging up.\n", e)
					break
					//log.Fatal(err)
				} else {
					log.Println("Accepted client")

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
									logger.LogNotice(fmt.Sprintf("lport Disconnected: shutting down tunnel [%d:%d]\n", lport, rport))
								} else {
									logger.LogErr(fmt.Sprintf("Read error from lport of tun [%d:%d]\n%s", lport, rport, e))
								}
								hc.WritePacket(tunDst.Bytes(), CSOTunClose)
								break
							}
							if n > 0 {
								rBuf = append(tunDst.Bytes(), rBuf[:n]...)
								logger.LogNotice(fmt.Sprintf("Got lport data:%v\n", tunDst.Bytes()))
								hc.WritePacket(rBuf[:n+4], CSOTunData)
							}
						}
					}()

					// tunnel lport -> outside client (c)
					go func() {
						defer func() {
							//if hc.tuns[rport] != nil {
							//	close(hc.tuns[rport])
							//	hc.tuns[rport] = nil
							//}
							c.Close()
						}()

						for {
							//fmt.Printf("Reading from client hc.tuns[%d]\n", lport)
							bytes, ok := <-hc.tuns[rport]
							if ok {
								//fmt.Printf("[Got this through tunnel:%v]\n", bytes)
								c.Write(bytes)
							} else {
								fmt.Printf("[Channel closed?]\n")
								//break
							}
						}
					}()

				}
			}
		}
	}()
}
