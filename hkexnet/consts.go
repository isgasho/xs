// consts.go - consts for hkexnet

// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package hkexnet

const (
	KEX_HERRADURA256 = iota // this MUST be first for default if omitted in ctor
	KEX_HERRADURA512
	KEX_HERRADURA1024
	KEX_HERRADURA2048
	KEX_resvd4
	KEX_resvd5
	KEX_resvd6
	KEX_resvd7
	KEX_KYBER512
	KEX_KYBER768
	KEX_KYBER1024
	KEX_resvd11
	KEX_resvd12
	KEX_resvd13
	KEX_resvd14
	KEX_resvd15
)

// Sent from client to server in order to specify which
// algo shall be used (eg., HerraduraKEx, [TODO: others...])
type KEXAlg uint8

// Extended exit status codes - indicate comm/pty issues
// rather than remote end normal UNIX exit codes
const (
	CSENone = 1024 + iota
	//CSEBadAuth     // Failed login password
	CSETruncCSO    // No CSOExitStatus in payload
	CSEStillOpen   // Channel closed unexpectedly
	CSEExecFail    // cmd.Start() (exec) failed
	CSEPtyExecFail // pty.Start() (exec w/pty) failed
)

// Extended (>255 UNIX exit status) codes
// This indicate channel-related or internal errors
type CSExtendedCode uint32

// Channel Status/Op bytes - packet types
const (
	// Main connection/session control
	CSONone        = iota // No error, normal packet
	CSOHmacInvalid        // HMAC mismatch detected on remote end
	CSOTermSize           // set term size (rows:cols)
	CSOExitStatus         // Remote cmd exit status
	CSOChaff              // Dummy packet, do not pass beyond decryption

	// Tunnel setup/control/status
	CSOTunSetup    // client -> server tunnel setup request (dstport)
	CSOTunSetupAck // server -> client tunnel setup ack
	CSOTunAccept   // client -> server: tunnel client got an Accept()
	// (Do we need a CSOTunAcceptAck server->client?)
	CSOTunRefused // server -> client: tunnel rport connection refused
	CSOTunData    // packet contains tunnel data [rport:data]
	CSOTunDisconn // server -> client: tunnel rport disconnected
	CSOTunHangup  // client -> server: tunnel lport hung up
)

// TunEndpoint.tunCtl control values - used to control workers for client or server tunnels
// depending on the code
const (
	TunCtl_Client_Listen = 'a'
	
	TunCtl_Server_Dial = 'd' // server has dialled OK, client side can accept() conns
	// [CSOTunAccept]
	// status: client listen() worker accepted conn on lport
	// action:server side should dial() rport on client's behalf

	TunCtl_Info_Hangup = 'h' // client side has hung up
	// [CSOTunHangup]
	// status: client side conn hung up from lport
	// action:server side should hang up on rport, on client's behalf

	TunCtl_Info_ConnRefused = 'r' // server side couldn't complete tunnel
	// [CSOTunRefused]
	// status:server side could not dial() remote side
	
	TunCtl_Info_LostConn = 'x' // server side disconnected
	// [CSOTunDisconn]
	// status:server side lost connection to rport
	// action:client should disconnect accepted lport connection
)

// Channel status Op byte type
type CSOType uint32

//TODO: this should be small (max unfragmented packet size?)
const MAX_PAYLOAD_LEN = 4*1024*1024*1024 - 1

const (
	CAlgAES256     = iota
	CAlgTwofish128 // golang.org/x/crypto/twofish
	CAlgBlowfish64 // golang.org/x/crypto/blowfish
	CAlgCryptMT1   //cryptmt using mtwist64
	CAlgNoneDisallowed
)

// Available ciphers for hkex.Conn
type CSCipherAlg uint32

const (
	HmacSHA256 = iota
	HmacSHA512
	HmacNoneDisallowed
)

// Available HMACs for hkex.Conn (TODO: not currently used)
type CSHmacAlg uint32
