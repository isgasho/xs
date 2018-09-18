// consts.go - consts for hkexnet

// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package hkexnet

const (
	KEX_HERRADURA = iota // this MUST be first for default if omitted in ctor
	KEX_FOO
	//KEX_DH
	//KEX_ETC
)

// const CSExtendedCode - extended (>255 UNIX exit status) codes
// This indicate channel-related or internal errors
const (
	CSENone        = 32 + iota
	CSEBadAuth     // Failed login password
	CSETruncCSO    // No CSOExitStatus in payload
	CSEStillOpen   // Channel closed unexpectedly
	CSEExecFail    // cmd.Start() (exec) failed
	CSEPtyExecFail // pty.Start() (exec w/pty) failed
)

const (
	CSONone        = iota // No error, normal packet
	CSOHmacInvalid        // HMAC mismatch detected on remote end
	CSOTermSize           // set term size (rows:cols)
	CSOExitStatus         // Remote cmd exit status
	CSOChaff              // Dummy packet, do not pass beyond decryption
)

const MAX_PAYLOAD_LEN = 4*1024*1024*1024 - 1

