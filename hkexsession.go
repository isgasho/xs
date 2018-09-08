// Session info/routines for the HKExSh
//
// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

package hkexsh

import (
	"fmt"
	"runtime"
)

type Session struct {
	op         []byte
	who        []byte
	termtype   []byte // client initial $TERM
	cmd        []byte
	authCookie []byte
	status     uint32 // exit status (0-255 is std UNIX status)
}

// Output Session record as a string. Implements Stringer interface.
func (h *Session) String() string {
	return fmt.Sprintf("hkexsh.Session:\nOp:%v\nWho:%v\nCmd:%v\nAuthCookie:%v\nStatus:%v",
		h.op, h.who, h.cmd, h.AuthCookie(false), h.status)
}

func (h Session) Op() []byte {
	return h.op
}

func (h *Session) SetOp(o []byte) {
	h.op = o
}

func (h Session) Who() []byte {
	return h.who
}

func (h *Session) SetWho(w []byte) {
	h.who = w
}

func (h Session) TermType() []byte {
	return h.termtype
}

func (h *Session) SetTermType(t []byte) {
	h.termtype = t
}

func (h Session) Cmd() []byte {
	return h.cmd
}

func (h *Session) SetCmd(c []byte) {
	h.cmd = c
}

func (h Session) AuthCookie(reallyShow bool) []byte {
	if reallyShow {
		return h.authCookie
	} else {
		return []byte("**REDACTED**")
	}
}

func (h *Session) SetAuthCookie(a []byte) {
	h.authCookie = a
}

func (h *Session) ClearAuthCookie() {
	for i := range h.authCookie {
		h.authCookie[i] = 0
	}
	runtime.GC()
}

func (h Session) Status() uint32 {
	return h.status
}

func (h *Session) SetStatus(s uint32) {
	h.status = s
}

func NewSession(op, who, ttype, cmd, authcookie []byte, status uint32) *Session {
	return &Session{
		op:         op,
		who:        who,
		termtype:   ttype,
		cmd:        cmd,
		authCookie: authcookie,
		status:     status}
}
