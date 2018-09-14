// Authentication routines for the HKExSh
//
// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

package hkexsh

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/user"
	"runtime"

	"github.com/jameskeane/bcrypt"
)

func AuthUserByPasswd(username string, auth string, fname string) (valid bool, allowedCmds string) {
	b, e := ioutil.ReadFile(fname)
	if e != nil {
		valid = false
		log.Println("ERROR: Cannot read hkexsh.passwd file!")
		log.Fatal(e)
	}
	r := csv.NewReader(bytes.NewReader(b))

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 3 // username:salt:authCookie [TODO:disallowedCmdList (a,b,...)]
	for {
		record, err := r.Read()
		if err == io.EOF {
			// Use dummy entry if user not found
			// (prevent user enumeration attack via obvious timing diff;
			// ie., not attempting any auth at all)
			record = []string{"$nosuchuser$",
				"$2a$12$l0coBlRDNEJeQVl6GdEPbU",
				"$2a$12$l0coBlRDNEJeQVl6GdEPbUC/xmuOANvqgmrMVum6S4i.EXPgnTXy6"}
			username = "$nosuchuser$"
			err = nil
		}
		if err != nil {
			log.Fatal(err)
		}

		if username == record[0] {
			tmp, _ := bcrypt.Hash(auth, record[1])
			if tmp == record[2] && username != "$nosuchuser$" {
				valid = true
			}
			break
		}
	}
	// Security scrub
	for i := range b {
		b[i] = 0
	}
	b = nil
	r = nil
	runtime.GC()

	return
}

func AuthUserByToken(username string, connhostname string, auth string) (valid bool) {
	u, ue := user.Lookup(username)
	if ue != nil {
		return false
	}

	b, e := ioutil.ReadFile(fmt.Sprintf("%s/.hkexsh_id", u.HomeDir))
	if e != nil {
		log.Printf("INFO: Cannot read %s/.hkexsh_id\n", u.HomeDir)
		return false
	}

	if string(b) == auth {
		return true
	}
	return
}
