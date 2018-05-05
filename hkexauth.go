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
	"io"
	"io/ioutil"
	"log"
	"runtime"

	"github.com/jameskeane/bcrypt"
)

func AuthUser(username string, auth string, fname string) (valid bool, allowedCmds string) {
	b, e := ioutil.ReadFile(fname)
	if e != nil {
		valid = false
		log.Println("ERROR: Cannot read hkexsh.passwd file!")
		log.Fatal(e)
	}
	r := csv.NewReader(bytes.NewReader(b))

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 4 // username:salt:authCookie:disallowedCmdList (a,b,...)
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		if username == record[0] {
			tmp, _ := bcrypt.Hash(auth, record[1])
			if tmp == record[2] {
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
