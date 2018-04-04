// Authentication routines for the HKExSh

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

	b = nil
	runtime.GC() // Paranoia and prob. not effective; kill authFile in b[]

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
	return
}
