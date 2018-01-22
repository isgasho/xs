// Authentication routines for the HKExSh

package herradurakex

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"runtime"
)

func AuthUser(username string, authcookie string, fname string) (valid bool, allowedCmds string) {
	b, _ := ioutil.ReadFile(fname)
	r := csv.NewReader(bytes.NewReader(b))

	b = nil
	runtime.GC() // Paranoia and prob. not effective; kill authFile in b[]

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 3 // username:authCookie:disallowedCmdList (a,b,...)
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		if username == record[0] &&
			authcookie == record[1] {
			valid = true
			break
		}

		fmt.Println(record)
	}
	return
}
