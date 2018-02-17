// Util to generate/store passwords for users in a file akin to /etc/passwd
// suitable for the demo hkexsh server, using bcrypt.
package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"

	hkex "github.com/Russtopia/hkexsh"
	"github.com/jameskeane/bcrypt"
)

func main() {
	var pfName string
	var newpw string
	var confirmpw string
	var userName string

	flag.StringVar(&userName, "u", "", "username")
	flag.StringVar(&pfName, "f", "/etc/hkexsh.passwd", "passwd file")
	flag.Parse()

	var uname string
	if len(userName) == 0 {
		log.Println("specify username with -u")
		os.Exit(1)
	}

	u, err := user.Lookup(userName)
	if err != nil {
		log.Printf("Invalid user %s\n", userName)
		log.Fatal(err)
	}
	uname = u.Username

	fmt.Printf("New Password:")
	ab, err := hkex.ReadPassword(int(os.Stdin.Fd()))
	fmt.Printf("\r\n")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	newpw = string(ab)

	fmt.Printf("Confirm:")
	ab, err = hkex.ReadPassword(int(os.Stdin.Fd()))
	fmt.Printf("\r\n")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	confirmpw = string(ab)

	if confirmpw != newpw {
		log.Println("New passwords do not match.")
		os.Exit(1)
	}

	// generate a random salt with specific rounds of complexity
	// (default in jameskeane/bcrypt is 12 but we'll be explicit here)
	salt, err := bcrypt.Salt(12)
	if err != nil {
		fmt.Println("ERROR: bcrypt.Salt() failed.")
		os.Exit(2)
	}

	// hash and verify a password with explicit (random) salt
	hash, err := bcrypt.Hash(newpw, salt)
	if err != nil || !bcrypt.Match(newpw, hash) {
		fmt.Println("ERROR: bcrypt.Match() failed.")
		log.Fatal(err)
	}
	//fmt.Println("Salt:", salt, "Hash:", hash)

	b, err := ioutil.ReadFile(pfName)
	if err != nil {
		log.Fatal(err)
	}
	r := csv.NewReader(bytes.NewReader(b))

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 4 // username:salt:authCookie:disallowedCmdList (a,b,...)

	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	for i, _ := range records {
		//fmt.Println(records[i])
		if records[i][0] == uname {
			records[i][1] = salt
			records[i][2] = hash
		}
		//// csv lib doesn't preserve comment in record, so put it back
		//if records[i][0][0] == '!' {
		//	records[i][0] = "#" + records[i][0]
		//}
	}

	outFile, err := ioutil.TempFile("", "hkexsh-passwd")
	if err != nil {
		log.Fatal(err)
	}
	w := csv.NewWriter(outFile)
	w.Comma = ':'
	//w.FieldsPerRecord = 4 // username:salt:authCookie:disallowedCmdList (a,b,...)
	w.Write([]string{"#username", "salt", "authCookie", "disallowedCmdList"})
	w.WriteAll(records)
	if err = w.Error(); err != nil {
		log.Fatal(err)
	}

	err = os.Remove(pfName)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Rename(outFile.Name(), pfName)
	if err != nil {
		log.Fatal(err)
	}
}
