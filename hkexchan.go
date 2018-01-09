/*  Herradura - a Key exchange scheme in the style of Diffie-Hellman Key Exchange.
    Copyright (C) 2017 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    golang implementation by Russ Magee (rmagee_at_gmail.com) */
package herradurakex

/* Support functions to set up encryption once an HKEx Conn has been
 established with FA exchange */

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"math/big"
	"os"
)

const (
	C_AES_256 = 0
)

const (
	H_SHA256 = 0
)

/*TODO: HMAC derived from HKEx FA.*/
/* Support functionality to set up encryption after a channel has
been negotiated via hkexnet.go
*/
func (hc Conn) getStreamReader(keymat *big.Int, flags uint32, r io.Reader) (ret *cipher.StreamReader) {
	var key []byte
	var block cipher.Block
	var err error

	// 256 algs should be enough for everybody.(tm)
	cipherAlg := (flags & 8)
	//TODO: flags for HMAC from keymat
	switch cipherAlg {
	case C_AES_256:
		key = keymat.Bytes()[0:aes.BlockSize]
		block, err = aes.NewCipher(key)
		break
	default:
		fmt.Println("DOOFUS SET A VALID CIPHER ALG")
		block, err = aes.NewCipher(key)
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	ret = &cipher.StreamReader{S: stream, R: r}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.
	return
}

func (hc Conn) getStreamWriter(keymat *big.Int, flags uint32, w io.Writer) (ret *cipher.StreamWriter) {
	var key []byte
	var block cipher.Block
	var err error

	// 256 algs should be enough for everybody.(tm)
	cipherAlg := (flags & 8)
	//TODO: flags for HMAC from keymat
	switch cipherAlg {
	case C_AES_256:
		key = keymat.Bytes()[0:aes.BlockSize]
		block, err = aes.NewCipher(key)
		break
	default:
		fmt.Println("DOOFUS SET A VALID CIPHER ALG")
		block, err = aes.NewCipher(key)
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	ret = &cipher.StreamWriter{S: stream, W: w}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.
	return
}
