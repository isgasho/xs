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
	"math/big"
	"os"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
)

// Available ciphers for hkex.Conn
const (
	CAlgAES256     = iota
	CAlgTwofish128 // golang.org/x/crypto/twofish
	CAlgBlowfish64 // golang.org/x/crypto/blowfish
	CAlgNoneDisallowed
)

// Available HMACs for hkex.Conn (TODO: not currently used)
const (
	HmacSHA256 = iota
	HmacNoneDisallowed
)

/*TODO: HMAC derived from HKEx FA.*/
/* Support functionality to set up encryption after a channel has
been negotiated via hkexnet.go
*/
func (hc Conn) getStream(keymat *big.Int) (ret cipher.Stream) {
	var key []byte
	var block cipher.Block
	var ivlen int
	var err error

	copts := hc.cipheropts & 0xFF
	// TODO: each cipher alg case should ensure len(keymat.Bytes())
	// is >= 2*cipher.BlockSize (enough for both key and iv)
	switch copts {
	case CAlgAES256:
		key = keymat.Bytes()[0:aes.BlockSize]
		block, err = aes.NewCipher(key)
		ivlen = aes.BlockSize
		iv := keymat.Bytes()[aes.BlockSize : aes.BlockSize+ivlen]
		ret = cipher.NewOFB(block, iv)
		fmt.Printf("[cipher AES_256 (%d)]\n", copts)
		break
	case CAlgTwofish128:
		key = keymat.Bytes()[0:twofish.BlockSize]
		block, err = twofish.NewCipher(key)
		ivlen = twofish.BlockSize
		iv := keymat.Bytes()[twofish.BlockSize : twofish.BlockSize+ivlen]
		ret = cipher.NewOFB(block, iv)
		fmt.Printf("[cipher TWOFISH_128 (%d)]\n", copts)
		break
	case CAlgBlowfish64:
		key = keymat.Bytes()[0:blowfish.BlockSize]
		block, err = blowfish.NewCipher(key)
		ivlen = blowfish.BlockSize
		// N.b. Bounds enforcement of differing cipher algorithms
		// ------------------------------------------------------
		// cipher/aes and x/cipher/twofish appear to allow one to
		// pass an iv larger than the blockSize harmlessly to
		// cipher.NewOFB(); x/cipher/blowfish implementation will
		// segfault here if len(iv) is not exactly blowfish.BlockSize.
		//
		// I assume the other two check bounds and only
		// copy what's needed whereas blowfish does no such check.
		iv := keymat.Bytes()[blowfish.BlockSize : blowfish.BlockSize+ivlen]
		ret = cipher.NewOFB(block, iv)
		fmt.Printf("[cipher BLOWFISH_64 (%d)]\n", copts)
		break
	default:
		fmt.Printf("DOOFUS SET A VALID CIPHER ALG (%d)\n", copts)
		os.Exit(1)
	}

	hopts := (hc.cipheropts >> 8) & 0xFF
	switch hopts {
	case HmacSHA256:
		fmt.Printf("[nop HmacSHA256 (%d)]\n", hopts)
		break
	default:
		fmt.Printf("DOOFUS SET A VALID HMAC ALG (%d)\n", hopts)
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}

	return
}
