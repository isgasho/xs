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

	"golang.org/x/crypto/twofish"
)

// Available ciphers for hkex.Conn
const (
	C_AES_256     = iota
	C_TWOFISH_128 // golang.org/x/crypto/twofish
	C_NONE_DISALLOWED
)

// Available HMACs for hkex.Conn (TODO: not currently used)
const (
	H_BOGUS = iota
	H_SHA256
	H_NONE_DISALLOWED
)

/*TODO: HMAC derived from HKEx FA.*/
/* Support functionality to set up encryption after a channel has
been negotiated via hkexnet.go
*/
func (hc Conn) getStream(keymat *big.Int) (ret cipher.Stream) {
	var key []byte
	var block cipher.Block
	var err error

	copts := hc.cipheropts & 0xFF
	switch copts {
	case C_AES_256:
		key = keymat.Bytes()[0:aes.BlockSize]
		block, err = aes.NewCipher(key)
		iv := make([]byte, aes.BlockSize)
		//if _, err = io.ReadFull(crand.Reader, iv); err != nil {
		//	panic(err)
		//}
		iv = keymat.Bytes()[aes.BlockSize:]
		ret = cipher.NewOFB(block, iv)
		fmt.Printf("[cipher AES_256 (%d)]\n", copts)
		break
	case C_TWOFISH_128:
		key = keymat.Bytes()[0:twofish.BlockSize]
		block, err = twofish.NewCipher(key)
		iv := make([]byte, twofish.BlockSize)
		//if _, err = io.ReadFull(crand.Reader, iv); err != nil {
		//	panic(err)
		//}
		iv = keymat.Bytes()[twofish.BlockSize:]
		ret = cipher.NewOFB(block, iv)
		fmt.Printf("[cipher TWOFISH_256 (%d)]\n", copts)
		break
	default:
		fmt.Printf("DOOFUS SET A VALID CIPHER ALG (%d)\n", copts)
		block, err = nil, nil
		os.Exit(1)
	}

	hopts := (hc.cipheropts >> 8) & 0xFF
	switch hopts {
		case H_BOGUS:
		fmt.Printf("[nop H_BOGUS (%d)]\n", hopts)
		break
	case H_SHA256:
		fmt.Printf("[nop H_SHA256 (%d)]\n", hopts)
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
