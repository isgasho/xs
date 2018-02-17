package herradurakex

/* Support functions to set up encryption once an HKEx Conn has been
established with FA exchange and support channel operations
(echo, file-copy, remote-cmd, ...) */

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"math/big"
	"os"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
	// hash algos must be manually imported thusly:
	// (Would be nice if the golang pkg docs were more clear
	// on this...)
	_ "crypto/sha256"
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
func (hc Conn) getStream(keymat *big.Int) (rc cipher.Stream, mc hash.Hash) {
	var key []byte
	var block cipher.Block
	var iv []byte
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
		iv = keymat.Bytes()[aes.BlockSize : aes.BlockSize+ivlen]
		rc = cipher.NewOFB(block, iv)
		log.Printf("[cipher AES_256 (%d)]\n", copts)
		break
	case CAlgTwofish128:
		key = keymat.Bytes()[0:twofish.BlockSize]
		block, err = twofish.NewCipher(key)
		ivlen = twofish.BlockSize
		iv = keymat.Bytes()[twofish.BlockSize : twofish.BlockSize+ivlen]
		rc = cipher.NewOFB(block, iv)
		log.Printf("[cipher TWOFISH_128 (%d)]\n", copts)
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
		iv = keymat.Bytes()[blowfish.BlockSize : blowfish.BlockSize+ivlen]
		rc = cipher.NewOFB(block, iv)
		log.Printf("[cipher BLOWFISH_64 (%d)]\n", copts)
		break
	default:
		log.Printf("[invalid cipher (%d)]\n", copts)
		fmt.Printf("DOOFUS SET A VALID CIPHER ALG (%d)\n", copts)
		os.Exit(1)
	}

	hopts := (hc.cipheropts >> 8) & 0xFF
	switch hopts {
	case HmacSHA256:
		log.Printf("[hash HmacSHA256 (%d)]\n", hopts)
		halg := crypto.SHA256
		mc = halg.New()
		if !halg.Available() {
			log.Fatal("hash not available!")
		}
		break
	default:
		log.Printf("[invalid hmac (%d)]\n", hopts)
		fmt.Printf("DOOFUS SET A VALID HMAC ALG (%d)\n", hopts)
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}

	// Feed the IV into the hmac: all traffic in the connection must
	// feed its data into the hmac afterwards, so both ends can xor
	// that with the stream to detect corruption.
	_, _ = mc.Write(iv)
	var currentHash []byte
	currentHash = mc.Sum(currentHash)
	log.Printf("Channel init hmac(iv):%s\n", hex.EncodeToString(currentHash))

	return
}
