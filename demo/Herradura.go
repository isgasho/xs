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
package main

import (
	"flag"
	"fmt"

	hkex "blitter.com/herradurakex"
)

func main() {
	var s int //MUST be 2^n where n is an integer
	var p int //Amount of bits to share (a,a,b,b2)

	flag.IntVar(&s, "s", 256, "Size in bits of secret (fa,fa2)")
	flag.IntVar(&p, "p", 64, "Size in bits of shared public portion (b,b2)")
	flag.Parse()

	fmt.Printf("s=%v p=%v\n", s, p)

	hkexAlice := hkex.New(s, p)
	hkexBob := hkex.New(s, p)

	fmt.Println("ALICE:")
	fmt.Println(hkexAlice)

	fmt.Println("BOB:")
	fmt.Println(hkexBob)

	// Alice and Bob exchange D
	// (This, of course, would occur over a public channel between peers)
	// hkexAlice and hkexBob would each be in separate contexts
	// (processes, client/server etc.)
	hkexBob.PeerD = hkexAlice.D()
	hkexAlice.PeerD = hkexBob.D()

	hkexAlice.FA()
	fmt.Println(hkexAlice)

	hkexBob.FA()
	fmt.Println(hkexBob)
}
