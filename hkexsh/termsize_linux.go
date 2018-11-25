// +build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"blitter.com/go/hkexsh/hkexnet"
)

// Handle pty resizes (notify server side)
func handleTermResizes(conn *hkexnet.Conn) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	wg.Add(1)
	go func() {
		defer wg.Done()

		for range ch {
			// Query client's term size so we can communicate it to server
			// pty after interactive session starts
			cols, rows, err := GetSize()
			log.Printf("[rows %v cols %v]\n", rows, cols)
			if err != nil {
				log.Println(err)
			}
			termSzPacket := fmt.Sprintf("%d %d", rows, cols)
			conn.WritePacket([]byte(termSzPacket), hkexnet.CSOTermSize) // nolint: errcheck,gosec
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.
}
