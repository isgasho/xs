// +build linux
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	hkexsh "blitter.com/go/hkexsh"
)

// Handle pty resizes (notify server side)
func handleTermResizes(conn *hkexsh.Conn) {
	rows := 0
	cols := 0

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	wg.Add(1)
	go func() {
		defer wg.Done()

		for range ch {
			// Query client's term size so we can communicate it to server
			// pty after interactive session starts
			cols, rows, err = GetSize()
			log.Printf("[rows %v cols %v]\n", rows, cols)
			if err != nil {
				log.Println(err)
			}
			termSzPacket := fmt.Sprintf("%d %d", rows, cols)
			conn.WritePacket([]byte(termSzPacket), hkexsh.CSOTermSize)
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.
}
