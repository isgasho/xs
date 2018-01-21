package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"

	hkex "blitter.com/herradurakex"
	isatty "github.com/mattn/go-isatty"
	"golang.org/x/sys/unix"
)

type cmdSpec struct {
	op         []byte
	who        []byte
	cmd        []byte
	authCookie []byte
	status     int
}

// Demo of a simple client that dials up to a simple test server to
// send data.
//
// While conforming to the basic net.Conn interface HKex.Conn has extra
// capabilities designed to allow apps to define connection options,
// encryption/hmac settings and operations across the encrypted channel.
//
// Initial setup is the same as using plain net.Dial(), but one may
// specify extra extension tags (strings) to set the cipher and hmac
// setting desired; as well as the intended operation mode for the
// connection (app-specific, passed through to the server to use or
// ignore at its discretion).
func main() {
	var wg sync.WaitGroup

	var cAlg string
	var hAlg string
	var server string
	isInteractive := false

	flag.StringVar(&cAlg, "c", "C_AES_256", "cipher [\"C_AES_256\" | \"C_TWOFISH_128\" | \"C_BLOWFISH_64\"]")
	flag.StringVar(&hAlg, "h", "H_SHA256", "hmac [\"H_SHA256\"]")
	flag.StringVar(&server, "s", "localhost:2000", "server hostname/address[:port]")
	flag.Parse()

	//log.SetOutput(os.Stdout)
	log.SetOutput(ioutil.Discard)

	conn, err := hkex.Dial("tcp", server, cAlg, hAlg)
	if err != nil {
		fmt.Println("Err!")
		panic(err)
	}
	defer conn.Close()

	// Set stdin in raw mode if it's an interactive session
	if isatty.IsTerminal(os.Stdin.Fd()) {
		isInteractive = true
		oldState, err := MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			panic(err)
		}
		defer func() { _ = Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.
	} else {
		fmt.Println("NOT A TTY")
	}

	rec := &cmdSpec{op: []byte{'s'},
		who:        []byte("ABCD"),
		cmd:        []byte("EFGH"),
		authCookie: []byte("99"),
		status:     0}

	_, err = fmt.Fprintf(conn, "%d %d %d %d\n", len(rec.op), len(rec.who), len(rec.cmd), len(rec.authCookie))
	_, err = conn.Write(rec.op)
	_, err = conn.Write(rec.who)
	_, err = conn.Write(rec.cmd)
	_, err = conn.Write(rec.authCookie)

	//client reader (from server) goroutine
	wg.Add(1)
	go func() {
		// By deferring a call to wg.Done(),
		// each goroutine guarantees that it marks
		// its direction's stream as finished.
		//
		// Whichever direction's goroutine finishes first
		// will call wg.Done() once more, explicitly, to
		// hang up on the other side, so that this client
		// exits immediately on an EOF from either side.
		defer wg.Done()

		// io.Copy() expects EOF so this will
		// exit with inerr == nil
		_, inerr := io.Copy(os.Stdout, conn)
		if inerr != nil {
			if inerr.Error() != "EOF" {
				fmt.Println(inerr)
				os.Exit(1)
			}
		}
		if isInteractive {
			log.Println("[Got EOF]")
			wg.Done() // server hung up, close WaitGroup to exit client
		}
	}()

	// client writer (to server) goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		// io.Copy() expects EOF so this will
		// exit with outerr == nil
		_, outerr := io.Copy(conn, os.Stdin)
		if outerr != nil {
			if outerr.Error() != "EOF" {
				fmt.Println(outerr)
				os.Exit(2)
			}
		}
		log.Println("[Sent EOF]")
		wg.Done() // client hung up, close WaitGroup to exit client
	}()

	// Wait until both stdin and stdout goroutines finish
	wg.Wait()
}

/* ------------- minimal terminal APIs brought in from ssh/terminal
 * (they have no real business being there as they aren't specific to
 * ssh, but as of v1.10, early 2018, core go stdlib hasn't yet done
 * the planned terminal lib reorgs.)
 * -------------
 */

// From github.com/golang/crypto/blob/master/ssh/terminal/util_linux.go
const ioctlReadTermios = unix.TCGETS
const ioctlWriteTermios = unix.TCSETS

// From github.com/golang/crypto/blob/master/ssh/terminal/util.go
// State contains the state of a terminal.
type State struct {
	termios unix.Termios
}

// MakeRaw put the terminal connected to the given file descriptor into raw
// mode and returns the previous state of the terminal so that it can be
// restored.
func MakeRaw(fd int) (*State, error) {
	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}

	oldState := State{termios: *termios}

	// This attempts to replicate the behaviour documented for cfmakeraw in
	// the termios(3) manpage.
	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB
	termios.Cflag |= unix.CS8
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, termios); err != nil {
		return nil, err
	}

	return &oldState, nil
}

// GetState returns the current state of a terminal which may be useful to
// restore the terminal after a signal.
func GetState(fd int) (*State, error) {
	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}

	return &State{termios: *termios}, nil
}

// Restore restores the terminal connected to the given file descriptor to a
// previous state.
func Restore(fd int, state *State) error {
	return unix.IoctlSetTermios(fd, ioctlWriteTermios, &state.termios)
}
