package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"

	hkex "blitter.com/herradurakex"
	"github.com/kr/pty"
)

const (
	OpR   = 'r' // read(file) (binary mode)
	OpW   = 'w' // (over)write
	OpA   = 'a' // append
	OpRm  = 'd' // rm
	OpRmD = 'D' // rmdir (rm -rf)
	OpM   = 'm' // mkdir (-p)
	OpN   = 'n' // re(n)ame (mv)
	OpCm  = 'c' // chmod
	OpCo  = 'C' // chown
	OpX   = 'x' // exec
)

type Op uint8

type cmdRunner struct {
	op         Op
	who        string
	arg        string
	authCookie string
	status     int
}

/* ------------- minimal terminal APIs brought in from ssh/terminal
 * (they have no real business being there as they aren't specific to
 * ssh.)
 * -------------
 */

/*
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
*/

/* -------------------------------------------------------------- */

/*
 func cmd(r *cmdRunner) {
	switch r.op {
	case OpR:
		//Clean up r.cmd beforehand
		r.arg = strings.TrimSpace(r.arg)
		fmt.Printf("[cmd was:'%s']\n", r.arg)
		runCmdAs(r.who, r.arg, nil)
		fmt.Println(r.arg)
		break
	default:
		fmt.Printf("[cmd %d ignored:%d]\n", int(r.op))
		break
	}
}
*/

// Run a command (via os.exec) as a specific user
func runCmdAs(who string, cmd string, conn hkex.Conn) (err error) {
	u, _ := user.Lookup(who)
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	fmt.Println("uid:", uid, "gid:", gid)

	args := strings.Split(cmd, " ")
	arg0 := args[0]
	args = args[1:]
	c := exec.Command(arg0, args...)
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	c.Stdin = conn
	c.Stdout = conn
	c.Stderr = conn

	// Start the command with a pty.
	ptmx, err := pty.Start(c) // returns immediately with ptmx file
	if err != nil {
		return err
	}
	// Make sure to close the pty at the end.
	defer func() { _ = ptmx.Close() }() // Best effort.
	// Copy stdin to the pty and the pty to stdout.
	go func() { _, _ = io.Copy(ptmx, conn) }()
	_, _ = io.Copy(conn, ptmx)

	//err = c.Run()  // returns when c finishes.

	if err != nil {
		log.Printf("Command finished with error: %v", err)
		log.Printf("[%s]\n", cmd)
	}
	return
}

// Demo of a simple server that listens and spawns goroutines for each
// connecting client. Note this code is identical to standard tcp
// server code, save for declaring 'hkex' rather than 'net'
// Listener and Conns. The KEx and encrypt/decrypt is done within the type.
// Compare to 'serverp.go' in this directory to see the equivalence.
func main() {
	var laddr string

	flag.StringVar(&laddr, "l", ":2000", "interface[:port] to listen")
	flag.Parse()

	log.SetOutput(ioutil.Discard)

	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := hkex.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	fmt.Println("Serving on", laddr)
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Accepted client")

		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c hkex.Conn) (e error) {
			defer c.Close()
			ch := make(chan []byte)
			chN := 0
			eCh := make(chan error)

			// Start a goroutine to read from our net connection
			go func(ch chan []byte, eCh chan error) {
				for {
					// try to read the data
					data := make([]byte, 512)
					chN, err = c.Read(data)
					if err != nil {
						// send an error if it's encountered
						eCh <- err
						return
					}
					// send data if we read some.
					ch <- data[0:chN]
				}
			}(ch, eCh)

			ticker := time.Tick(time.Second / 100)
			//var r cmdRunner
			var connOp *byte = nil
		Term:
			// continuously read from the connection
			for {
				select {
				// This case means we recieved data on the connection
				case data := <-ch:
					// Do something with the data
					fmt.Printf("Client sent %+v\n", data[0:chN])
					if connOp == nil {
						// Initial xmit - get op byte
						// (TODO: determine valid ops
						//  for now 'e' (echo), 'i' (interactive), 'x' (exec), ... ?)
						connOp = new(byte)
						*connOp = data[0]
						data = data[1:chN]
						chN -= 1
						// Have op here and first block of data[]

						fmt.Printf("[* connOp '%c']\n", *connOp)
						// The CloseHandler typically handles the
						// accumulated command data
						//r = cmdRunner{op: Op(*connOp),
						//	who: "larissa", arg: string(data),
						//	authCookie:   "c00ki3",
						//	status:       0}
					}

					// From here, one could pass all subsequent data
					// between client/server attached to an exec.Cmd,
					// as data to/from a file, etc.
					if *connOp == 's' {
						fmt.Println("[Running shell]")
						runCmdAs("larissa", "bash -l -i", conn)
						// Returned hopefully via an EOF or exit/logout;
						// Clear current op so user can enter next, or EOF
						connOp = nil
						fmt.Println("[Exiting shell]")
						conn.Close()
					}
					if strings.Trim(string(data), "\r\n") == "exit" {
						conn.Close()
					}

					//fmt.Printf("Client sent %s\n", string(data))
				// This case means we got an error and the goroutine has finished
				case err := <-eCh:
					// handle our error then exit for loop
					if err.Error() == "EOF" {
						fmt.Printf("[Client disconnected]\n")
					} else {
						fmt.Printf("Error reading client data! (%+v)\n", err)
					}
					break Term
				// This will timeout on the read.
				case <-ticker:
					// do nothing? this is just so we can time out if we need to.
					// you probably don't even need to have this here unless you want
					// do something specifically on the timeout.
				}
			}
			// Shut down the connection.
			//c.Close()
			return
		}(conn)
	}
}
