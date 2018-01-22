package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	hkex "blitter.com/herradurakex"
	"github.com/kr/pty"
)

type cmdSpec struct {
	op         []byte
	who        []byte
	cmd        []byte
	authCookie []byte
	status     int
}

/* -------------------------------------------------------------- */

// Run a command (via os.exec) as a specific user
//
// Uses ptys to support commands which expect a terminal.
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

// Run a command (via default shell) as a specific user
//
// Uses ptys to support commands which expect a terminal.
func runShellAs(who string, cmd string, interactive bool, conn hkex.Conn) (err error) {
	u, _ := user.Lookup(who)
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	fmt.Println("uid:", uid, "gid:", gid)

	var c *exec.Cmd
	if interactive {
		c = exec.Command("/bin/bash", "-i")
	} else {
		c = exec.Command("/bin/bash", "-c", cmd)
	}
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
	var dbg bool
	var laddr string

	flag.StringVar(&laddr, "l", ":2000", "interface[:port] to listen")
	flag.BoolVar(&dbg, "d", false, "debug logging")
	flag.Parse()

	if dbg {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}

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

			//We use io.ReadFull() here to guarantee we consume
			//just the data we want for the cmdSpec, and no more.
			//Otherwise data will be sitting in the channel that isn't
			//passed down to the command handlers.
			var rec cmdSpec
			var len1, len2, len3, len4 uint32

			n, err := fmt.Fscanf(c, "%d %d %d %d\n", &len1, &len2, &len3, &len4)
			if err != nil || n < 4 {
				fmt.Println("[Bad cmdSpec fmt]")
				return err
			}
			fmt.Printf("  lens:%d %d %d %d\n", len1, len2, len3, len4)

			rec.op = make([]byte, len1, len1)
			_, err = io.ReadFull(c, rec.op)
			if err != nil {
				fmt.Println("[Bad cmdSpec.op]")
				return err
			}
			rec.who = make([]byte, len2, len2)
			_, err = io.ReadFull(c, rec.who)
			if err != nil {
				fmt.Println("[Bad cmdSpec.who]")
				return err
			}

			rec.cmd = make([]byte, len3, len3)
			_, err = io.ReadFull(c, rec.cmd)
			if err != nil {
				fmt.Println("[Bad cmdSpec.cmd]")
				return err
			}

			rec.authCookie = make([]byte, len4, len4)
			_, err = io.ReadFull(c, rec.authCookie)
			if err != nil {
				fmt.Println("[Bad cmdSpec.authCookie]")
				return err
			}

			fmt.Printf("[cmdSpec: op:%c who:%s cmd:%s auth:%s]\n",
				rec.op[0], string(rec.who), string(rec.cmd), string(rec.authCookie))

			if rec.op[0] == 'c' {
				// Non-interactive command
				fmt.Println("[Running command]")
				runShellAs(string(rec.who), string(rec.cmd), false, conn)
				// Returned hopefully via an EOF or exit/logout;
				// Clear current op so user can enter next, or EOF
				rec.op[0] = 0
				fmt.Println("[Command complete]")
			} else if rec.op[0] == 's' {
				fmt.Println("[Running shell]")
				runShellAs(string(rec.who), string(rec.cmd), true, conn)
				// Returned hopefully via an EOF or exit/logout;
				// Clear current op so user can enter next, or EOF
				rec.op[0] = 0
				fmt.Println("[Exiting shell]")
			} else {
				fmt.Println("[Bad cmdSpec]")
			}
			return
		}(conn)
	} //endfor
	fmt.Println("[Exiting]")
}
