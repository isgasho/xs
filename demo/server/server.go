package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"

	hkex "blitter.com/herradurakex"
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

func cmd(r *cmdRunner) {
	switch r.op {
	case OpR:
		//Clean up r.cmd beforehand
		r.arg = strings.TrimSpace(r.arg)
		fmt.Printf("[cmd was:'%s']\n", r.arg)
		runCmdAs(r.who, r.arg)
		fmt.Println(r.arg)
		break
	default:
		fmt.Printf("[cmd %d ignored:%d]\n", int(r.op))
		break
	}
}

// Run a command (via os.exec) as a specific user
func runCmdAs(who string, cmd string) (err error) {
	u, _ := user.Lookup(who)
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	//fmt.Println("uid:", uid, "gid:", gid)

	args := strings.Split(cmd, " ")
	arg0 := args[0]
	args = args[1:]
	c := exec.Command(arg0, args...)
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	err = c.Run()
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
					conn.Write([]byte("SERVER RESPONSE to '"))
					conn.Write(data)
					conn.Write([]byte("'\n"))
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
