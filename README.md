Package herradurakex is a drop-in replacement for golang/pkg/net facilities
(net.Dial(), net.Listen(), net.Accept() and the net.Conn type), yielding
'secure' sockets using the experimental HerraduraKEx key exchange algorithm
first released by (Omar Elejandro Herrera Reyna's github page)[github.com/Caume/HerraduraKEx].

One can simply replace calls to net.Dial() with hkex.Dial(), and likewise
net.Listen() with hkex.Listen(), to obtain connections (hkex.Conn) conforming
to the basic net.Conn interface. Upon Dial(), the HerraduraKEx key exchange
is initiated (whereby client and server independently derive the same
keying material).

Above this layer, apps (such as the demo/server/ and demo/client code) can
then negotiate session settings (cipher/hmac algorithms, etc.) to be used
for further communication.

NOTE: Due to the experimental nature of the HerraduraKEx algorithm used to
derive crypto keying material on each end, this algorithm and the
demonstration remote shell client/server programs should be used with caution.
As of this time (Jan 2018) no verdict by acknowledged 'crypto experts' as to
the true security of the HerraduraKEx algorithm for purposes of session key
exchange over an insecure channel has been rendered.
It is hoped that such experts in the field will analyze the algorithm and
determine if it is indeed a suitable one for use in situations where
Diffie-Hellman and other key exchange algorithms are currently utilized.

Within the demo/ tree are client and servers implementing a simplified,
ssh-like secure shell facility and a password-setting utility using its
own user/password file separate from the system /etc/passwd, which is
used by the server to authenticate clients.

Dependencies:
github.com/mattn/go-isatty //terminal tty detection
github.com/kr/pty //unix pty control (server pty connections)
github.com/jameskeane/bcrypt //password storage/auth


To run
--
$ go get <tbd>/herradurakex.git
$ cd $GOPATH/src/<tbd>/herradurakex
$ go install .
$ go build demo/client/client.go && go build demo/server/server.go
$ go build demo/hkexpasswd/hkexpasswd.go

[To set accounts & passwords]
$ sudo echo "joebloggs:*:*:*" >/etc/hkexsh.passwd
$ sudo ./hkexpasswd -u joebloggs

[ in separate shells ]
[A]$ ./server &
[B]$ ./client -u joebloggs

