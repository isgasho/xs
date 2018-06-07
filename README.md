HKExSh
--

'hkexsh' (HerraduraKEx shell) is a golang implementation of a simple
remote shell client and server, similar in role to ssh, offering
encrypted interactive and non-interactive sessions. The client and server
programs (hkexsh and hkexshd) use a mostly drop-in replacement for golang's
standard golang/pkg/net facilities (net.Dial(), net.Listen(), net.Accept()
and the net.Conn type), which automatically negotiate keying material for
'secure' sockets using the experimental HerraduraKEx key exchange algorithm
first released at
[Omar Elejandro Herrera Reyna's HerraduraKEx project](http://github.com/Caume/HerraduraKEx).

One can simply replace calls to net.Dial() with hkex.Dial(), and likewise
net.Listen() with hkex.Listen(), to obtain connections (hkex.Conn) conforming
to the basic net.Conn interface. Upon Dial(), the HerraduraKEx key exchange
is initiated (whereby client and server independently derive the same
keying material).

Above the hkex.Conn layer, the server and client apps in this repository
(server/hkexshd and client/hkexsh) negotiate session settings (cipher/hmac
algorithms, interactive/non-interactive, etc.) to be used for further
communication.

NOTE: Due to the experimental nature of the HerraduraKEx algorithm used to
derive crypto keying material, this algorithm and the demonstration remote
shell client/server programs should be used with caution and should definitely
NOT be used for any sensitive applications, or at the very least at one's
own risk.

As of this time (Jan 2018) no verdict by acknowledged 'crypto experts' as to
the level of security of the HerraduraKEx algorithm for purposes of session
key exchange over an insecure channel has been rendered.
It is hoped that experts in the field will analyze the algorithm and
determine if it is indeed a suitable one for use in situations where
Diffie-Hellman or other key exchange algorithms are currently utilized.

Finally, within the hkexpasswd/ directory is a password-setting utility
using its own user/password file distinct from the system /etc/passwd, which
is used by the hkexshd server to authenticate clients.

Dependencies:
--
* Recent version of go (tested with go-1.9)
* [github.com/mattn/go-isatty](http://github.com/mattn/go-isatty) //terminal tty detection
* [github.com/kr/pty](http://github.com/kr/pty) //unix pty control (server pty connections)
* [github.com/jameskeane/bcrypt](http://github.com/jameskeane/bcrypt) //password storage/auth

Get source code
--
* $ go get -u github.com/Russtopia/hkexsh
* $ go get github.com/mattn/go-isatty  ## only used by demos, not picked up by above go get -u?

To build
--
* $ cd $GOPATH/src/github.com/Russtopia/hkexsh
* $ make clean all

To set accounts & passwords:
--
* $ sudo echo "joebloggs:*:*:*" >/etc/hkexsh.passwd
* $ sudo hkexpasswd/hkexpasswd -u joebloggs
* $ &lt;enter a password, enter again to confirm&gt;

Running Clent and Server. In separate shells:
--
* [A]$ sudo hkexshd/hkexshd &
* [B]$ hkexsh/hkexsh -u joebloggs
