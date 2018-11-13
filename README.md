HKExSh
--

'hkexsh' (HerraduraKyberEx shell) is a golang implementation of a simple
remote shell client and server, similar in role to ssh, offering
encrypted interactive and non-interactive sessions as well as file copying.

The client and server programs (hkexsh and hkexshd) use a mostly drop-in
replacement for golang's standard golang/pkg/net facilities (net.Dial(), net.Listen(), net.Accept()
and the net.Conn type), which automatically negotiate keying material for
'secure' sockets, using one of a selectable set of experimental key exchange (KEX) or
key encapsulation mechanisms (KEM).

Currently supported exchanges are:

* The HerraduraKEx key exchange algorithm first released at
[Omar Elejandro Herrera Reyna's HerraduraKEx project](http://github.com/Caume/HerraduraKEx);
* The KYBER IND-CCA-2 secure key encapsulation mechanism, [pq-crystals Kyber](https://pq-crystals.org/kyber/)  :: [Yawning/kyber golang implementation](https://git.schwanenlied.me/yawning/kyber)

Currently supported session encryption and hmac algorithms:

* AES-256
* Twofish-128
* Blowfish-64
* CryptMTv1 (https://eprint.iacr.org/2005/165.pdf)
* HMAC-SHA256
* HMAC-SHA512


One can simply replace calls to net.Dial() with hkex.Dial(), and likewise
net.Listen() with hkex.Listen(), to obtain connections (hkex.Conn) conforming
to the basic net.Conn interface. Upon Dial(), the HerraduraKEx key exchange
is initiated (whereby client and server independently derive the same
keying material).

Above the hkex.Conn layer, the server and client apps in this repository
(server/hkexshd and client/hkexsh) negotiate session settings (cipher/hmac
algorithms, interactive/non-interactive, etc.) to be used for further
communication.

Packets are subject to random padding, and (optionally) the client and server
channels can both send _chaff_ packets at random defineable intervals to help
thwart analysis of session activity (especially for interactive shell sessions).

NOTE: THIS PROJECT IS EXPERIMENTAL. Due to the experimental nature of the HerraduraKEx and Kyber IND-CCA-2 algorithms, this package SHOULD BE USED WITH CAUTION and should DEFINITELY NOT be used for any sensitive applications. USE AT YOUR OWN RISK. NO WARRANTY OR CLAIM OF FITNESS FOR PURPOSE IS IMPLIED.

HERRADURA KEX

As of this time (Oct 2018) no verdict by acknowledged 'crypto experts' as to
the level of security of the HerraduraKEx algorithm for purposes of session
key exchange over an insecure channel has been rendered.
It is hoped that experts in the field will analyze the algorithm and
determine if it is indeed a suitable one for use in situations where
Diffie-Hellman or other key exchange algorithms are currently utilized.

KYBER IND-CCA-2 KEM

As of this time (Oct 2018) Kyber is one of the candidate algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography). The authors recommend using it in "... so-called hybrid mode in combination with established "pre-quantum" security; for example in combination with elliptic-curve Diffie-Hellman." THIS PROJECT DOES NOT DO THIS, for purposes of simplicity of code and to evaluate the algorithm in operation by itself (again, THIS PROJECT IS EXPERIMENTAL.)

Finally, within the hkexpasswd/ directory is a password-setting utility
using its own user/password file distinct from the system /etc/passwd, which
is used by the hkexshd server to authenticate clients.

Dependencies:
--
* Recent version of go (tested, at various times, with go-1.9 to go-1.11.1)
* [github.com/mattn/go-isatty](http://github.com/mattn/go-isatty) //terminal tty detection
* [github.com/kr/pty](http://github.com/kr/pty) //unix pty control (server pty connections)
* [github.com/jameskeane/bcrypt](http://github.com/jameskeane/bcrypt) //password storage/auth
* [blitter.com/go/goutmp](https://blitter.com/gogs/Russtopia/goutmp) // wtmp/lastlog C bindings
* [https://git.schwanenlied.me/yawning/kyber](https://git.schwanenlied.me/yawning/kyber) // golang Kyber KEM
* [blitter.com/go/mtwist](https://blitter.com/gogs/RLabs/mtwist) // 64-bit Mersenne Twister PRNG
* [blitter.com/go/cryptmt](https://blitter.com/gogs/RLabs/cryptmt) // CryptMTv1 stream cipher

Get source code
--
* $ go get -u blitter.com/go/hkexsh
* $ cd $GOPATH/src/blitter.com/go/hkexsh
* $ go build ./... # install all dependent go pkgs

To build
--
* $ cd $GOPATH/src/blitter.com/go/hkexsh
* $ make clean all

To set accounts & passwords:
--
* $ sudo touch /etc/hkexsh.passwd
* $ sudo hkexpasswd/hkexpasswd -u joebloggs
* $ &lt;enter a password, enter again to confirm&gt;

Running Clent and Server
--
In separate shells A and B:
* [A]$ cd hkexshd && sudo ./hkexshd &  # add -d for debugging

Interactive shell
* [B]$ cd hkexsh && ./hkexsh joebloggs@host-or-ip # add -d for debugging

One-shot command
* [B]$ cd hkexsh && ./hkexsh -x "ls /tmp" joebloggs@host-or-ip

WARNING WARNING WARNING: the -d debug flag will echo passwords to the log/console!

NOTE if running client (hkexsh) with -d, one will likely need to run 'reset' afterwards
to fix up the shell tty afterwards, as stty echo may not be restored if client crashes
or is interrupted.

Setting up an 'authtoken' for scripted (password-free) logins
--
Use the -g option of hkexsh to request a token from the remote server, which will return a
hostname:token string. Place this string into $HOME/.hkexsh_id to allow logins without
entering a password (obviously, $HOME/.hkexsh_id on both server and client $HOME for the user
should *not* be world-readable.)

File Copying using hkexcp
--
hkexcp is a symlink to hkexsh, and the binary checks its own filename to determine whether
it is being invoked in 'shell' or 'copy' mode. Refer to the '-h' output for differences in
accepted options.

General remote syntax is: user@server:[/]src-or-dest-path
If no leading / is specified in src-or-dest-path, it is assumed to be relative to $HOME of the
remote user. File operations are all performed as the remote user, so account permissions apply
as expected.

Local (client) to remote (server) copy:
* cd hkexsh && ./hkexcp fileA /some/where/fileB /some/where/else/dirC joebloggs@host-or-ip:remoteDir

Remote (server) to local (client) copy:
* cd hekxsh && ./hkexcp joebloggs@host-or-ip:/remoteDirOrFile /some/where/local/Dir

NOTE: Renaming while copying is NOT supported (ie., like cp's 'cp /foo/bar/fileA ./fileB).
Put another way, the destination (whether local or remote) is ALWAYS a dir.

hkexcp uses tar with gzip compression (ala a 'tarpipe') under the hood, sending tar data over
the hkex encrypted channel. Use the -d flag on client or server to see the generated tar
commandlines if you're curious.

Tunnels
--
Simple tunnels (only client tunnels from client -> server for now, no reverse
tunnels) are supported.

Syntax: hkexsh -T=<tunspec>{,<tunspec>...}
.. where <tunspec> is <localport:remoteport>

Example, tunnelling ssh through hkexsh

* [server side] $ sudo /usr/sbin/sshd -p 7002
* [client side] $ hkexsh -T=6002:7002 @server.hostname
* [client side] $ ssh user@localhost -p 6002
