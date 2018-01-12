This is a drop-in replacement for the golang/pkg/net facilities
(net.Dial(), net.Listen(), net.Accept() and net.Conn type) using the
experimental HerraduraKEx 'secure' key exchange algorithm, first released at
github.com/Caume/HerraduraKEx

One can simply replace calls to net.Dial() with hkex.Dial(), and likewise
net.Listen() with hkex.Listen(), to obtain connections (hkex.Conn) conforming
to the basic net.Conn interface. Upon Dial(), the HerraduraKEx key exchange
is initiated (whereby client and server independently derive the same
keying material) and session algorithms to be used are exchanged allowing an
encrypted channel between client and server.

NOTE: the terms 'secure' and 'securely' where used above are purposely
enclosed in singled quotes due to the experimental nature of the HerraduraKEx
algorithm used to derive crypto keying material on each end.
As of this time no verdict by acknowledged 'crypto experts' as to the true
security of the HerraduraKEx algorithm for purposes of session key exchange
over an insecure channel has been rendered.
It is hoped that such experts in the field will analyze the algorithm and
determine if it is indeed a suitable one for use in situations where
Diffie-Hellman key exchange is currently utilized.

To run
--
$ go get <tbd>/herradurakex.git
$ cd $GOPATH/src/<tbd>/herradurakex
$ go install .
$ cd demo/
$ go build client.go && go build server.go

[ in separate shell windows ]
[A]$ ./server
[B]$ ./client
