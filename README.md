This is an implementation of the 'HerraduraKEx' key exchange algorithm in golang.
See github.com/Caume/HerraduraKEx

package herradurakex is a simple golang library to manage key exchanges using the algorithm
and (TODO) wraps/extends golang.org/pkg/net/, Listener interface, Dial/Accept methods by
providing a HKexConn built on top of the vanilla Conn.

Theory:
1. Build a standard pkg/net/ Conn c
2. Build a HKexConn passing in Conn hc (HKexConn implements io.Reader,io.Writer)s
3. Dial/Listen on hc (it will do the KEx and store session key, negotiate crypto alg.)
4. Call any pkg/net ops as usual using HKexConn


? -rlm 2018-01-06

