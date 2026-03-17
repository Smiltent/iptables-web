# todo
* [x] rewrite todo
* [ ] rewrite from firewalld to iptables
* [ ] always search based on line numbers (-L -n --line-numbers)
* [ ] insert between rules using line numners
* [ ] port ranges


-- tables (-t)
filter
nat
mangle
raw
security

-- input interface (-i)
list interfaces

-- output interface (-o)
list interfaces

-- ip address (-s)

-- source port (outgoing) (--sport)

-- destination port (incoming) (--dport)

-- protocol (-p)
tcp
udp


-- chains (-A)
PREROUTING
INPUT
OUTPUT
FORWARD
POSTROUTING
... list all chains ...

-- target (-j)
ACCEPT
DROP
REJECT
MASQUERADE

-- state (--ctstate)
NEW
ESTABLISHED
RELATED