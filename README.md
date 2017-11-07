# dns-client
This program receives a domain and returns its IP address through A, AAAA and MX types.

#### input
```
./dns <domain> <server (op)>
./dns google.com
./dns twitter.com 8.8.8.8
./dns yaho
```
#### output
```
google.com:
A	172.217.29.174
AAAA	2800:3f0:4001:80a::200e
MX	40 alt3.aspmx.l.google.com
	30 alt2.aspmx.l.google.com
	50 alt4.aspmx.l.google.com
	20 alt1.aspmx.l.google.com
	10 aspmx.l.google.com
twitter.com:
A	104.244.42.193
	104.244.42.129
AAAA	<none>   	AUTHORITATIVE RESPONSE: ns1.p26.dynect.net zone-admin.dyndns.com 2007138245 3600 600 604800 60
MX	10 aspmx.l.google.com
	20 alt1.aspmx.l.google.com
	20 alt2.aspmx.l.google.com
	30 aspmx2.googlemail.com
	30 aspmx3.googlemail.com
yaho:
A	ERROR: NXDOMAIN
AAAA	ERROR: NXDOMAIN
MX	ERROR: NXDOMAIN
```
