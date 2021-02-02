# garpd

Gratuitous ARP daemon written in Go

A small utility for sending gratuitous ARP requests as per
[RFC522y](https://tools.ietf.org/html/rfc5227#page-15).


## Usage

```
$ garpd -h

-interface value
  interface name for which to send ARP requests, valid multiple times
-interval duration
  how often to send a gratuitous ARP request (default 15s)
```

## Example

```
garpd \
  -interface en0 \
  -interface en2 \
  -interface en6 \
  -interval 30s

2021/02/02 14:34:29 using 30s as interval
2021/02/02 14:34:29 garp inf (en0)
2021/02/02 14:34:29 garp inf (en0) sent ARP request for 192.168.2.184
2021/02/02 14:34:29 garp inf (en0) sent 1 ARP requests
2021/02/02 14:34:29 garp inf (en2)
2021/02/02 14:34:29 garp inf (en2) sent 0 ARP requests
2021/02/02 14:34:29 garp inf (en6)
2021/02/02 14:34:29 garp inf (en6) sent 0 ARP requests
```

The above example sent an ARP request for every interface specified for which
an IP address was allocated.

## Caveats

* Only works for Unix systems.
* Requires `CAP_NET_RAW` on linux systems
* Requires `root` on non-linux systems
