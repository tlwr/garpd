package main

import (
	"flag"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	interfaceNames = StringSliceFlag{}
	interval       time.Duration
)

func main() {
	flag.Var(&interfaceNames, "interface", "interface name for which to send ARP requests, valid multiple times")
	flag.DurationVar(&interval, "interval", 15*time.Second, "how often to send a gratuitous ARP request")
	flag.Parse()

	interfaces := []net.Interface{}
	allInterfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("could not get all interfaces")
	}
	for _, inf := range allInterfaces {
		for _, infName := range interfaceNames {
			if inf.Name == infName {
				if len(inf.HardwareAddr) == 0 {
					log.Printf("skipping inf (%s) because it has no MAC address", inf.Name)
					continue
				}
				interfaces = append(interfaces, inf)
			}
		}
	}

	if len(interfaces) == 0 {
		log.Fatalf("no interfaces for which to send gratuitous ARP requests")
	}

	immediate := time.After(0 * time.Second)

	for {
		select {
		case <-immediate:
		case <-time.After(interval):
		}

		for _, inf := range interfaces {
			log.Printf("garp inf (%s)", inf.Name)

			err := garp(inf)
			if err != nil {
				log.Printf("error garp inf (%s): %s", inf.Name, err)
			}
		}
	}
}

func garp(inf net.Interface) error {
	const (
		ethernetAddressSize uint8 = 6
		ipv4AddressSize     uint8 = 4
	)

	var (
		sent = 0
	)

	addrs, err := inf.Addrs()
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		var ip net.IP

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		ip = ip.To4()
		if ip == nil {
			continue
		}

		func() {
			rawPacketBuf := gopacket.NewSerializeBuffer()

			packet := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     ethernetAddressSize,
				ProtAddressSize:   ipv4AddressSize,
				Operation:         layers.ARPRequest,
				SourceHwAddress:   inf.HardwareAddr,
				SourceProtAddress: ip,
				DstHwAddress:      []byte([]uint8{0, 0, 0, 0, 0, 0}),
				DstProtAddress:    ip,
			}

			err := packet.SerializeTo(rawPacketBuf, gopacket.SerializeOptions{FixLengths: true})
			if err != nil {
				log.Printf("error crafting packet for inf (%s): %s", inf.Name, err)
				return
			}

			fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
			if err != nil {
				log.Printf("error opening raw socket for inf (%s): %s", inf.Name, err)
				return
			}

			defer syscall.Close(fd)

			addr := syscall.SockaddrInet4{
				Port: 0,
				Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]},
			}

			err = syscall.Sendto(fd, rawPacketBuf.Bytes(), 0, &addr)
			if err != nil {
				log.Printf("error writing packet for inf (%s) for ip (%s): %s", inf.Name, ip, err)
				return
			}

			log.Printf("garp inf (%s) sent ARP request for %s", inf.Name, ip)
			sent += 1
		}()
	}

	log.Printf("garp inf (%s) sent %d ARP requests", inf.Name, sent)

	return nil
}
