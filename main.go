package iptype

import (
	"fmt"
	"net"
)

// https://www.wikiwand.com/en/Reserved_IP_addresses
type IPScope uint8

const (
	Documentation IPScope = iota
	Host
	Link
	Multicast
	Private
	Public
	Reserved
	Routing
	Software
	Subnet
)

func (s IPScope) String() string {
	switch s {
	case Documentation:
		return "Documentation"
	case Host:
		return "Host"
	case Link:
		return "Link"
	case Multicast:
		return "Multicast"
	case Private:
		return "Private"
	case Public:
		return "Public"
	case Reserved:
		return "Reserved"
	case Routing:
		return "Routing"
	case Software:
		return "Software"
	case Subnet:
		return "Subnet"
	}
	return "unknown"
}

type IPType struct {
	net.IP
	IPScope
}

func (ipt IPType) String() string {
	return fmt.Sprintf("addr: %s, type: %s", ipt.IP, ipt.IPScope.String())
}

var v4PrivateBlocks = map[string]IPScope{
	"0.0.0.0/8":          Software,
	"10.0.0.0/8":         Private,
	"100.64.0.0/10":      Private,
	"127.0.0.0/8":        Host,
	"169.254.0.0/16":     Subnet,
	"172.16.0.0/12":      Private,
	"192.0.0.0/24":       Private,
	"192.0.2.0/24":       Documentation,
	"192.88.99.0/24":     Reserved,
	"192.168.0.0/16":     Private,
	"198.18.0.0/15":      Private,
	"198.51.100.0/24":    Documentation,
	"203.0.113.0/24":     Documentation,
	"224.0.0.0/4":        Multicast,
	"233.252.0.0/24":     Documentation,
	"240.0.0.0/4":        Reserved,
	"255.255.255.255/32": Subnet,
}

var networkPrefixes = map[uint8][]string{
	0:   {"0.0.0.0/8"},
	10:  {"10.0.0.0/8"},
	100: {"100.64.0.0/10"},
	127: {"127.0.0.0/8"},
	169: {"169.254.0.0/16"},
	172: {"172.16.0.0/12"},
	192: {"192.0.0.0/24", "192.0.2.0/24"},
	198: {"198.18.0.0/15", "198.51.100.0/24"},
	203: {"203.0.113.0/24"},
	224: {"224.0.0.0/4"},
	233: {"233.252.0.0/24"},
	240: {"240.0.0.0/4"},
	255: {"255.255.255.255/32"},
}

func GetIPTypes() ([]IPType, error) {
	var addresses, err = getAddresses()
	if err != nil {
		return nil, err
	}

	var ips = make([]IPType, len(addresses))
	for i, addr := range addresses {
		var ipType, err = categorizeIP(addr)
		if err != nil {
			return nil, err
		}

		ips[i] = ipType
	}

	return ips, nil
}

func categorizeIP(addr net.IP) (IPType, error) {
	if ipArr := addr.To4(); ipArr != nil {
		if networks, found := networkPrefixes[ipArr[0]]; found {
			for _, network := range networks {
				if networkContainsIP(network, addr) {
					return IPType{addr, v4PrivateBlocks[network]}, nil
				}
			}
		}
	}
	return IPType{addr, Public}, nil
}

func networkContainsIP(network string, addr net.IP) bool {
	_, rNW, err := net.ParseCIDR(network)
	if err != nil {
		return false // not getting here as the networks are hardcoded above
	}

	return rNW.Contains(addr)
}

func getAddresses() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
