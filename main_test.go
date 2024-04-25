package iptype

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetworkContainsIP(t *testing.T) {
	t.Parallel()

	assert.False(t, networkContainsIP("0.0.0.0/8", net.ParseIP("123.32.43.54")))
	assert.True(t, networkContainsIP("0.0.0.0/8", net.ParseIP("0.10.0.0")))
}

func TestCategorizeIP(t *testing.T) {
	t.Parallel()

	var ip = net.ParseIP("0.10.0.0")
	var ipType, err = categorizeIP(ip)
	assert.NoError(t, err)

	assert.Equal(t, ip, ipType.IP)
	assert.Equal(t, Software, ipType.IPScope)

	ip = net.ParseIP("71.222.203.13")
	ipType, err = categorizeIP(ip)
	assert.NoError(t, err)

	assert.Equal(t, ip, ipType.IP)
	assert.Equal(t, Public, ipType.IPScope)
}

func TestGetAddresses(t *testing.T) {
	t.Parallel()

	var addresses, err = getAddresses()
	assert.NoError(t, err)
	assert.True(t, len(addresses) > 0)
}

func TestGetIPTypes(t *testing.T) {
	t.Parallel()

	var ipTypes, err = GetIPTypes()
	assert.NoError(t, err)
	assert.True(t, len(ipTypes) > 0)

	for _, ipt := range ipTypes {
		fmt.Printf("addr: %s, type: %s \n", ipt.IP, ipt.IPScope)
	}
}
