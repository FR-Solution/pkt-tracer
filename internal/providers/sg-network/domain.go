package sgnetwork

import (
	"bytes" //nolint:gosec
	"fmt"
	"net"
	"time"

	sg "github.com/wildberries-tech/sgroups/v2/pkg/api/sgroups"

	"github.com/pkg/errors"
)

type (

	// NetworkName net name
	NetworkName = string

	// SGName sg name
	SGName = string

	// Network is IP network
	Network struct {
		Net  net.IPNet
		Name NetworkName
	}

	SgNet struct {
		Network
		SgName string
	}

	// SecGroup: represents a security group
	SecGroup struct {
		// name of security group
		Name string
		// related to security gpoup network(s)
		Networks []string
	}

	// SyncStatus succeeded sync-op status
	SyncStatus struct {
		UpdatedAt time.Time
	}

	network struct {
		Network
	}
)

func (n *network) from(protoNw *sg.Network) error {
	n.Name = protoNw.GetName()
	c := protoNw.GetNetwork().GetCIDR()
	ip, nt, err := net.ParseCIDR(c)
	if err != nil {
		return err
	}
	if !nt.IP.Equal(ip) {
		return errors.Errorf("the '%s' seems just an IP address; the address of network is expected instead", c)
	}
	n.Net = *nt
	return nil
}

// String impl Stringer
func (nw Network) String() string {
	return fmt.Sprintf("%s(%s)", nw.Name, &nw.Net)
}

// IsEq -
func (nw Network) IsEq(other Network) bool {
	return nw.Name == other.Name &&
		nw.Net.IP.Equal(other.Net.IP) &&
		bytes.Equal(nw.Net.Mask, other.Net.Mask)
}

// Proto2ModelNetwork converts Network (proto --> model)
func Proto2ModelNetwork(protoNw *sg.Network) (Network, error) {
	const api = "proto2model-Network-conv" //nolint:gosec
	var ret network
	err := ret.from(protoNw)
	return ret.Network, errors.WithMessage(err, api)
}
