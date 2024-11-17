package sgnetwork

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/suite"
)

type sgHolderTestSuite struct {
	suite.Suite
}

func Test_SgNw(t *testing.T) {
	suite.Run(t, new(sgHolderTestSuite))
}

func (sui *sgHolderTestSuite) Test_SgNwFetch() {
	var (
		sgList []SecGroup
		nwList []Network
		sgExp  []SgNet
	)
	sgCache := make(SgNameCache)
	for i := 0; i < 10; i++ {
		sgName := strconv.Itoa(i)
		var nws []string
		for j := 0; j < 5; j++ {
			cidr := fmt.Sprintf("192.168.%d.%d/32", i, j)
			_, ipnet, _ := net.ParseCIDR(cidr)
			nws = append(nws, cidr)
			nwList = append(nwList, Network{Net: *ipnet, Name: cidr})
			sgExp = append(sgExp, SgNet{Network: Network{Net: *ipnet, Name: cidr}, SgName: sgName})
		}
		sgList = append(sgList, SecGroup{Name: sgName, Networks: nws})
	}
	for _, sg := range sgList {
		for _, nwName := range sg.Networks {
			sgCache[nwName] = sg.Name
		}
	}
	sui.Require().Equal(len(nwList), len(sgCache))
	sgn := make([]SgNet, 0, len(nwList))
	for _, m := range nwList {
		sgName, ok := sgCache[m.Name]
		sui.Require().True(ok)
		sgn = append(sgn, SgNet{Network: m, SgName: sgName})
	}
	sui.Require().ElementsMatch(sgExp, sgn)
}

func (sui *sgHolderTestSuite) Test_SgNwCache() {
	const (
		sgNum  = 10
		netNum = 5
	)

	var (
		cache Cache
		sgExp [sgNum][netNum]SgNet
	)

	item := cache.Find(net.ParseIP("192.168.1.1"))
	sui.Require().Nil(item)
	sgs := make([]*SgNet, 0)
	for i := 0; i < sgNum; i++ {
		sgName := strconv.Itoa(i)
		for j := 0; j < netNum; j++ {
			cidr := fmt.Sprintf("192.168.%d.%d/32", i, j)
			_, ipnet, _ := net.ParseCIDR(cidr)
			sgExp[i][j] = SgNet{Network: Network{Net: *ipnet, Name: cidr}, SgName: sgName}
			sgs = append(sgs, &SgNet{Network: Network{Net: *ipnet, Name: cidr}, SgName: sgName})
		}
	}
	cache.Init(sgs)
	sui.Require().Equal(0, len(cache.fast))
	sui.Require().Equal(sgNum*netNum, len(cache.slow))

	for i := 0; i < sgNum; i++ {
		for j := 0; j < netNum; j++ {
			item := cache.Find(net.ParseIP(fmt.Sprintf("192.168.%d.%d", i, j)))
			sui.Require().NotNil(item)
			sui.Require().Equal(sgExp[i][j], *item)
			sui.Require().Equal(i*netNum+j+1, len(cache.fast))
		}
	}
	cache.Clear()
	sui.Require().Equal(0, len(cache.fast))
	sui.Require().Equal(0, len(cache.slow))
	item = cache.Find(net.ParseIP("192.168.1.1"))
	sui.Require().Nil(item)
}

func (sui *sgHolderTestSuite) Test_SgNwCacheMThread() {
	const (
		sgNum  = 10
		netNum = 5
	)

	var (
		cache Cache
		sgExp [sgNum][netNum]SgNet
	)

	sgs := make([]*SgNet, 0)
	for i := 0; i < sgNum; i++ {
		sgName := strconv.Itoa(i)
		for j := 0; j < netNum; j++ {
			cidr := fmt.Sprintf("192.168.%d.%d/32", i, j)
			_, ipnet, _ := net.ParseCIDR(cidr)
			sgExp[i][j] = SgNet{Network: Network{Net: *ipnet, Name: cidr}, SgName: sgName}
			sgs = append(sgs, &SgNet{Network: Network{Net: *ipnet, Name: cidr}, SgName: sgName})
		}
	}
	cache.Init(sgs)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < sgNum/2; i++ {
			for j := 0; j < netNum; j++ {
				item := cache.Find(net.ParseIP(fmt.Sprintf("192.168.%d.%d", i, j)))
				sui.Require().NotNil(item)
				sui.Require().Equal(sgExp[i][j], *item)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := sgNum / 2; i < sgNum; i++ {
			for j := 0; j < netNum; j++ {
				item := cache.Find(net.ParseIP(fmt.Sprintf("192.168.%d.%d", i, j)))
				sui.Require().NotNil(item)
				sui.Require().Equal(sgExp[i][j], *item)
			}
		}
	}()

	wg.Wait()

}
