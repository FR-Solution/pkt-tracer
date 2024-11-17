package iface

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ifCacheTestSuite struct {
	suite.Suite
}

func (sui *ifCacheTestSuite) Test_IfCacheAddGetRmOneThread() {
	cache := NewCache()
	testData := []ifCacheItem{
		{"if1", 1},
		{"if2", 2},
		{"if3", 3},
		{"if4", 4},
	}
	for _, t := range testData {
		cache.Update(t)
	}
	sui.Require().Equal(len(testData), cache.cache.Len())
	for _, t := range testData {
		ifc, err := cache.GetItemById(t.ifIndex)
		sui.Require().NoError(err)
		sui.Require().Equal(t, ifc)
	}

	for _, t := range testData {
		cache.RmCacheItemByIfName(t.ifName)
	}
	sui.Require().Equal(0, cache.cache.Len())
}

func (sui *ifCacheTestSuite) Test_IfCacheAddGetMultiThread() {
	cache := NewCache()
	testData := []ifCacheItem{
		{"if1", 1},
		{"if2", 2},
		{"if3", 3},
		{"if4", 4},
		{"if5", 5},
		{"if6", 6},
		{"if7", 7},
		{"if8", 8},
		{"if9", 9},
		{"if10", 10},
	}
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for _, t := range testData[:6] {
			cache.Update(t)
			ifc, err := cache.GetItemById(t.ifIndex)
			sui.Require().NoError(err)
			sui.Require().Equal(t, ifc)
		}
	}()

	go func() {
		defer wg.Done()
		for _, t := range testData[6:] {
			cache.Update(t)
			ifc, err := cache.GetItemById(t.ifIndex)
			sui.Require().NoError(err)
			sui.Require().Equal(t, ifc)
		}
	}()
	wg.Wait()
	sui.Require().Equal(len(testData), cache.cache.Len())
	for _, t := range testData {
		ifc, err := cache.GetItemById(t.ifIndex)
		sui.Require().NoError(err)
		sui.Require().Equal(t, ifc)
	}
}

func (sui *ifCacheTestSuite) Test_IfCacheAddRmMultiThread() {
	cache := NewCache()
	testData := []ifCacheItem{
		{"if1", 1},
		{"if2", 2},
		{"if3", 3},
		{"if4", 4},
		{"if5", 5},
		{"if6", 6},
		{"if7", 7},
		{"if8", 8},
		{"if9", 9},
		{"if10", 10},
	}
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for _, t := range testData[:6] {
			cache.Update(t)
			cache.RmCacheItemByIfName(t.ifName)
		}
	}()

	go func() {
		defer wg.Done()
		for _, t := range testData[6:] {
			cache.Update(t)
			cache.RmCacheItemByIfName(t.ifName)
		}
	}()
	wg.Wait()
	sui.Require().Equal(0, cache.cache.Len())

}

func Test_IfCache(t *testing.T) {
	suite.Run(t, new(ifCacheTestSuite))
}
