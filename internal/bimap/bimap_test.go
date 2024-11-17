package bimap

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
)

type bimapTestSuite struct {
	suite.Suite
}

func (sui *bimapTestSuite) Test_BimapLen() {
	var m BiMap[int, string, int]
	sui.Require().Equal(0, m.Len())
	for i := 1; i < 10; i++ {
		m.Insert(i, strconv.Itoa(i), i+1)
		sui.Require().Equal(i, m.Len())
	}
	m.Clear()
	sui.Require().Equal(0, m.Len())
}

func (sui *bimapTestSuite) Test_BimapUpd() {
	var m BiMap[int, string, int]
	sui.Require().Equal(0, m.Len())
	for i := 1; i < 10; i++ {
		m.Insert(i, strconv.Itoa(i), i+1)
		sui.Require().Equal(i, m.Len())
		val, ok := m.At(i)
		sui.Require().True(ok)
		sui.Require().Equal(i+1, val.V)
		val, ok = m.AtRev(strconv.Itoa(i))
		sui.Require().True(ok)
		sui.Require().Equal(i+1, val.V)

		ok = m.Upd(i, i+2)
		sui.Require().True(ok)
		val, ok = m.At(i)
		sui.Require().True(ok)
		sui.Require().Equal(i+2, val.V)
		val, ok = m.AtRev(strconv.Itoa(i))
		sui.Require().True(ok)
		sui.Require().Equal(i+2, val.V)

		ok = m.UpdRev(strconv.Itoa(i), i+1)
		sui.Require().True(ok)
		val, ok = m.AtRev(strconv.Itoa(i))
		sui.Require().True(ok)
		sui.Require().Equal(i+1, val.V)
		val, ok = m.At(i)
		sui.Require().True(ok)
		sui.Require().Equal(i+1, val.V)
	}
	m.Clear()
	sui.Require().Equal(0, m.Len())
}

func (sui *bimapTestSuite) Test_BimapInsert() {
	var m BiMap[int, string, int]
	testData := []struct {
		key1 int
		key2 string
		val  int
	}{}
	for i := 1; i < 10; i++ {
		testData = append(testData, struct {
			key1 int
			key2 string
			val  int
		}{i, strconv.Itoa(i), i + 1})
		m.Insert(i, strconv.Itoa(i), i+1)
	}
	for _, t := range testData {
		val, ok := m.At(t.key1)
		sui.Require().True(ok)
		sui.Require().Equal(t.val, val.V)
		sui.Require().Equal(t.key1, val.K1)
		sui.Require().Equal(t.key2, val.K2)

		val, ok = m.AtRev(t.key2)
		sui.Require().True(ok)
		sui.Require().Equal(t.val, val.V)
		sui.Require().Equal(t.key1, val.K1)
		sui.Require().Equal(t.key2, val.K2)
	}
}

func (sui *bimapTestSuite) Test_BimapRm() {
	var m BiMap[int, string, int]
	testData := []struct {
		key1 int
		key2 string
		val  int
	}{}
	for i := 1; i < 10; i++ {
		testData = append(testData, struct {
			key1 int
			key2 string
			val  int
		}{i, strconv.Itoa(i), i + 1})
		m.Insert(i, strconv.Itoa(i), i+1)
	}

	//remove by valid keys
	for i, t := range testData {

		if i%2 == 0 {
			val := m.RmRev(t.key2)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)

			_, ok := m.AtRev(t.key2)
			sui.Require().False(ok)
			_, ok = m.At(t.key1)
			sui.Require().False(ok)

			val = m.RmRev(t.key2)
			sui.Require().Nil(val)

			val = m.Rm(t.key1)
			sui.Require().Nil(val)
		} else {
			val := m.Rm(t.key1)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)

			_, ok := m.At(t.key1)
			sui.Require().False(ok)
			_, ok = m.AtRev(t.key2)
			sui.Require().False(ok)

			val = m.Rm(t.key1)
			sui.Require().Nil(val)
			val = m.RmRev(t.key2)
			sui.Require().Nil(val)
		}
		sui.Require().Equal(len(testData)-i-1, m.Len())
	}
	sui.Require().Equal(0, m.Len())
}

func (sui *bimapTestSuite) Test_BimapMismatch() {
	var m BiMap[int, string, int]
	testData := []struct {
		key1 int
		key2 string
		val  int
	}{
		{1, "k1", 1},
		{2, "k1", 2},
		{3, "k1", 3},
	}
	for _, t := range testData {
		m.Insert(t.key1, t.key2, t.val)
	}
	var cb int
	m.Iterate(func(k1 int, k2 string, v int) bool {
		cb++
		return true
	})
	sui.Require().Equal(1, cb)
	sui.Require().Equal(cb, m.Len())

	for i, t := range testData {
		val, ok := m.At(t.key1)
		if i == len(testData)-1 {
			sui.Require().True(ok)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)
		} else {
			sui.Require().False(ok)
		}

		val, ok = m.AtRev(t.key2)
		if i == len(testData)-1 {
			sui.Require().True(ok)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)
		} else {
			sui.Require().True(ok)
			sui.Require().NotEqual(t.val, val.V)
			sui.Require().Equal(t.key2, val.K2)
			sui.Require().NotEqual(t.key1, val.K1)
		}
	}
	m.Clear()
	sui.Require().Equal(0, m.Len())

	testData = []struct {
		key1 int
		key2 string
		val  int
	}{
		{1, "k1", 1},
		{1, "k1", 2},
		{1, "k1", 3},
	}
	for _, t := range testData {
		m.Insert(t.key1, t.key2, t.val)
	}
	sui.Require().Equal(1, cb)
	for i, t := range testData {
		val, ok := m.At(t.key1)
		if i == len(testData)-1 {
			sui.Require().True(ok)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)
		} else {
			sui.Require().True(ok)
			sui.Require().NotEqual(t.val, val.V)
			sui.Require().Equal(t.key2, val.K2)
			sui.Require().Equal(t.key1, val.K1)
		}

		val, ok = m.AtRev(t.key2)
		if i == len(testData)-1 {
			sui.Require().True(ok)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)
		} else {
			sui.Require().True(ok)
			sui.Require().NotEqual(t.val, val.V)
			sui.Require().Equal(t.key2, val.K2)
			sui.Require().Equal(t.key1, val.K1)
		}
	}
	m.Clear()
	sui.Require().Equal(0, m.Len())

	testData = []struct {
		key1 int
		key2 string
		val  int
	}{
		{1, "k1", 1},
		{1, "k2", 2},
		{1, "k3", 3},
	}
	for _, t := range testData {
		m.Insert(t.key1, t.key2, t.val)
	}
	sui.Require().Equal(1, cb)
	for i, t := range testData {
		val, ok := m.At(t.key1)
		if i == len(testData)-1 {
			sui.Require().True(ok)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)
		} else {
			sui.Require().True(ok)
			sui.Require().NotEqual(t.val, val.V)
			sui.Require().NotEqual(t.key2, val.K2)
			sui.Require().Equal(t.key1, val.K1)
		}

		val, ok = m.AtRev(t.key2)
		if i == len(testData)-1 {
			sui.Require().True(ok)
			sui.Require().Equal(t.val, val.V)
			sui.Require().Equal(t.key1, val.K1)
			sui.Require().Equal(t.key2, val.K2)
		} else {
			sui.Require().False(ok)
		}
	}
}

func (sui *bimapTestSuite) Test_BimapIterate() {
	var m BiMap[int, string, int]
	sui.Require().Equal(0, m.Len())
	const size = 10
	for i := 0; i < size; i++ {
		m.Insert(i, strconv.Itoa(i), i+1)
	}
	cb := 0

	m.Iterate(func(k1 int, k2 string, v int) bool {
		cb++
		return true
	})
	sui.Require().Equal(size, m.Len())
	sui.Require().Equal(m.Len(), cb)

	m.Clear()
	sui.Require().Equal(0, m.Len())

	testData := []struct {
		key1 int
		key2 string
		val  int
	}{
		{1, "k1", 1},
		{2, "k1", 2},
		{3, "k1", 3},
	}
	for _, t := range testData {
		m.Insert(t.key1, t.key2, t.val)
	}
	cb = 0
	m.Iterate(func(k1 int, k2 string, v int) bool {
		cb++
		return true
	})
	sui.Require().Equal(1, cb)
	sui.Require().Equal(cb, m.Len())

	m.Clear()
	sui.Require().Equal(0, m.Len())

	testData = []struct {
		key1 int
		key2 string
		val  int
	}{
		{1, "k1", 1},
		{1, "k1", 2},
		{1, "k1", 3},
	}
	for _, t := range testData {
		m.Insert(t.key1, t.key2, t.val)
	}
	cb = 0
	m.Iterate(func(k1 int, k2 string, v int) bool {
		cb++
		return true
	})
	sui.Require().Equal(1, cb)
	sui.Require().Equal(cb, m.Len())

	m.Clear()
	sui.Require().Equal(0, m.Len())

	testData = []struct {
		key1 int
		key2 string
		val  int
	}{
		{1, "k1", 1},
		{1, "k2", 2},
		{1, "k3", 3},
	}
	for _, t := range testData {
		m.Insert(t.key1, t.key2, t.val)
	}
	cb = 0
	m.Iterate(func(k1 int, k2 string, v int) bool {
		cb++
		return true
	})
	sui.Require().Equal(1, cb)
	sui.Require().Equal(cb, m.Len())

	m.Clear()
	sui.Require().Equal(0, m.Len())

	cb = 0
	m.Iterate(func(k1 int, k2 string, v int) bool {
		cb++
		return true
	})
	sui.Require().Equal(0, cb)
	sui.Require().Equal(cb, m.Len())
}

func Test_BiMAP(t *testing.T) {
	suite.Run(t, new(bimapTestSuite))
}
