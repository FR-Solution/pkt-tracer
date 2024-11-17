package nftmonitor

import (
	"fmt"
	"strings"
	"time"

	nfte "github.com/wildberries-tech/pkt-tracer/internal/nftables/encoders"
	"github.com/wildberries-tech/pkt-tracer/internal/nftables/parser"

	"github.com/H-BF/corlib/pkg/dict"
	nftLib "github.com/google/nftables"
)

type (
	slice[T any]  []T
	SliceT[T any] struct {
		slice[T]
	}
	RuleEntry struct {
		position int
		Rule     *nftLib.Rule
	}
	RuleEntryKey struct {
		ChainEntryKey
		RuleHandle uint64
	}
	ChainEntry struct {
		position     int
		Chain        *nftLib.Chain
		OrderedRules SliceT[*RuleEntry]
		rulesCache   dict.HDict[RuleEntryKey, *RuleEntry]
	}
	ChainEntryKey struct {
		TableEntryKey
		ChainName string
	}
	ElementEntry struct {
		position int
		Elem     nftLib.SetElement
	}
	ElementEntryKey struct {
		SetEntryKey
		Elem string
	}
	SetEntry struct {
		position         int
		Set              *nftLib.Set
		OrderedElements  SliceT[ElementEntry]
		setElementsCache dict.HDict[ElementEntryKey, ElementEntry]
	}
	SetEntryKey struct {
		TableEntryKey
		SetName string
	}

	TableEntry struct {
		Table         *nftLib.Table
		OrderedChains SliceT[*ChainEntry]
		chainsCache   dict.HDict[ChainEntryKey, *ChainEntry]
		OrderedSets   SliceT[*SetEntry]
		setsCache     dict.HDict[SetEntryKey, *SetEntry]
		UpdatedAt     time.Time
		UsedAt        time.Time
	}

	TableEntryKey struct {
		TableName   string
		TableFamily nftLib.TableFamily
	}
)

func (s *SliceT[T]) Rm(id int) {
	if id < 0 || id >= s.Len() {
		return
	}
	if len(s.slice) == 1 || id == len(s.slice)-1 {
		s.slice = s.slice[:s.Len()-1]
		return
	}
	s.slice = append(s.slice[:id], s.slice[id+1:]...)
}

func (s *SliceT[T]) Clear() {
	s.slice = nil
}

func (s *SliceT[T]) Len() int {
	return len(s.slice)
}

func (s *SliceT[T]) Add(val ...T) {
	s.slice = append(s.slice, val...)
}
func (s *SliceT[T]) Put(id int, val T) {
	if id < 0 || id >= s.Len() {
		return
	}
	s.slice[id] = val
}

func (s *SliceT[T]) Iterate(f func(T) bool) {
	for _, val := range s.slice {
		if !f(val) {
			return
		}
	}
}

func (r *RuleEntry) String() (string, error) {
	return (*nfte.RuleEncode)(r.Rule).String()
}

func (c *ChainEntry) PutRules(rules ...*nftLib.Rule) {
	for _, rule := range rules {
		entry := &RuleEntry{
			position: c.OrderedRules.Len(),
			Rule:     rule,
		}
		key := RuleEntryKey{
			ChainEntryKey: ChainEntryKey{
				TableEntryKey: TableEntryKey{
					TableName:   rule.Table.Name,
					TableFamily: rule.Table.Family,
				},
				ChainName: c.Chain.Name,
			},
			RuleHandle: rule.Handle,
		}
		if oldEntry, ok := c.rulesCache.Get(key); ok {
			entry.position = oldEntry.position
			c.OrderedRules.Put(oldEntry.position, entry)
		} else {
			c.OrderedRules.Add(entry)
		}
		c.rulesCache.Put(key, entry)
	}
}

func (c *ChainEntry) RmRule(rule *nftLib.Rule) {
	key := RuleEntryKey{
		ChainEntryKey: ChainEntryKey{
			TableEntryKey: TableEntryKey{
				TableName:   rule.Table.Name,
				TableFamily: rule.Table.Family,
			},
			ChainName: c.Chain.Name,
		},
		RuleHandle: rule.Handle,
	}
	if entry, ok := c.rulesCache.Get(key); ok {
		c.rulesCache.Del(key)
		c.OrderedRules.Rm(entry.position)
	}
}

func (c *ChainEntry) String() (string, error) {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("chain %s {\n", c.Chain.Name))
	if c.Chain.Type != "" || c.Chain.Hooknum != nil || c.Chain.Priority != nil || c.Chain.Policy != nil {
		sb.WriteString("\t\t")
		if c.Chain.Type != "" {
			sb.WriteString(fmt.Sprintf("type %s ", c.Chain.Type))
		}
		if c.Chain.Hooknum != nil {
			sb.WriteString(fmt.Sprintf("hook %s ", parser.ChainHook(*c.Chain.Hooknum)))
		}
		if c.Chain.Priority != nil {
			sb.WriteString(fmt.Sprintf("priority %s; ", parser.ChainPriority(*c.Chain.Priority)))
		}
		if c.Chain.Policy != nil {
			sb.WriteString(fmt.Sprintf("policy %s;", parser.ChainPolicy(*c.Chain.Policy)))
		}
		sb.WriteByte('\n')
	}

	for _, rule := range c.OrderedRules.slice {
		ruleStr, err := rule.String()
		if err != nil {
			return "", err
		}
		sb.WriteString("\t\t")
		sb.WriteString(ruleStr)
		sb.WriteByte('\n')
	}
	sb.WriteString("\t}")
	return sb.String(), nil
}

func (s *SetEntry) String() (string, error) {
	sb := strings.Builder{}

	sb.WriteString(fmt.Sprintf("set %s {\n\t\ttype %s\n\t\tflags %s\n\t\telements = { ",
		s.Set.Name, s.Set.KeyType.Name, strings.Join(parser.Set{Set: s.Set}.Flags(), ",")))
	sb.WriteString(
		parser.Set{
			Set: s.Set,
			Elems: func() []nftLib.SetElement {
				var elems []nftLib.SetElement
				s.OrderedElements.Iterate(func(e ElementEntry) bool {
					elems = append(elems, e.Elem)
					return true
				})
				return elems
			}(),
		}.String())
	sb.WriteString(" }\n\t}")
	return sb.String(), nil
}

func (s *SetEntry) PutElements(elems ...nftLib.SetElement) {
	for _, el := range elems {
		entry := ElementEntry{
			position: s.OrderedElements.Len(),
			Elem:     el,
		}
		key := ElementEntryKey{
			SetEntryKey: SetEntryKey{
				TableEntryKey: TableEntryKey{
					TableName:   s.Set.Table.Name,
					TableFamily: s.Set.Table.Family,
				},
				SetName: s.Set.Name,
			},
			Elem: parser.SetElem{Set: s.Set, Elem: el}.String(),
		}
		if oldEntry, ok := s.setElementsCache.Get(key); ok {
			entry.position = oldEntry.position
			s.OrderedElements.Put(oldEntry.position, entry)
		} else {
			s.OrderedElements.Add(entry)
		}
		s.setElementsCache.Put(key, entry)
	}
}

func (s *SetEntry) RmElements(elems ...nftLib.SetElement) {
	for _, el := range elems {
		key := ElementEntryKey{
			SetEntryKey: SetEntryKey{
				TableEntryKey: TableEntryKey{
					TableName:   s.Set.Table.Name,
					TableFamily: s.Set.Table.Family,
				},
				SetName: s.Set.Name,
			},
			Elem: parser.SetElem{Set: s.Set, Elem: el}.String(),
		}
		if entry, ok := s.setElementsCache.Get(key); ok {
			s.setElementsCache.Del(key)
			s.OrderedElements.Rm(entry.position)
		}
	}
}

//nolint:dupl
func (t *TableEntry) PutChains(chains ...*nftLib.Chain) {
	for _, chain := range chains {
		entry := &ChainEntry{
			position: t.OrderedChains.Len(),
			Chain:    chain,
		}
		key := ChainEntryKey{
			TableEntryKey: TableEntryKey{
				TableName:   chain.Table.Name,
				TableFamily: chain.Table.Family,
			},
			ChainName: chain.Name,
		}
		if oldEntry, ok := t.chainsCache.Get(key); ok {
			entry.position = oldEntry.position
			t.OrderedChains.Put(oldEntry.position, entry)
		} else {
			t.OrderedChains.Add(entry)
		}
		t.chainsCache.Put(key, entry)
	}
}

func (t *TableEntry) InsertChainWithRules(chain *nftLib.Chain, rules ...*nftLib.Rule) {
	entry := &ChainEntry{position: t.chainsCache.Len(), Chain: chain}
	entry.PutRules(rules...)
	key := ChainEntryKey{
		TableEntryKey: TableEntryKey{
			TableName:   chain.Table.Name,
			TableFamily: chain.Table.Family,
		},
		ChainName: chain.Name,
	}
	if oldEntry, ok := t.chainsCache.Get(key); ok {
		entry.position = oldEntry.position
		t.OrderedChains.Put(oldEntry.position, entry)
	} else {
		t.OrderedChains.Add(entry)
	}
	t.chainsCache.Put(key, entry)
}

func (t *TableEntry) RmChains(chains ...*nftLib.Chain) {
	for _, chain := range chains {
		key := ChainEntryKey{
			TableEntryKey: TableEntryKey{
				TableName:   chain.Table.Name,
				TableFamily: chain.Table.Family,
			},
			ChainName: chain.Name,
		}
		if entry, ok := t.chainsCache.Get(key); ok {
			t.chainsCache.Del(key)
			t.OrderedChains.Rm(entry.position)
		}
	}
}

func (t *TableEntry) GetChainEntry(key ChainEntryKey) (val *ChainEntry, ok bool) {
	return t.chainsCache.Get(key)
}

func (t *TableEntry) GetSetEntry(key SetEntryKey) (val *SetEntry, ok bool) {
	return t.setsCache.Get(key)
}

//nolint:dupl
func (t *TableEntry) PutSets(sets ...*nftLib.Set) {
	for _, set := range sets {
		entry := &SetEntry{
			position: t.OrderedChains.Len(),
			Set:      set,
		}
		key := SetEntryKey{
			TableEntryKey: TableEntryKey{
				TableName:   set.Table.Name,
				TableFamily: set.Table.Family,
			},
			SetName: set.Name,
		}
		if oldEntry, ok := t.setsCache.Get(key); ok {
			entry.position = oldEntry.position
			t.OrderedSets.Put(oldEntry.position, entry)
		} else {
			t.OrderedSets.Add(entry)
		}
		t.setsCache.Put(key, entry)
	}
}

func (t *TableEntry) InsertSetWithElements(set *nftLib.Set, elements ...nftLib.SetElement) {
	key := SetEntryKey{
		TableEntryKey: TableEntryKey{
			TableName:   set.Table.Name,
			TableFamily: set.Table.Family,
		},
		SetName: set.Name,
	}
	entry := &SetEntry{
		position: t.OrderedSets.Len(),
		Set:      set,
	}
	entry.PutElements(elements...)

	if oldEntry, ok := t.setsCache.Get(key); ok {
		entry.position = oldEntry.position
		t.OrderedSets.Put(oldEntry.position, entry)
	} else {
		t.OrderedSets.Add(entry)
	}
	t.setsCache.Put(key, entry)
}

func (t *TableEntry) RmSets(sets ...*nftLib.Set) {
	for _, set := range sets {
		key := SetEntryKey{
			TableEntryKey: TableEntryKey{
				TableName:   set.Table.Name,
				TableFamily: set.Table.Family,
			},
			SetName: set.Name,
		}
		if entry, ok := t.setsCache.Get(key); ok {
			t.setsCache.Del(key)
			t.OrderedSets.Rm(entry.position)
		}
	}
}

func (t *TableEntry) String() (string, error) {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("table %s %s {\n", parser.TableFamily(t.Table.Family), t.Table.Name))
	for _, set := range t.OrderedSets.slice {
		setStr, err := set.String()
		if err != nil {
			return "", err
		}
		sb.WriteByte('\t')
		sb.WriteString(setStr)
		sb.WriteByte('\n')
	}
	for _, chain := range t.OrderedChains.slice {
		chainStr, err := chain.String()
		if err != nil {
			return "", err
		}
		sb.WriteByte('\t')
		sb.WriteString(chainStr)
		sb.WriteByte('\n')
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

func (t *TableEntry) Timed() TableEntry {
	t.UpdatedAt = time.Now()
	return *t
}
