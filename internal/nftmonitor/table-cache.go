package nftmonitor

import (
	"github.com/wildberries-tech/pkt-tracer/internal/nftables/parser"

	"github.com/H-BF/corlib/pkg/dict"
	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
)

type tableCache struct {
	dict.HDict[TableEntryKey, TableEntry]
}

// Refresh - update table cache
func (t *tableCache) Refresh() error {
	conn, err := nftLib.New()
	if err != nil {
		return errors.WithMessage(err, "failed to create netlink connection")
	}
	defer conn.CloseLasting() //nolint:errcheck
	tables, err := conn.ListTables()
	if err != nil {
		return errors.WithMessage(err, "failed to obtain list of tables from the netfilter")
	}

	for _, table := range tables {
		err := t.updTableEntries(table, conn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cache *tableCache) updTableEntries(table *nftLib.Table, conn *nftLib.Conn) error {
	tblEntry := TableEntry{Table: table}

	chains, err := conn.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return errors.WithMessagef(err,
			"failed to obtain list of chains from the netfilter for the table family='%s'",
			parser.TableFamily(table.Family),
		)
	}

	for _, chain := range chains {
		if chain.Table.Name == table.Name && chain.Table.Family == table.Family {
			rules, err := conn.GetRules(table, chain)
			if err != nil {
				return errors.WithMessagef(
					err, "failed to obtain rules from the netfilter for the table name='%s' family='%s' and chain=%s",
					table.Name, parser.TableFamily(table.Family), chain.Name,
				)
			}
			tblEntry.InsertChainWithRules(chain, rules...)
		}
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		return errors.WithMessagef(
			err, "failed to obtain list of sets from the netfilter for the table name='%s' family='%s'",
			table.Name, parser.TableFamily(table.Family),
		)
	}
	for _, set := range sets {
		elems, err := conn.GetSetElements(set)
		if err != nil {
			return errors.WithMessagef(err, "failed to obtain set elements for the set='%s'", set.Name)
		}
		tblEntry.InsertSetWithElements(set, elems...)
	}
	cache.Put(
		TableEntryKey{
			TableName:   table.Name,
			TableFamily: table.Family,
		},
		tblEntry.Timed())
	return nil
}

// PutTable put table into cache
func (cache *tableCache) PutTable(entry TableEntry) {
	cache.Put(
		TableEntryKey{
			TableName:   entry.Table.Name,
			TableFamily: entry.Table.Family,
		},
		entry)
}
