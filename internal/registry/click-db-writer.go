package registry

import (
	"context"
	"sync"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	model "github.com/wildberries-tech/pkt-tracer/internal/registry/clickhouse"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/pkg/errors"
)

var _ BatchWriter = (*clickDbBatcher)(nil)

type clickDbBatcher struct {
	sync.Mutex
	reg           *clickDbRegistry
	table         string
	ctx           context.Context
	cap           BatchCapacity
	batchReporter BatchFlushedCountReporter
	isClosed      bool
	batch         driver.Batch
}

func (c *clickDbBatcher) ensureBatch() (err error) {
	if c.batch != nil {
		return nil
	}
	ok := c.reg.pool.Fetch(func(conn driver.Conn) {
		query := "INSERT INTO " + c.reg.db + "." + c.table
		c.batch, err = conn.PrepareBatch(
			c.ctx,
			query,
			driver.WithReleaseConnection(),
		)
	})
	if !ok {
		err = ErrNoRegistry
	}
	return errors.WithMessage(err, "on init new batch")
}

func (c *clickDbBatcher) size() int {
	if c.batch != nil {
		return c.batch.Rows()
	}
	return 0
}

func (c *clickDbBatcher) batchFlush() (count int, err error) {
	defer func() {
		err = errors.WithMessage(err, "on batch flush")
	}()
	if count = c.size(); count > 0 {
		err = c.batch.Send()
	} else if c.batch != nil {
		_ = c.batch.Abort()
	}
	c.batch = nil
	return count, err
}

func (c *clickDbBatcher) tracePut(m *trace.TraceModel) (count int, err error) {
	var msg model.TraceDB
	msg.InitFromTraceModel(m)
	defer func() {
		err = errors.WithMessage(err, "on put 'trace' record")
	}()
	if err = c.ensureBatch(); err == nil {
		err = c.batch.AppendStruct(&msg)
	}
	if err == nil && c.size() >= int(c.cap) {
		count, err = c.batchFlush()
	}
	return count, err
}

func (c *clickDbBatcher) PutTrace(msg *trace.TraceModel) (err error) {
	c.Lock()
	if c.isClosed {
		c.Unlock()
		return ErrWriterClosed
	}
	var count int
	defer func() {
		c.Unlock()
		if err == nil && count > 0 {
			c.reg.registrySubject.Notify(CountDBWriteEvent{Cnt: count})
			if c.batchReporter != nil {
				c.batchReporter(count)
			}
		}
	}()
	count, err = c.tracePut(msg)
	return err
}

func (c *clickDbBatcher) PutNftTable(msg *trace.NftTableModel) (err error) {
	c.Lock()
	if c.isClosed {
		c.Unlock()
		return ErrWriterClosed
	}
	var count int
	defer func() {
		c.Unlock()
		if err == nil && count > 0 {
			c.reg.registrySubject.Notify(CountDBWriteEvent{Cnt: count})
			if c.batchReporter != nil {
				c.batchReporter(count)
			}
		}
	}()
	count, err = c.nftablePut(msg)
	return err
}

func (c *clickDbBatcher) nftablePut(m *trace.NftTableModel) (count int, err error) {
	defer func() {
		err = errors.WithMessage(err, "on put 'nftable' record")
	}()

	for _, rlch := range m.Rules {
		cnt := 0
		msg := model.NftTablesDB{
			TableName:   m.TableName,
			TableFamily: m.TableFamily,
			ChainName:   rlch.ChainName,
			Rule:        rlch.Rule,
			TableStr:    m.TableStr,
			Timestamp:   time.Now(),
		}
		if err = c.ensureBatch(); err == nil {
			err = c.batch.AppendStruct(&msg)
		}
		if err == nil && c.size() >= int(c.cap) {
			cnt, err = c.batchFlush()
			count += cnt
		}
		if err != nil {
			break
		}
	}

	return count, err
}

func (c *clickDbBatcher) Flush() (err error) {
	c.Lock()
	if c.isClosed {
		c.Unlock()
		return ErrWriterClosed
	}
	var count int
	defer func() {
		c.Unlock()
		if err == nil && count > 0 {
			c.reg.registrySubject.Notify(CountDBWriteEvent{Cnt: count})
			if c.batchReporter != nil {
				c.batchReporter(count)
			}
		}
	}()
	count, err = c.batchFlush()
	return err
}

func (c *clickDbBatcher) Close() error {
	c.Lock()
	defer c.Unlock()
	if !c.isClosed {
		c.isClosed = true
		if c.batch != nil {
			_ = c.batch.Abort()
		}
	}
	return nil
}
