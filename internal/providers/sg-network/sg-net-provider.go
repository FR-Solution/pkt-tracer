package sgnetwork

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	sgAPI "github.com/wildberries-tech/pkt-tracer/internal/api/sgroups"
	sg "github.com/wildberries-tech/sgroups/v2/pkg/api/sgroups"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type (

	// SGClient is an alias to 'sgAPI.ClosableClient'
	SGClient = sgAPI.ClosableClient

	SgNameCache = map[NetworkName]SGName

	SGCollector interface {
		Run(ctx context.Context) (err error)
		GetSGByIP(ip net.IP) (SgNet, error)
		Close() error
	}

	sgCollectorImpl struct {
		cached        Cache
		sstaus        *SyncStatus
		client        SGClient
		checkInterval time.Duration
		usePushModel  bool
		onceRun       sync.Once
		onceClose     sync.Once
		stop          chan struct{}
		stopped       chan struct{}
	}
)

func NewSgCollector(ctx context.Context, c SGClient, d time.Duration, usePush bool) (SGCollector, error) {
	if d < time.Second {
		panic(
			fmt.Errorf("'SgCollector/CheckInterval' is (%v) less than 1s", d),
		)
	}
	s := &sgCollectorImpl{
		client:        c,
		checkInterval: d,
		usePushModel:  usePush,
		stop:          make(chan struct{}),
	}
	st, err := s.getSyncStatus(ctx)
	if err != nil {
		return nil, err
	}
	if st != nil {
		sg, err := s.fetchNwAndSG(ctx)
		if err != nil {
			return nil, err
		}
		s.sstaus = st
		s.cached.Init(sg)
	}
	return s, nil
}

// Run -
func (s *sgCollectorImpl) Run(ctx context.Context) (err error) {
	var doRun bool
	s.onceRun.Do(func() { doRun = true })
	if !doRun {
		return ErrSgNw{Err: errors.New("it has been run or closed yet")}
	}

	s.stopped = make(chan struct{})
	log := logger.FromContext(ctx).Named("sg-collector")
	mode := "pull"
	if s.usePushModel {
		mode = "push"
	}
	log.Infow("start", "mode", mode)
	defer func() {
		close(s.stopped)
		log.Info("stop")
	}()

	if s.usePushModel {
		return s.push(ctx, log)
	}
	tc := time.NewTicker(s.checkInterval)
	defer tc.Stop()
	return s.pull(ctx, tc, log)
}

// GetSGByIP -
func (s *sgCollectorImpl) GetSGByIP(ip net.IP) (nw SgNet, err error) {
	item := s.cached.Find(ip)
	if item == nil {
		err = ErrSgMiss
	} else {
		nw = *item
	}
	return nw, err
}

// Close -
func (s *sgCollectorImpl) Close() error {
	stopped := s.stopped
	s.onceClose.Do(func() {
		close(s.stop)
		s.onceRun.Do(func() {})
		if stopped != nil {
			<-stopped
		}
	})
	return nil
}

func (s *sgCollectorImpl) push(ctx context.Context, log logger.TypeOfLogger) (err error) {
	var (
		stream sg.SecGroupService_SyncStatusesClient
		errc   chan error
	)
	defer func() {
		if err != nil {
			log.Errorf("will exit cause %v", err)
		}
		if stream != nil {
			err = stream.CloseSend()
			if err != nil {
				log.Warnf("errors occurred while closing grpc stream for SG synchronization: %v", err)
			}
		}
		if errc != nil {
			<-errc
		}
	}()
	if stream, err = s.client.SyncStatuses(ctx, new(emptypb.Empty)); err != nil {
		return err
	}
	streamCtx := stream.Context()
	log.Debug("connected")
	errc = make(chan error, 1)
	go func() {
		defer close(errc)
		for {
			resp, err := stream.Recv()
			if err != nil {
				errc <- err
				return
			}
			if s.sstaus == nil || !s.sstaus.UpdatedAt.Equal(resp.GetUpdatedAt().AsTime()) {
				s.sstaus = &SyncStatus{
					UpdatedAt: resp.GetUpdatedAt().AsTime(),
				}
				sg, err := s.fetchNwAndSG(ctx)
				if err != nil {
					errc <- err
					return
				}
				s.cached.Init(sg)
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-streamCtx.Done():
			log.Info("will exit cause ctx canceled for grpc stream of SG synchronization")
			return streamCtx.Err()
		case errRcv := <-errc:
			return errRcv
		case <-s.stop:
			log.Info("will exit cause it has closed")
			return nil
		}
	}
}

func (s *sgCollectorImpl) pull(ctx context.Context, tc *time.Ticker, log logger.TypeOfLogger) (err error) {
	defer func() {
		if err != nil {
			log.Errorf("will exit cause %v", err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stop:
			log.Info("will exit cause it has closed")
			return nil
		case <-tc.C:
			st, err := s.getSyncStatus(ctx)
			if err != nil {
				return err
			}
			if s.sstaus == nil || !s.sstaus.UpdatedAt.Equal(st.UpdatedAt) {
				s.sstaus = st

				sg, err := s.fetchNwAndSG(ctx)
				if err != nil {
					return err
				}
				s.cached.Init(sg)
			}
		}
	}
}

func (s *sgCollectorImpl) getSyncStatus(ctx context.Context) (*SyncStatus, error) {
	var ret *SyncStatus
	resp, err := s.client.SyncStatus(ctx, new(emptypb.Empty))
	if err == nil {
		ret = new(SyncStatus)
		ret.UpdatedAt = resp.GetUpdatedAt().AsTime()
	} else if e := errors.Cause(err); status.Code(e) == codes.NotFound {
		err = nil
	}
	return ret, err
}

func (s *sgCollectorImpl) fetchNwAndSG(ctx context.Context) ([]*SgNet, error) {
	listSG, err := s.client.ListSecurityGroups(ctx, &sg.ListSecurityGroupsReq{})

	if err != nil {
		return nil, err
	}
	protoSgs := listSG.GetGroups()

	sgCache := make(SgNameCache, len(protoSgs))
	for _, protoSg := range protoSgs {
		for _, nwName := range protoSg.GetNetworks() {
			sgCache[nwName] = protoSg.GetName()
		}
	}
	//get a list of all networks, even those not associated with SG
	listNw, err := s.client.ListNetworks(ctx, &sg.ListNetworksReq{})

	if err != nil {
		return nil, err
	}
	protoNws := listNw.GetNetworks()
	sgn := make([]*SgNet, 0, len(protoNws))
	for _, protoNw := range protoNws {
		var m Network
		if m, err = Proto2ModelNetwork(protoNw); err != nil {
			return nil, err
		}
		sgName := sgCache[m.Name]
		sgn = append(sgn, &SgNet{m, sgName})
	}
	return sgn, nil
}
