// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package peer

import (
	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/node/manager"

	"golang.org/x/sync/errgroup"
)

// Service implements the peerpb.PeerServer gRPC service.
// TODO: implement tests. This requires turning manager.Manager into an
// interface so that it can be mocked for the purpose of testing.
type Service struct {
	stop chan (struct{})
	mgr  *manager.Manager
}

// Ensure that Service implements the peerpb.PeerServer interface.
var _ peerpb.PeerServer = (*Service)(nil)

// NewService creates a new Service.
func NewService(mgr *manager.Manager) *Service {
	return &Service{
		stop: make(chan struct{}),
		mgr:  mgr,
	}
}

// Notify implements peerpb.Peer_PeerServer.Notify.
func (s *Service) Notify(_ *peerpb.NotifyRequest, stream peerpb.Peer_NotifyServer) error {
	h := newHandler()
	defer h.Close()
	// The node manager sends notifications upon call to Subscribe. As the
	// handler's channel is unbuffered, make sure that the client is ready to
	// read notifications to avoid a deadlock situation.
	var g errgroup.Group
	g.Go(func() error {
		for {
			select {
			case <-s.stop:
				return nil
			case cn := <-h.C:
				if err := stream.Send(cn); err != nil {
					//FIXME: retry?
					return err
				}
			}
		}
	})
	s.mgr.Subscribe(h)
	defer s.mgr.Unsubscribe(h)
	return g.Wait()
}

// Close frees resources associated to the Service.
func (s *Service) Close() error {
	close(s.stop)
	return nil
}
