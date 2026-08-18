package trusted

import (
	"context"
	"sync"

	"github.com/donovan-yohan/airlock/internal/paging"
)

// ActionService is the single in-process authority for trusted decisions and
// execution. Web and local-control handlers deliberately share this object so
// there is one reservation, retry, receipt, and provider-invocation path.
type ActionService struct {
	store *Store

	mu       sync.Mutex
	root     context.Context
	cancel   context.CancelFunc
	active   int
	stopping bool
	done     chan struct{}
}

func NewActionService(store *Store) *ActionService {
	ctx, cancel := context.WithCancel(context.Background())
	return &ActionService{store: store, root: ctx, cancel: cancel, done: make(chan struct{})}
}

// Execute deliberately does not inherit the frontend context. After this
// daemon accepts an execution, a web or control disconnect cannot revoke the
// already reserved action; only daemon shutdown, its deadline, or Store's own
// outcome handling can end it.
// Execute accepts only an explicit, transport-validated full-authority
// confirmation. Keeping this check at the shared action boundary prevents a
// future trusted transport from accidentally turning a plan-digest post into
// sufficient authority.
func (s *ActionService) Execute(_ context.Context, id, reviewer, planDigest string, confirmFullAuthority bool) error {
	if !confirmFullAuthority {
		return ErrExecutionConfirmationRequired
	}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return ErrExecutionUnavailable
	}
	ctx := s.root
	s.active++
	s.mu.Unlock()

	defer s.complete()
	return s.store.Execute(ctx, id, reviewer, planDigest)
}

// Shutdown closes execution admission and cancels every daemon-owned child
// context before waiting for Store to persist each terminal outcome. The
// admission/count gate avoids WaitGroup Add/Wait races and makes repeated
// shutdown calls safe.
func (s *ActionService) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.stopping {
		s.stopping = true
		s.cancel()
		if s.active == 0 {
			close(s.done)
		}
	}
	done := s.done
	s.mu.Unlock()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *ActionService) complete() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.stopping && s.active == 0 {
		close(s.done)
	}
}

func (s *ActionService) Deny(id, reviewer string) error {
	_, err := s.store.Deny(id, reviewer)
	return err
}

func (s *ActionService) Record(id string) (Record, *ExecutionPlan, bool) { return s.store.Record(id) }

func (s *ActionService) RecordPage(cursor string) ([]Record, string, error) {
	return s.store.RecordPage(paging.MaxPage, cursor)
}

func (s *ActionService) ControlRecordPage(cursor string) ([]Record, string, error) {
	return s.store.RecordPage(maxControlPageRecords, cursor)
}
