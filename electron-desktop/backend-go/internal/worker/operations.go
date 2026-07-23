package worker

import (
	"context"
	"errors"
	"strings"
	"time"
)

type trackedOperation struct {
	cancel context.CancelFunc
}

func boundedOperationTimeout(milliseconds int, fallback, minimum, maximum time.Duration) time.Duration {
	value := time.Duration(milliseconds) * time.Millisecond
	if milliseconds <= 0 {
		value = fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func (s *Server) beginOperation(id string, timeout time.Duration) (context.Context, func(), error) {
	operationID := strings.TrimSpace(id)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	if operationID == "" {
		return ctx, cancel, nil
	}

	tracked := &trackedOperation{cancel: cancel}
	s.operationMu.Lock()
	if _, exists := s.operations[operationID]; exists {
		s.operationMu.Unlock()
		cancel()
		return nil, nil, errors.New("operation_id is already active")
	}
	s.operations[operationID] = tracked
	s.operationMu.Unlock()

	finish := func() {
		cancel()
		s.operationMu.Lock()
		if s.operations[operationID] == tracked {
			delete(s.operations, operationID)
		}
		s.operationMu.Unlock()
	}
	return ctx, finish, nil
}

func (s *Server) cancelOperation(id string) bool {
	operationID := strings.TrimSpace(id)
	if operationID == "" {
		return false
	}
	s.operationMu.Lock()
	tracked := s.operations[operationID]
	s.operationMu.Unlock()
	if tracked == nil {
		return false
	}
	tracked.cancel()
	return true
}

func (s *Server) cancelAllOperations() {
	s.operationMu.Lock()
	tracked := make([]*trackedOperation, 0, len(s.operations))
	for _, operation := range s.operations {
		tracked = append(tracked, operation)
	}
	s.operations = make(map[string]*trackedOperation)
	s.operationMu.Unlock()
	for _, operation := range tracked {
		operation.cancel()
	}
}
