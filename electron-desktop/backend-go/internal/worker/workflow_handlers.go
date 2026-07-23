package worker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/workflow"
)

func (s *Server) registerWorkflowHandlers() {
	s.handlers["workflow.run"] = s.workflowRun
}

func (s *Server) workflowRun(raw json.RawMessage) (any, *protocol.RPCError) {
	var params workflow.Options
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := workflow.New(s.web, s.store, s.emit).Run(ctx, params)
	return webResult(result, err)
}
