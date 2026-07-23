package worker

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocolmap"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

func (s *Server) registerStorageHandlers() {
	s.handlers["projects.list"] = s.projectsList
	s.handlers["projects.get"] = s.projectsGet
	s.handlers["projects.save"] = s.projectsSave
	s.handlers["projects.delete"] = s.projectsDelete
	s.handlers["projects.snapshot"] = s.projectsSnapshot
	s.handlers["projects.import"] = s.projectsImport
	s.handlers["entities.list"] = s.entitiesList
	s.handlers["entities.get"] = s.entitiesGet
	s.handlers["entities.save"] = s.entitiesSave
	s.handlers["entities.delete"] = s.entitiesDelete
	s.handlers["storage.backup"] = s.storageBackup
	s.handlers["protocol.map"] = s.protocolMap
}

func (s *Server) protocolMap(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ProjectID string `json:"project_id"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	result, err := protocolmap.Build(context.Background(), s.store, params.ProjectID)
	return resultOrError(map[string]any{"protocol_map": result}, err)
}

type projectParams struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	TargetURL string         `json:"target_url"`
	Metadata  map[string]any `json:"metadata"`
	Limit     int            `json:"limit"`
}

type entityParams struct {
	Kind      string         `json:"kind"`
	ID        string         `json:"id"`
	ProjectID string         `json:"project_id"`
	Name      string         `json:"name"`
	Value     string         `json:"value"`
	Metadata  map[string]any `json:"metadata"`
	Limit     int            `json:"limit"`
}

func (s *Server) projectsList(raw json.RawMessage) (any, *protocol.RPCError) {
	var params projectParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	projects, err := s.store.ListProjects(context.Background(), params.Limit)
	return resultOrError(map[string]any{"projects": projects}, err)
}

func (s *Server) projectsGet(raw json.RawMessage) (any, *protocol.RPCError) {
	var params projectParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	project, err := s.store.GetProject(context.Background(), params.ID)
	if err != nil {
		return nil, storageError(err)
	}
	snapshot, err := s.store.ProjectSnapshot(context.Background(), project.ID)
	if err != nil {
		return nil, storageError(err)
	}
	return snapshot, nil
}

func (s *Server) projectsSave(raw json.RawMessage) (any, *protocol.RPCError) {
	var params projectParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	project, err := s.store.SaveProject(context.Background(), store.Project{ID: params.ID, Name: params.Name, TargetURL: params.TargetURL, Metadata: params.Metadata})
	return resultOrError(map[string]any{"project": project}, err)
}

func (s *Server) projectsDelete(raw json.RawMessage) (any, *protocol.RPCError) {
	var params projectParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	err := s.store.DeleteProject(context.Background(), params.ID)
	return resultOrError(map[string]any{"deleted": err == nil, "id": params.ID}, err)
}

func (s *Server) projectsSnapshot(raw json.RawMessage) (any, *protocol.RPCError) {
	var params projectParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	snapshot, err := s.store.ProjectSnapshot(context.Background(), params.ID)
	return resultOrError(snapshot, err)
}

func (s *Server) projectsImport(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ContentBase64 string `json:"content_base64"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	content, err := base64.StdEncoding.DecodeString(params.ContentBase64)
	if err != nil {
		return nil, &protocol.RPCError{Code: "invalid_params", Message: "Project content is not valid base64"}
	}
	project, err := s.store.ImportJSON(context.Background(), content)
	return resultOrError(map[string]any{"project": project}, err)
}

func (s *Server) entitiesList(raw json.RawMessage) (any, *protocol.RPCError) {
	var params entityParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	entities, err := s.store.ListEntities(context.Background(), params.Kind, params.ProjectID, params.Limit)
	return resultOrError(map[string]any{"items": entities, "kind": params.Kind}, err)
}

func (s *Server) entitiesGet(raw json.RawMessage) (any, *protocol.RPCError) {
	var params entityParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	entity, err := s.store.GetEntity(context.Background(), params.Kind, params.ID)
	return resultOrError(map[string]any{"item": entity, "kind": params.Kind}, err)
}

func (s *Server) entitiesSave(raw json.RawMessage) (any, *protocol.RPCError) {
	var params entityParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	entity, err := s.store.SaveEntity(context.Background(), params.Kind, store.Entity{ID: params.ID, ProjectID: params.ProjectID, Name: params.Name, Value: params.Value, Metadata: params.Metadata})
	return resultOrError(map[string]any{"item": entity, "kind": params.Kind}, err)
}

func (s *Server) entitiesDelete(raw json.RawMessage) (any, *protocol.RPCError) {
	var params entityParams
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	err := s.store.DeleteEntity(context.Background(), params.Kind, params.ID)
	return resultOrError(map[string]any{"deleted": err == nil, "id": params.ID}, err)
}

func (s *Server) storageBackup(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct{}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	path, err := s.store.Backup(context.Background())
	return resultOrError(map[string]any{"path": path}, err)
}

func decodeParams(raw json.RawMessage, destination any) *protocol.RPCError {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return &protocol.RPCError{Code: "invalid_params", Message: "Request parameters are invalid", Detail: err.Error()}
	}
	return nil
}

func resultOrError(result any, err error) (any, *protocol.RPCError) {
	if err != nil {
		return nil, storageError(err)
	}
	return result, nil
}

func storageError(err error) *protocol.RPCError {
	if errors.Is(err, sql.ErrNoRows) {
		return &protocol.RPCError{Code: "not_found", Message: "Requested record was not found"}
	}
	return &protocol.RPCError{Code: "storage_error", Message: "Project database operation failed", Detail: fmt.Sprintf("%v", err)}
}
