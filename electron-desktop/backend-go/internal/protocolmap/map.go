package protocolmap

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

type family struct {
	Name             string   `json:"name"`
	Count            int      `json:"count"`
	Fields           []string `json:"fields"`
	AuthFields       []string `json:"auth_fields"`
	IdentifierFields []string `json:"identifier_fields"`
	Sample           any      `json:"sample"`
	fieldSet         map[string]bool
}

func Build(ctx context.Context, database *store.Store, projectID string) (map[string]any, error) {
	connections, err := database.ListEntities(ctx, "ws_connections", projectID, 5000)
	if err != nil {
		return nil, err
	}
	frames, err := database.ListEntities(ctx, "ws_frames", projectID, 5000)
	if err != nil {
		return nil, err
	}
	findings, err := database.ListEntities(ctx, "findings", projectID, 5000)
	if err != nil {
		return nil, err
	}

	families := map[string]*family{}
	fieldCounts := map[string]int{}
	transitions := map[string]int{}
	lastByConnection := map[string]string{}
	for index := len(frames) - 1; index >= 0; index-- {
		frame := frames[index]
		name, fields, sample := classify(frame)
		current := families[name]
		if current == nil {
			current = &family{Name: name, Sample: sample, fieldSet: map[string]bool{}}
			families[name] = current
		}
		current.Count++
		for _, field := range fields {
			current.fieldSet[field] = true
			fieldCounts[field]++
		}
		connectionID, _ := frame.Metadata["connection_id"].(string)
		if previous := lastByConnection[connectionID]; connectionID != "" && previous != "" {
			transitions[previous+"\x00"+name]++
		}
		if connectionID != "" {
			lastByConnection[connectionID] = name
		}
	}

	familyList := make([]map[string]any, 0, len(families))
	templates := make([]map[string]any, 0, len(families))
	allFields := map[string]bool{}
	for _, item := range families {
		item.Fields = sortedSet(item.fieldSet)
		for _, field := range item.Fields {
			allFields[field] = true
			lower := strings.ToLower(field)
			if containsAny(lower, "auth", "token", "session", "cookie", "secret", "password") {
				item.AuthFields = append(item.AuthFields, field)
			}
			if containsAny(lower, "id", "tenant", "user", "account", "channel", "room", "role") {
				item.IdentifierFields = append(item.IdentifierFields, field)
			}
		}
		sort.Strings(item.AuthFields)
		sort.Strings(item.IdentifierFields)
		familyList = append(familyList, map[string]any{"name": item.Name, "count": item.Count, "fields": item.Fields, "auth_fields": item.AuthFields, "identifier_fields": item.IdentifierFields, "sample": item.Sample})
		editable := make([]map[string]any, 0, len(item.Fields))
		for _, field := range item.Fields {
			editable = append(editable, map[string]any{"location": "payload", "name": field})
		}
		templates = append(templates, map[string]any{"name": item.Name, "count": item.Count, "fields": item.Fields, "editable_fields": editable})
	}
	sort.Slice(familyList, func(i, j int) bool { return familyList[i]["name"].(string) < familyList[j]["name"].(string) })
	sort.Slice(templates, func(i, j int) bool { return templates[i]["name"].(string) < templates[j]["name"].(string) })

	transitionList := make([]map[string]any, 0, len(transitions))
	for key, count := range transitions {
		parts := strings.SplitN(key, "\x00", 2)
		transitionList = append(transitionList, map[string]any{"source": parts[0], "target": parts[1], "count": count})
	}
	sort.Slice(transitionList, func(i, j int) bool { return transitionList[i]["count"].(int) > transitionList[j]["count"].(int) })

	nodes := make([]map[string]any, 0, len(connections))
	for _, connection := range connections {
		nodes = append(nodes, map[string]any{"id": "conn:" + connection.ID, "type": "connection", "label": connection.Name, "meta": connection.Metadata})
	}
	findingCategories := map[string]int{}
	for _, finding := range findings {
		findingCategories[finding.Name]++
	}
	recurring := []string{}
	for field, count := range fieldCounts {
		if count > 1 {
			recurring = append(recurring, field)
		}
	}
	sort.Strings(recurring)
	format := "unknown"
	if _, ok := families["binary"]; ok && len(families) == 1 {
		format = "binary"
	} else if len(allFields) > 0 {
		format = "json"
	} else if len(frames) > 0 {
		format = "text"
	}
	recommendations := []map[string]any{{"id": "mutation", "title": "Protocol mutation", "reason": "Mutate observed message fields and compare behavior."}}
	if containsField(allFields, "tenant", "role", "user", "account", "id") {
		recommendations = append(recommendations, map[string]any{"id": "authz-diff", "title": "Authorization difference", "reason": "Identity-like fields were observed in captured frames."})
	}
	if containsField(allFields, "channel", "room", "subscription", "tenant") {
		recommendations = append(recommendations, map[string]any{"id": "subscription-abuse", "title": "Subscription abuse", "reason": "Channel or tenant fields may define subscription boundaries."})
	}
	result := map[string]any{
		"summary":          map[string]any{"connection_count": len(connections), "frame_count": len(frames), "family_count": len(familyList), "finding_count": len(findings)},
		"protocol_summary": map[string]any{"format": format, "recurring_fields": recurring, "injectable_fields": sortedSet(allFields)},
		"message_families": familyList, "transitions": transitionList, "templates": templates, "nodes": nodes,
		"correlation_groups": []any{}, "finding_categories": findingCategories, "recommended_attacks": recommendations,
		"target_packs": []any{}, "playbook_candidates": []any{},
	}
	encoded, _ := json.Marshal(result)
	_, _ = database.SaveEntity(ctx, "protocol_maps", store.Entity{ID: "protocol-map-" + projectID, ProjectID: projectID, Name: "live-protocol-map", Value: string(encoded), Metadata: map[string]any{"summary": result["summary"]}})
	return result, nil
}

func classify(frame store.Entity) (string, []string, any) {
	if frame.Metadata["message_type"] == "binary" {
		return "binary", nil, map[string]any{"encoding": "base64", "size": frame.Metadata["size"]}
	}
	var value any
	if json.Unmarshal([]byte(frame.Value), &value) != nil {
		return "text", nil, frame.Value
	}
	document, ok := value.(map[string]any)
	if !ok {
		return "json-value", nil, value
	}
	name := "json"
	for _, key := range []string{"type", "action", "event", "operation", "command"} {
		if candidate := strings.TrimSpace(toString(document[key])); candidate != "" {
			name = key + ":" + candidate
			break
		}
	}
	fields := make([]string, 0, len(document))
	for key := range document {
		fields = append(fields, key)
	}
	sort.Strings(fields)
	return name, fields, document
}

func toString(value any) string {
	text, _ := value.(string)
	return text
}

func sortedSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func containsField(fields map[string]bool, candidates ...string) bool {
	for field := range fields {
		if containsAny(strings.ToLower(field), candidates...) {
			return true
		}
	}
	return false
}
