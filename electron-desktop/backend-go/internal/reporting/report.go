package reporting

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

type Generator struct{ store *store.Store }

func New(database *store.Store) *Generator { return &Generator{store: database} }

func (g *Generator) Generate(ctx context.Context, projectID, format string) (map[string]any, error) {
	snapshot, err := g.store.ProjectSnapshot(ctx, projectID)
	if err != nil {
		return nil, err
	}
	format = strings.ToLower(format)
	var content []byte
	mime := "application/octet-stream"
	extension := format
	switch format {
	case "json":
		content, err = json.MarshalIndent(compactReportSnapshot(snapshot), "", "  ")
		mime = "application/json"
	case "html":
		content, err = htmlReport(snapshot)
		mime = "text/html"
	case "csv":
		content, err = csvReport(snapshot)
		mime = "text/csv"
	case "sarif":
		content, err = sarifReport(snapshot)
		mime = "application/sarif+json"
	case "markdown", "md":
		content, err = markdownReport(snapshot)
		mime = "text/markdown"
		extension = "md"
	default:
		return nil, errors.New("format must be json, html, csv, sarif, or markdown")
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	return map[string]any{"format": format, "extension": extension, "mime_type": mime, "content": string(content), "sha256": hex.EncodeToString(sum[:]), "bytes": len(content)}, nil
}

func compactReportSnapshot(snapshot map[string]any) map[string]any {
	result := map[string]any{
		"format":       "wshawk-security-report",
		"version":      1,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"project":      snapshot["project"],
	}
	counts := map[string]int{}
	for kind, value := range snapshot {
		if kind == "format" || kind == "version" || kind == "project" {
			continue
		}
		items := entityMaps(value)
		counts[kind] = len(items)
		compact := make([]map[string]any, 0, len(items))
		for _, item := range items {
			entry := map[string]any{
				"id":         item["id"],
				"project_id": item["project_id"],
				"name":       item["name"],
				"created_at": item["created_at"],
				"updated_at": item["updated_at"],
			}
			switch kind {
			case "identities", "sessions":
				entry["redacted"] = true
			case "http_flows", "ws_frames", "ws_connections":
				entry["metadata"] = item["metadata"]
				entry["raw_value_omitted"] = true
			default:
				entry["metadata"] = item["metadata"]
				value := fmt.Sprint(item["value"])
				if len(value) > 16*1024 {
					value = value[:16*1024]
					entry["value_truncated"] = true
				}
				entry["value"] = value
			}
			compact = append(compact, entry)
		}
		result[kind] = compact
	}
	result["counts"] = counts
	return result
}

func markdownReport(snapshot map[string]any) ([]byte, error) {
	project, _ := json.MarshalIndent(snapshot["project"], "", "  ")
	var out strings.Builder
	out.WriteString("# WSHawk Security Report\n\n## Project\n\n```json\n")
	out.Write(project)
	out.WriteString("\n```\n\n## Findings\n")
	findings := entityMaps(snapshot["findings"])
	if len(findings) == 0 {
		out.WriteString("\nNo findings recorded.\n")
	}
	for _, finding := range findings {
		metadata, _ := finding["metadata"].(map[string]any)
		out.WriteString("\n### " + fmt.Sprint(finding["name"]) + "\n\n")
		out.WriteString("- Severity: " + fmt.Sprint(metadata["severity"]) + "\n")
		out.WriteString("- URL: " + fmt.Sprint(metadata["url"]) + "\n")
		out.WriteString("- Detail: " + strings.ReplaceAll(fmt.Sprint(metadata["detail"]), "\n", " ") + "\n")
	}
	return []byte(out.String()), nil
}

func (g *Generator) Bundle(ctx context.Context, projectID string) (map[string]any, error) {
	snapshot, err := g.store.ProjectSnapshot(ctx, projectID)
	if err != nil {
		return nil, err
	}
	snapshotBytes, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, err
	}
	snapshotHash := sha256.Sum256(snapshotBytes)
	manifest := map[string]any{"format": "wshawk-evidence-bundle", "version": 1, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "project_id": projectID, "files": map[string]string{"project.json": hex.EncodeToString(snapshotHash[:])}}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, data := range map[string][]byte{"project.json": snapshotBytes, "manifest.json": manifestBytes} {
		entry, createErr := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now().UTC()})
		if createErr != nil {
			return nil, createErr
		}
		if _, writeErr := entry.Write(data); writeErr != nil {
			return nil, writeErr
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	bundleHash := sha256.Sum256(buffer.Bytes())
	return map[string]any{"content_base64": base64.StdEncoding.EncodeToString(buffer.Bytes()), "sha256": hex.EncodeToString(bundleHash[:]), "bytes": buffer.Len(), "manifest": manifest}, nil
}

func VerifyBundle(encoded string) (map[string]any, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("bundle is not valid base64")
	}
	if len(data) > 64*1024*1024 {
		return nil, errors.New("bundle exceeds 64 MiB")
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("bundle is not a valid ZIP")
	}
	files := map[string][]byte{}
	for _, entry := range reader.File {
		if entry.UncompressedSize64 > 64*1024*1024 {
			return nil, errors.New("bundle entry exceeds limit")
		}
		source, openErr := entry.Open()
		if openErr != nil {
			return nil, openErr
		}
		content, readErr := io.ReadAll(io.LimitReader(source, 64*1024*1024+1))
		source.Close()
		if readErr != nil {
			return nil, readErr
		}
		files[entry.Name] = content
	}
	var manifest struct {
		Format  string            `json:"format"`
		Version int               `json:"version"`
		Files   map[string]string `json:"files"`
	}
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		return nil, errors.New("manifest.json is missing or invalid")
	}
	if manifest.Format != "wshawk-evidence-bundle" || manifest.Version != 1 {
		return nil, errors.New("unsupported evidence bundle")
	}
	verified := map[string]bool{}
	for name, expected := range manifest.Files {
		sum := sha256.Sum256(files[name])
		verified[name] = strings.EqualFold(expected, hex.EncodeToString(sum[:]))
	}
	valid := true
	for _, ok := range verified {
		if !ok {
			valid = false
		}
	}
	return map[string]any{"valid": valid, "files": verified, "manifest": manifest}, nil
}

func htmlReport(snapshot map[string]any) ([]byte, error) {
	const document = `<!doctype html><html><head><meta charset="utf-8"><title>WSHawk Report</title><style>body{font-family:system-ui;background:#0b1020;color:#e5e7eb;padding:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #334155;padding:.5rem;text-align:left}code{white-space:pre-wrap}</style></head><body><h1>WSHawk Security Report</h1><p>Generated {{.Generated}}</p><h2>Project</h2><pre>{{.Project}}</pre><h2>Findings</h2><table><thead><tr><th>Type</th><th>Value</th><th>Metadata</th></tr></thead><tbody>{{range .Findings}}<tr><td>{{index . "name"}}</td><td><code>{{index . "value"}}</code></td><td><code>{{index . "metadata"}}</code></td></tr>{{end}}</tbody></table></body></html>`
	tmpl, err := template.New("report").Parse(document)
	if err != nil {
		return nil, err
	}
	project, _ := json.MarshalIndent(snapshot["project"], "", "  ")
	var out bytes.Buffer
	err = tmpl.Execute(&out, map[string]any{"Generated": time.Now().UTC().Format(time.RFC3339), "Project": string(project), "Findings": entityMaps(snapshot["findings"])})
	return out.Bytes(), err
}

func csvReport(snapshot map[string]any) ([]byte, error) {
	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	_ = writer.Write([]string{"id", "type", "value", "metadata", "created_at"})
	for _, finding := range entityMaps(snapshot["findings"]) {
		_ = writer.Write([]string{fmt.Sprint(finding["id"]), fmt.Sprint(finding["name"]), fmt.Sprint(finding["value"]), fmt.Sprint(finding["metadata"]), fmt.Sprint(finding["created_at"])})
	}
	writer.Flush()
	return out.Bytes(), writer.Error()
}

func sarifReport(snapshot map[string]any) ([]byte, error) {
	results := []map[string]any{}
	for _, finding := range entityMaps(snapshot["findings"]) {
		metadata, _ := finding["metadata"].(map[string]any)
		level := "warning"
		severity := strings.ToLower(fmt.Sprint(metadata["severity"]))
		if severity == "critical" || severity == "high" {
			level = "error"
		} else if severity == "info" {
			level = "note"
		}
		results = append(results, map[string]any{
			"ruleId": fmt.Sprint(finding["name"]), "level": level,
			"message":   map[string]any{"text": fmt.Sprint(metadata["detail"])},
			"locations": []map[string]any{{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": fmt.Sprint(metadata["url"])}}}},
		})
	}
	document := map[string]any{
		"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "WSHawk Go Desktop", "informationUri": "https://github.com/regaan/wshawk"}},
			"results": results,
		}},
	}
	return json.MarshalIndent(document, "", "  ")
}

func entityMaps(value any) []map[string]any {
	raw, _ := json.Marshal(value)
	var result []map[string]any
	_ = json.Unmarshal(raw, &result)
	return result
}
