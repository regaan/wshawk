package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
)

const (
	AuthzPolicyCompareOnly                       = "compare_only"
	AuthzPolicyPrimaryDeniedOwnerAllow           = "primary_denied_owner_allowed"
	AuthzPolicyAnonymousDeniedAuthenticatedAllow = "anonymous_denied_authenticated_allowed"
	AuthzPolicyLowerPrivilegeDeniedPrivileged    = "lower_privilege_denied_privileged_allowed"
	AuthzPolicyTenantIsolation                   = "tenant_isolation"
	AuthzPolicyFunctionLevel                     = "function_level_authorization"
	AuthzPolicyAdminOnly                         = "admin_only_operation"
	AuthzPolicyOwnershipTransfer                 = "ownership_transfer"
)

type AuthzPolicy struct {
	Mode                 string   `json:"mode"`
	MinimumConfirmations int      `json:"minimum_confirmations,omitempty"`
	DenialMarkers        []string `json:"denial_markers,omitempty"`
	SuccessMarkers       []string `json:"success_markers,omitempty"`
}

type AuthzCase struct {
	ID             string          `json:"id"`
	IdentityID     string          `json:"identity_id,omitempty"`
	Alias          string          `json:"alias"`
	Role           string          `json:"role,omitempty"`
	Expectation    string          `json:"expectation"`
	ObjectValue    string          `json:"object_value,omitempty"`
	Request        websec.Request  `json:"request"`
	BeforeRequest  *websec.Request `json:"before_request,omitempty"`
	AfterRequest   *websec.Request `json:"after_request,omitempty"`
	CleanupRequest *websec.Request `json:"cleanup_request,omitempty"`
}

type AuthzMatrixOptions struct {
	Cases              []AuthzCase `json:"cases"`
	Policy             AuthzPolicy `json:"policy"`
	SafeWriteConfirmed bool        `json:"safe_write_confirmed"`
	WriteMode          string      `json:"write_mode,omitempty"`
	MaxRequests        int         `json:"max_requests"`
}

type AuthzSemantic struct {
	State          string   `json:"state"`
	Reason         string   `json:"reason"`
	SemanticSHA256 string   `json:"semantic_sha256,omitempty"`
	SensitiveKeys  []string `json:"sensitive_keys,omitempty"`
	GraphQLErrors  bool     `json:"graphql_errors"`
	PartialData    bool     `json:"partial_data"`
}

func (e *Engine) AuthzDiff(ctx context.Context, left, right websec.Request) (map[string]any, error) {
	return e.AuthzDiffWithPolicy(ctx, left, right, AuthzPolicy{Mode: AuthzPolicyCompareOnly})
}

func (e *Engine) AuthzDiffWithPolicy(ctx context.Context, left, right websec.Request, policy AuthzPolicy) (map[string]any, error) {
	leftResponse, err := e.client.Do(ctx, left)
	if err != nil {
		return nil, err
	}
	rightResponse, err := e.client.Do(ctx, right)
	if err != nil {
		return nil, err
	}
	similarity := bodySimilarity(leftResponse.Body, leftResponse.SHA256, rightResponse.Body, rightResponse.SHA256)
	risk := "none"
	if (leftResponse.Status >= 400 && rightResponse.Status < 400) || (rightResponse.Status >= 400 && leftResponse.Status < 400) {
		risk = "high"
	} else if leftResponse.Status != rightResponse.Status || similarity < 0.8 {
		risk = "medium"
	}
	return map[string]any{
		"left":                     leftResponse,
		"right":                    rightResponse,
		"body_similarity":          similarity,
		"authorization_difference": risk,
		"policy_evaluation":        evaluateAuthzPolicy(policy, leftResponse, rightResponse),
	}, nil
}

func (e *Engine) AuthzMatrix(ctx context.Context, options AuthzMatrixOptions) (map[string]any, error) {
	if len(options.Cases) < 2 {
		return nil, errors.New("at least two authorization cases are required")
	}
	maxRequests := options.MaxRequests
	if maxRequests <= 0 {
		maxRequests = 40
	}
	if maxRequests > 80 {
		maxRequests = 80
	}
	writeMode := strings.ToLower(strings.TrimSpace(options.WriteMode))
	if writeMode == "" && options.SafeWriteConfirmed {
		writeMode = "execute"
	}
	if writeMode == "" {
		writeMode = "dry_run"
	}
	if writeMode != "dry_run" && writeMode != "execute" && writeMode != "execute_with_rollback" {
		return nil, errors.New("write_mode must be dry_run, execute, or execute_with_rollback")
	}
	plannedRequests := 0
	for _, testCase := range options.Cases {
		plannedRequests++
		method := strings.ToUpper(strings.TrimSpace(testCase.Request.Method))
		if method == "" {
			method = http.MethodGet
		}
		if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions && writeMode != "dry_run" {
			if testCase.BeforeRequest != nil {
				plannedRequests += 2
			}
			if testCase.AfterRequest != nil {
				plannedRequests++
			}
			if testCase.CleanupRequest != nil {
				plannedRequests++
			}
		}
	}
	if plannedRequests > maxRequests {
		return nil, fmt.Errorf("authorization matrix exceeds the %d request limit", maxRequests)
	}
	for _, testCase := range options.Cases {
		method := strings.ToUpper(strings.TrimSpace(testCase.Request.Method))
		if method == "" {
			method = http.MethodGet
		}
		if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
			if writeMode == "dry_run" {
				continue
			}
			if !options.SafeWriteConfirmed {
				return nil, errors.New("safe_write_confirmed must be true for POST, PUT, PATCH, or DELETE authorization testing")
			}
			if writeMode == "execute_with_rollback" && (testCase.BeforeRequest == nil || testCase.AfterRequest == nil || testCase.CleanupRequest == nil) {
				return nil, errors.New("execute_with_rollback requires before_request, after_request, and cleanup_request for every write case")
			}
		}
	}

	results := make([]map[string]any, 0, len(options.Cases))
	for index, testCase := range options.Cases {
		method := strings.ToUpper(strings.TrimSpace(testCase.Request.Method))
		if method == "" {
			method = http.MethodGet
		}
		isWrite := method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
		if isWrite && writeMode == "dry_run" {
			results = append(results, map[string]any{
				"index": index, "case_id": testCase.ID, "identity_id": testCase.IdentityID,
				"identity_alias": testCase.Alias, "role": testCase.Role,
				"expectation": normalizeExpectation(testCase.Expectation), "object_value": testCase.ObjectValue,
				"request":         map[string]any{"method": testCase.Request.Method, "url": testCase.Request.URL},
				"semantic":        AuthzSemantic{State: "planned", Reason: "dry-run mode did not transmit the state-changing request"},
				"expectation_met": false, "policy_violation": false, "invalid_identity": false,
				"write_evidence": map[string]any{"mode": "dry_run", "transmitted": false, "rollback_required": false},
			})
			continue
		}
		writeEvidence := map[string]any{"mode": writeMode, "transmitted": isWrite}
		if isWrite && testCase.BeforeRequest != nil {
			before, err := e.client.Do(ctx, *testCase.BeforeRequest)
			if err != nil {
				return nil, fmt.Errorf("authorization case %q before evidence: %w", testCase.Alias, err)
			}
			writeEvidence["before"] = before
		}
		response, err := e.client.Do(ctx, testCase.Request)
		if err != nil {
			return nil, fmt.Errorf("authorization case %q: %w", testCase.Alias, err)
		}
		if isWrite && testCase.AfterRequest != nil {
			after, afterErr := e.client.Do(ctx, *testCase.AfterRequest)
			if afterErr != nil {
				return nil, fmt.Errorf("authorization case %q after evidence: %w", testCase.Alias, afterErr)
			}
			writeEvidence["after"] = after
		}
		if isWrite && testCase.CleanupRequest != nil && response.Status >= 200 && response.Status < 300 {
			cleanupRequest := applyResponseVariables(*testCase.CleanupRequest, response)
			cleanup, cleanupErr := e.client.Do(ctx, cleanupRequest)
			if cleanupErr != nil {
				return nil, fmt.Errorf("authorization case %q cleanup: %w", testCase.Alias, cleanupErr)
			}
			writeEvidence["cleanup"] = cleanup
			writeEvidence["cleanup_succeeded"] = cleanup.Status >= 200 && cleanup.Status < 300
			if succeeded, _ := writeEvidence["cleanup_succeeded"].(bool); !succeeded {
				return nil, fmt.Errorf("authorization case %q cleanup returned HTTP %d", testCase.Alias, cleanup.Status)
			}
			if testCase.BeforeRequest != nil {
				restored, restoreErr := e.client.Do(ctx, *testCase.BeforeRequest)
				if restoreErr != nil {
					return nil, fmt.Errorf("authorization case %q rollback verification: %w", testCase.Alias, restoreErr)
				}
				writeEvidence["restored"] = restored
				before, _ := writeEvidence["before"].(websec.Response)
				writeEvidence["rollback_verified"] = before.Status == restored.Status && semanticResponseHash(before) == semanticResponseHash(restored)
			}
		} else if isWrite && testCase.CleanupRequest != nil {
			writeEvidence["cleanup_succeeded"] = true
			writeEvidence["cleanup_skipped"] = "primary write request was denied or unsuccessful"
		}
		semantic := analyzeAuthzResponse(response, options.Policy)
		expectation := normalizeExpectation(testCase.Expectation)
		met, violation, invalidIdentity := authzExpectationResult(options.Policy, testCase, semantic)
		results = append(results, map[string]any{
			"index": index, "case_id": testCase.ID, "identity_id": testCase.IdentityID,
			"identity_alias": testCase.Alias, "role": testCase.Role,
			"expectation": expectation, "object_value": testCase.ObjectValue,
			"request":  map[string]any{"method": testCase.Request.Method, "url": testCase.Request.URL},
			"response": response, "semantic": semantic, "expectation_met": met,
			"policy_violation": violation, "invalid_identity": invalidIdentity, "write_evidence": writeEvidence,
		})
	}

	evaluation := evaluateAuthzMatrix(options.Policy, results)
	if writeMode == "dry_run" && hasStateChangingCase(options.Cases) {
		evaluation = authzResult(evaluation, "dry_run_planned", "info", "none", false, "Dry-run completed without transmitting state-changing requests. Confirm the bounded request plan before execution.")
	}
	return map[string]any{
		"policy": options.Policy, "results": results, "evaluation": evaluation,
		"summary": mergeAuthzSummary(matrixSummary(results, evaluation), map[string]any{"write_mode": writeMode, "planned_request_count": plannedRequests}),
	}, nil
}

func hasStateChangingCase(cases []AuthzCase) bool {
	for _, testCase := range cases {
		method := strings.ToUpper(strings.TrimSpace(testCase.Request.Method))
		if method != "" && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
			return true
		}
	}
	return false
}

func mergeAuthzSummary(left, right map[string]any) map[string]any {
	for key, value := range right {
		left[key] = value
	}
	return left
}

func applyResponseVariables(request websec.Request, response websec.Response) websec.Request {
	values := map[string]string{}
	var document map[string]any
	if json.Unmarshal([]byte(response.Body), &document) == nil {
		var collect func(map[string]any)
		collect = func(object map[string]any) {
			for key, value := range object {
				switch typed := value.(type) {
				case string:
					values[key] = typed
				case float64:
					values[key] = fmt.Sprint(typed)
				case map[string]any:
					collect(typed)
				}
			}
		}
		collect(document)
	}
	replace := func(input string) string {
		for key, value := range values {
			input = strings.ReplaceAll(input, "{{"+key+"}}", value)
		}
		return input
	}
	request.URL, request.Body, request.BodyBase64 = replace(request.URL), replace(request.Body), replace(request.BodyBase64)
	for key, value := range request.Headers {
		request.Headers[key] = replace(value)
	}
	return request
}

func semanticResponseHash(response websec.Response) string {
	var value any
	if json.Unmarshal([]byte(response.Body), &value) == nil {
		return semanticHash(value)
	}
	sum := sha256.Sum256([]byte(normalizeVolatileText(response.Body)))
	return hex.EncodeToString(sum[:])
}

func evaluateAuthzPolicy(policy AuthzPolicy, left, right websec.Response) map[string]any {
	mode := normalizePolicyMode(policy.Mode)
	leftSemantic := analyzeAuthzResponse(left, policy)
	rightSemantic := analyzeAuthzResponse(right, policy)
	profile := authzPolicyProfile(mode)
	result := map[string]any{
		"mode": mode, "verdict": "comparison_only", "severity": "info", "finding": false,
		"confidence": "none", "finding_type": profile.findingType,
		"detail":   "Responses were compared without an expected authorization policy.",
		"expected": map[string]any{"primary": "unspecified", "comparison": "unspecified"},
		"observed": map[string]any{"primary_status": left.Status, "comparison_status": right.Status, "primary_state": leftSemantic.State, "comparison_state": rightSemantic.State},
		"semantic": map[string]any{"primary": leftSemantic, "comparison": rightSemantic},
	}
	if mode == AuthzPolicyCompareOnly {
		return result
	}

	result["expected"] = map[string]any{"primary": "deny", "comparison": "allow"}
	if rightSemantic.State == "unauthenticated" {
		return authzResult(result, "invalid_identity", "warning", "high", false, "The owner/control identity returned 401; refresh or re-record its authentication.")
	}
	if rightSemantic.State != "allowed" {
		return authzResult(result, "invalid_control", "warning", "high", false, "The owner/control request was not semantically allowed, so the policy cannot be evaluated.")
	}
	if leftSemantic.State == "unauthenticated" && mode != AuthzPolicyAnonymousDeniedAuthenticatedAllow {
		return authzResult(result, "invalid_identity", "warning", "high", false, "The primary stored identity returned 401; refresh or re-record its authentication.")
	}
	if leftSemantic.State == "denied" || (leftSemantic.State == "unauthenticated" && mode == AuthzPolicyAnonymousDeniedAuthenticatedAllow) {
		return authzResult(result, "access_control_enforced", "info", "high", false, "The primary identity was denied while the owner/control identity was allowed.")
	}
	if leftSemantic.State == "allowed" {
		confidence := semanticConfidence(leftSemantic, rightSemantic, left, right)
		return authzResult(result, profile.verdict, profile.severity, confidence, true, profile.detail)
	}
	return authzResult(result, "inconclusive", "warning", "low", false, "The primary response was neither a semantic authorization denial nor a successful resource response.")
}

type authzProfile struct {
	verdict, findingType, severity, detail string
}

func authzPolicyProfile(mode string) authzProfile {
	switch mode {
	case AuthzPolicyAnonymousDeniedAuthenticatedAllow:
		return authzProfile{"missing_authentication", "missing-authentication", "high", "An anonymous request received protected data that was expected to require authentication."}
	case AuthzPolicyLowerPrivilegeDeniedPrivileged:
		return authzProfile{"potential_privilege_escalation", "vertical-privilege-escalation", "high", "A lower-privileged identity accessed functionality reserved for the privileged control identity."}
	case AuthzPolicyTenantIsolation:
		return authzProfile{"potential_tenant_isolation_bypass", "tenant-isolation", "critical", "An identity accessed an object assigned to another tenant."}
	case AuthzPolicyFunctionLevel:
		return authzProfile{"potential_bfla", "broken-function-level-authorization", "high", "A lower-privileged identity invoked a function reserved for the privileged control identity."}
	case AuthzPolicyAdminOnly:
		return authzProfile{"potential_admin_operation_bypass", "admin-only-authorization", "critical", "A non-administrator invoked an operation explicitly reserved for administrators."}
	case AuthzPolicyOwnershipTransfer:
		return authzProfile{"potential_ownership_transfer_bypass", "ownership-transfer", "critical", "An identity transferred ownership of an object without the required owner or administrator authorization."}
	default:
		return authzProfile{"potential_idor", "idor-bola", "high", "The primary identity accessed an owner-controlled object despite an expected denial."}
	}
}

func authzResult(result map[string]any, verdict, severity, confidence string, finding bool, detail string) map[string]any {
	result["verdict"] = verdict
	result["severity"] = severity
	result["confidence"] = confidence
	result["finding"] = finding
	result["detail"] = detail
	return result
}

func analyzeAuthzResponse(response websec.Response, policy AuthzPolicy) AuthzSemantic {
	semantic := AuthzSemantic{State: "inconclusive", Reason: "response did not match an allow or deny signal"}
	if response.Status == http.StatusUnauthorized {
		semantic.State, semantic.Reason = "unauthenticated", "HTTP 401 indicates missing or expired authentication"
		return semantic
	}
	if response.Status == http.StatusForbidden || response.Status == http.StatusNotFound {
		semantic.State, semantic.Reason = "denied", fmt.Sprintf("HTTP %d is treated as an authorization denial", response.Status)
		return semantic
	}
	if response.Status >= 300 && response.Status < 400 {
		semantic.State, semantic.Reason = "denied", "redirect response is treated as an authentication or authorization boundary"
		return semantic
	}
	if response.Status < 200 || response.Status >= 300 {
		semantic.Reason = fmt.Sprintf("HTTP %d is not a clear successful or denied response", response.Status)
		return semantic
	}

	body := response.Body
	var document any
	if json.Unmarshal([]byte(body), &document) == nil {
		semantic.SensitiveKeys = collectSensitiveKeys(document, "")
		if object, ok := document.(map[string]any); ok {
			_, hasErrors := object["errors"]
			data, hasData := object["data"]
			if hasErrors {
				semantic.GraphQLErrors = true
				semantic.PartialData = hasData && data != nil
				if !semantic.PartialData {
					semantic.State, semantic.Reason = "denied", "GraphQL returned errors without usable data"
					semantic.SemanticSHA256 = semanticHash(document)
					return semantic
				}
			}
		}
		semantic.SemanticSHA256 = semanticHash(document)
	} else {
		sum := sha256.Sum256([]byte(normalizeVolatileText(body)))
		semantic.SemanticSHA256 = hex.EncodeToString(sum[:])
	}

	lowerBody := strings.ToLower(body)
	denialMarkers := append([]string{"access denied", "permission denied", "not authorized", "not authorised", "forbidden", "authentication required", `"authenticated":false`}, policy.DenialMarkers...)
	for _, marker := range denialMarkers {
		if marker = strings.TrimSpace(strings.ToLower(marker)); marker != "" && strings.Contains(lowerBody, marker) {
			semantic.State, semantic.Reason = "denied", "successful HTTP status contained an application-level denial marker"
			return semantic
		}
	}
	if len(policy.SuccessMarkers) > 0 {
		for _, marker := range policy.SuccessMarkers {
			if marker = strings.TrimSpace(strings.ToLower(marker)); marker != "" && strings.Contains(lowerBody, marker) {
				semantic.State, semantic.Reason = "allowed", "configured success marker was present"
				return semantic
			}
		}
		semantic.Reason = "none of the configured success markers were present"
		return semantic
	}
	semantic.State, semantic.Reason = "allowed", "2xx response contained no semantic denial signal"
	return semantic
}

func authzExpectationResult(policy AuthzPolicy, testCase AuthzCase, semantic AuthzSemantic) (bool, bool, bool) {
	expectation := normalizeExpectation(testCase.Expectation)
	if expectation == "observe" {
		return true, false, false
	}
	if expectation == "allow" {
		return semantic.State == "allowed", false, semantic.State == "unauthenticated"
	}
	if semantic.State == "allowed" {
		return false, true, false
	}
	if semantic.State == "unauthenticated" {
		anonymous := strings.EqualFold(testCase.Role, "anonymous") || normalizePolicyMode(policy.Mode) == AuthzPolicyAnonymousDeniedAuthenticatedAllow
		return anonymous, false, !anonymous
	}
	return semantic.State == "denied", false, false
}

func evaluateAuthzMatrix(policy AuthzPolicy, results []map[string]any) map[string]any {
	mode := normalizePolicyMode(policy.Mode)
	profile := authzPolicyProfile(mode)
	required := policy.MinimumConfirmations
	if required <= 0 {
		required = 1
	}
	if required > 10 {
		required = 10
	}
	allowByObject := map[string]bool{}
	violationByObject := map[string]bool{}
	invalidControls := 0
	invalidIdentities := 0
	for _, item := range results {
		objectValue := fmt.Sprint(item["object_value"])
		if objectValue == "" {
			objectValue = "__single__"
		}
		expectation := fmt.Sprint(item["expectation"])
		semantic, _ := item["semantic"].(AuthzSemantic)
		if expectation == "allow" {
			if semantic.State == "allowed" {
				allowByObject[objectValue] = true
			} else {
				invalidControls++
			}
		}
		if violation, _ := item["policy_violation"].(bool); violation {
			violationByObject[objectValue] = true
		}
		if invalid, _ := item["invalid_identity"].(bool); invalid {
			invalidIdentities++
		}
	}
	confirmedObjects := make([]string, 0)
	for objectValue := range violationByObject {
		if allowByObject[objectValue] {
			confirmedObjects = append(confirmedObjects, objectValue)
		}
	}
	sort.Strings(confirmedObjects)
	evaluation := map[string]any{
		"mode": mode, "verdict": "access_control_enforced", "finding": false,
		"finding_type": profile.findingType, "severity": "info", "confidence": "high",
		"required_confirmations": required, "confirmed_objects": confirmedObjects,
		"confirmation_count": len(confirmedObjects), "invalid_control_count": invalidControls,
		"invalid_identity_count": invalidIdentities,
		"detail":                 "Expected authorization boundaries were enforced across the tested matrix.",
	}
	if invalidControls > 0 {
		return authzResult(evaluation, "invalid_control", "warning", "high", false, "One or more expected owner/privileged control requests were not allowed.")
	}
	if invalidIdentities > 0 {
		return authzResult(evaluation, "invalid_identity", "warning", "high", false, "One or more stored identities returned 401 and must be refreshed before classification.")
	}
	if len(confirmedObjects) >= required {
		return authzResult(evaluation, profile.verdict, profile.severity, "high", true, profile.detail)
	}
	if len(confirmedObjects) > 0 {
		return authzResult(evaluation, "insufficient_confirmation", "warning", "medium", false, fmt.Sprintf("Observed %d policy violation(s), below the required confirmation threshold of %d.", len(confirmedObjects), required))
	}
	return evaluation
}

func matrixSummary(results []map[string]any, evaluation map[string]any) map[string]any {
	statuses := map[string]int{}
	states := map[string]int{}
	violations := 0
	for _, item := range results {
		if response, ok := item["response"].(websec.Response); ok {
			statuses[fmt.Sprint(response.Status)]++
		}
		if semantic, ok := item["semantic"].(AuthzSemantic); ok {
			states[semantic.State]++
		}
		if violation, _ := item["policy_violation"].(bool); violation {
			violations++
		}
	}
	return map[string]any{
		"request_count": len(results), "policy_violation_count": violations,
		"http_status_breakdown": statuses, "semantic_state_breakdown": states,
		"verdict": evaluation["verdict"], "finding": evaluation["finding"],
	}
}

func normalizePolicyMode(mode string) string {
	mode = strings.TrimSpace(strings.ToLower(mode))
	switch mode {
	case AuthzPolicyPrimaryDeniedOwnerAllow, AuthzPolicyAnonymousDeniedAuthenticatedAllow,
		AuthzPolicyLowerPrivilegeDeniedPrivileged, AuthzPolicyTenantIsolation, AuthzPolicyFunctionLevel,
		AuthzPolicyAdminOnly, AuthzPolicyOwnershipTransfer:
		return mode
	default:
		return AuthzPolicyCompareOnly
	}
}

func normalizeExpectation(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "allow":
		return "allow"
	case "deny":
		return "deny"
	default:
		return "observe"
	}
}

func semanticConfidence(left, right AuthzSemantic, leftResponse, rightResponse websec.Response) string {
	if leftResponse.SHA256 != "" && leftResponse.SHA256 == rightResponse.SHA256 {
		return "high"
	}
	if left.SemanticSHA256 != "" && left.SemanticSHA256 == right.SemanticSHA256 {
		return "high"
	}
	for _, leftKey := range left.SensitiveKeys {
		for _, rightKey := range right.SensitiveKeys {
			if leftKey == rightKey {
				return "high"
			}
		}
	}
	return "medium"
}

func collectSensitiveKeys(value any, prefix string) []string {
	keys := map[string]bool{}
	var visit func(any, string)
	visit = func(current any, path string) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				next := key
				if path != "" {
					next = path + "." + key
				}
				lower := strings.ToLower(key)
				if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "email") || strings.Contains(lower, "balance") || strings.Contains(lower, "note") || strings.Contains(lower, "owner") || strings.Contains(lower, "tenant") {
					keys[next] = true
				}
				visit(child, next)
			}
		case []any:
			for _, child := range typed {
				visit(child, path)
			}
		}
	}
	visit(value, prefix)
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func semanticHash(value any) string {
	normalized := normalizeJSONValue(value)
	encoded, _ := json.Marshal(normalized)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func normalizeJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, child := range typed {
			lower := strings.ToLower(key)
			if lower == "timestamp" || lower == "date" || lower == "request_id" || lower == "trace_id" || lower == "nonce" || lower == "expires_at" || lower == "session_id" {
				continue
			}
			result[key] = normalizeJSONValue(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = normalizeJSONValue(child)
		}
		return result
	default:
		return value
	}
}

func normalizeVolatileText(value string) string {
	fields := []string{"timestamp", "date", "request_id", "trace_id", "nonce", "expires_at", "session_id"}
	result := value
	for _, field := range fields {
		result = strings.ReplaceAll(result, field, "volatile_field")
	}
	return result
}
