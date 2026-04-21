package unobpx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadPXFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "docs", "px", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return string(data)
}

func TestExtractFieldAssignmentsResolvesArithmeticDecoderCalls(t *testing.T) {
	source := loadPXFixture(t, "walmart_4-9-26_init.js")
	assignments := ExtractFieldAssignments(source)

	want := map[string]string{
		"GmEhYFwIKVQ=": `fJ(gP(), eO["userAgent"])`,
		"MklJCHQkQjs=": `fJ(cc, eO["userAgent"])`,
	}

	seen := map[string]bool{}
	for _, assignment := range assignments {
		expected, ok := want[assignment.Key]
		if !ok {
			continue
		}
		if assignment.Resolved == expected {
			seen[assignment.Key] = true
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("missing resolved arithmetic decoder assignment for %s", key)
		}
	}
}

func TestAnalyzeArithmeticDecoderCallsFindsUserAgentResolution(t *testing.T) {
	source := loadPXFixture(t, "walmart_4-9-26_init.js")
	findings := AnalyzeArithmeticDecoderCalls(source)

	var found bool
	for _, finding := range findings {
		if finding.Line != 7321 || finding.ArgExpr != "eL + 344" {
			continue
		}
		if finding.DecodedToken != "userAgent" {
			t.Fatalf("expected decoded token userAgent, got %q", finding.DecodedToken)
		}
		if finding.EvaluatedIndex != 207 {
			t.Fatalf("expected evaluated index 207, got %d", finding.EvaluatedIndex)
		}
		if finding.Confidence != "high" {
			t.Fatalf("expected high confidence, got %q", finding.Confidence)
		}
		if !strings.Contains(finding.ResolvedExpr, `eO["userAgent"]`) {
			t.Fatalf("expected resolved expr to contain navigator userAgent lookup, got %q", finding.ResolvedExpr)
		}
		found = true
	}

	if !found {
		t.Fatal("missing arithmetic decoder finding for eL + 344")
	}
}
