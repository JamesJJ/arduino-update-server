package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeMAC(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantOK  bool
	}{
		{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", true},
		{"aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", true},
		{"AABBCCDDEEFF", "aa-bb-cc-dd-ee-ff", true},
		{"AA:BB:CC:DD:EE:FF:00:11", "", false},                        // too many pairs
		{"AA:BB:CC:DD:EE", "", false},                            // only 5 pairs
		{"GG:HH:II:JJ:KK:LL", "", false},                        // invalid hex
		{"aa:bb:cc:dd:ee:ff::", "aa-bb-cc-dd-ee-ff", true},       // trailing colons ok, still 6 pairs
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := sanitizeMAC(tt.in)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("sanitizeMAC(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestSanitizeVersion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.0.0", "1.0.0"},
		{"abc123", "abc123"},
		{"my_board-v2.1", "my_board-v2.1"},
		{"hello world", "hello-world"},
		{"|D:foo|T:bar|", "-D-foo-T-bar-"},
		{"a" + strings.Repeat("b", 40), "a" + strings.Repeat("b", 31)},
	}
	for _, tt := range tests {
		if got := sanitizeVersion(tt.in); got != tt.want {
			t.Errorf("sanitizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in    string
		parse bool
		want  string
	}{
		// Parsing enabled, valid format
		{"|D:Mar 21 2026|T:18:28:18|", true, "20260321-182818"},
		{"|D:Mar  1 2026|T:08:05:01|", true, "20260301-080501"},
		{"|D:Mar  5 2026|T:09:00:00|", true, "20260305-090000"},
		// With optional suffix
		{"|D:Jan 15 2026|T:12:00:00|my-board", true, "20260115-120000-my-board"},
		{"|D:Jan 15 2026|T:12:00:00|special chars!", true, "20260115-120000-special-chars-"},
		{"|D:Jan 15 2026|T:12:00:00|v2.1_test", true, "20260115-120000-v2.1_test"},
		// Parsing enabled but not matching format — falls back to sanitize
		{"some-random-version", true, "some-random-version"},
		{"1.2.3", true, "1.2.3"},
		{"has spaces", true, "has-spaces"},
		// Parsing disabled — always sanitize
		{"|D:Mar 21 2026|T:18:28:18|", false, "-D-Mar-21-2026-T-18-28-18-"},
	}
	for _, tt := range tests {
		if got := parseVersion(tt.in, tt.parse); got != tt.want {
			t.Errorf("parseVersion(%q, %v) = %q, want %q", tt.in, tt.parse, got, tt.want)
		}
	}
}

func TestStripControl(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello", "hello"},
		{"hello\tworld", "helloworld"},
		{"line\nbreak", "linebreak"},
		{"cr\rhere", "crhere"},
		{"\x00\x1f\x7f", ""},
		{"normal text", "normal text"},
	}
	for _, tt := range tests {
		if got := stripControl(tt.in); got != tt.want {
			t.Errorf("stripControl(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEscHTML(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello", "hello"},
		{"<script>", "&lt;script&gt;"},
		{`a&b"c`, `a&amp;b&quot;c`},
	}
	for _, tt := range tests {
		if got := escHTML(tt.in); got != tt.want {
			t.Errorf("escHTML(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	if got := clientIP(r); got != "192.168.1.1" {
		t.Errorf("clientIP = %q, want 192.168.1.1", got)
	}
	r.RemoteAddr = "badaddr"
	if got := clientIP(r); got != "badaddr" {
		t.Errorf("clientIP = %q, want badaddr", got)
	}
}

func TestWriteAndReadClientLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.tsv")

	writeClientLog(path, "aa-bb-cc", "10.0.0.1", "v1", "v2.bin")
	records := readClientLog(path)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].FailCount != 1 {
		t.Errorf("first call failCount = %d, want 1", records[0].FailCount)
	}

	writeClientLog(path, "aa-bb-cc", "10.0.0.1", "v1", "v2.bin")
	records = readClientLog(path)
	if records[0].FailCount != 2 {
		t.Errorf("second call failCount = %d, want 2", records[0].FailCount)
	}

	writeClientLog(path, "aa-bb-cc", "10.0.0.1", "v1", "v2.bin")
	records = readClientLog(path)
	if records[0].FailCount != 3 {
		t.Errorf("third call failCount = %d, want 3", records[0].FailCount)
	}

	writeClientLog(path, "aa-bb-cc", "10.0.0.1", "v2", "<NONE>")
	records = readClientLog(path)
	if records[0].FailCount != 0 {
		t.Errorf("no-update failCount = %d, want 0", records[0].FailCount)
	}

	writeClientLog(path, "aa-bb-cc", "10.0.0.1", "v2", "v3.bin")
	records = readClientLog(path)
	if records[0].FailCount != 1 {
		t.Errorf("new-version failCount = %d, want 1", records[0].FailCount)
	}

	writeClientLog(path, "dd-ee-ff", "10.0.0.2", "v1", "<NONE>")
	records = readClientLog(path)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestWriteClientLogNoPath(t *testing.T) {
	writeClientLog("", "aa-bb-cc", "10.0.0.1", "v1", "v2.bin")
}

func TestHandleOTA_MissingHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/ota", nil)
	w := httptest.NewRecorder()
	handleOTA(w, r, t.TempDir(), false, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleOTA_InvalidMAC(t *testing.T) {
	r := httptest.NewRequest("GET", "/ota", nil)
	r.Header.Set("x-ESP8266-STA-MAC", "ZZZZZZZZZZZZ")
	r.Header.Set("x-ESP8266-version", "v1")
	w := httptest.NewRecorder()
	handleOTA(w, r, t.TempDir(), true, "")
	if w.Code != http.StatusNotModified {
		t.Errorf("expected 304 for invalid MAC, got %d", w.Code)
	}
}

func TestHandleOTA_NoDirectory(t *testing.T) {
	r := httptest.NewRequest("GET", "/ota", nil)
	r.Header.Set("x-ESP8266-STA-MAC", "AA:BB:CC:DD:EE:FF")
	r.Header.Set("x-ESP8266-version", "v1")
	w := httptest.NewRecorder()
	handleOTA(w, r, t.TempDir(), true, "")
	if w.Code != http.StatusNotModified {
		t.Errorf("expected 304, got %d", w.Code)
	}
}

func TestHandleOTA_ServesUpdate(t *testing.T) {
	root := t.TempDir()
	macDir := filepath.Join(root, "aa-bb-cc-dd-ee-ff")
	os.MkdirAll(macDir, 0755)
	os.WriteFile(filepath.Join(macDir, "20260322-180000.bin"), []byte("firmware"), 0644)

	r := httptest.NewRequest("GET", "/ota", nil)
	r.Header.Set("x-ESP8266-STA-MAC", "AA:BB:CC:DD:EE:FF")
	r.Header.Set("x-ESP8266-version", "|D:Mar 21 2026|T:18:00:00|")
	w := httptest.NewRecorder()
	handleOTA(w, r, root, false, "")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "firmware" {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestHandleOTA_NotEnoughSpace(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "clients.tsv")
	macDir := filepath.Join(root, "aa-bb-cc-dd-ee-ff")
	os.MkdirAll(macDir, 0755)
	os.WriteFile(filepath.Join(macDir, "20260322-180000.bin"), []byte("firmware"), 0644) // 8 bytes

	r := httptest.NewRequest("GET", "/ota", nil)
	r.Header.Set("x-ESP8266-STA-MAC", "AA:BB:CC:DD:EE:FF")
	r.Header.Set("x-ESP8266-version", "|D:Mar 21 2026|T:18:00:00|")
	r.Header.Set("x-ESP8266-free-space", "5") // less than 8
	w := httptest.NewRecorder()
	handleOTA(w, r, root, false, logPath)
	if w.Code != http.StatusNotModified {
		t.Errorf("expected 304, got %d", w.Code)
	}
	// Verify fail count was incremented
	records := readClientLog(logPath)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].FailCount != 1 {
		t.Errorf("failCount = %d, want 1", records[0].FailCount)
	}
}

func TestHandleOTA_NoUpdate(t *testing.T) {
	root := t.TempDir()
	macDir := filepath.Join(root, "aa-bb-cc-dd-ee-ff")
	os.MkdirAll(macDir, 0755)
	os.WriteFile(filepath.Join(macDir, "20260101-000000.bin"), []byte("old"), 0644)

	r := httptest.NewRequest("GET", "/ota", nil)
	r.Header.Set("x-ESP8266-STA-MAC", "AA:BB:CC:DD:EE:FF")
	r.Header.Set("x-ESP8266-version", "|D:Mar 21 2026|T:18:00:00|")
	w := httptest.NewRecorder()
	handleOTA(w, r, root, false, "")
	if w.Code != http.StatusNotModified {
		t.Errorf("expected 304, got %d", w.Code)
	}
}

func TestHandleClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.tsv")
	writeClientLog(path, "aa-bb-cc", "10.0.0.1", "v1", "v2.bin")
	writeClientLog(path, "dd-ee-ff", "10.0.0.2", "v1", "<NONE>")

	w := httptest.NewRecorder()
	handleClients(w, path)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "aa-bb-cc") || !strings.Contains(body, "dd-ee-ff") {
		t.Error("expected both MACs in HTML output")
	}
}

func TestHandleClients_NoLog(t *testing.T) {
	w := httptest.NewRecorder()
	handleClients(w, "")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHandleMetrics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.tsv")

	writeClientLog(path, "aa-bb-cc", "10.0.0.1", "v2", "<NONE>")
	writeClientLog(path, "dd-ee-ff", "10.0.0.2", "v1", "v2.bin")
	writeClientLog(path, "11-22-33", "10.0.0.3", "v1", "v2.bin")
	writeClientLog(path, "11-22-33", "10.0.0.3", "v1", "v2.bin")
	writeClientLog(path, "11-22-33", "10.0.0.3", "v1", "v2.bin")

	w := httptest.NewRecorder()
	handleMetrics(w, path)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var m map[string]int
	json.NewDecoder(w.Body).Decode(&m)
	if m["total_clients"] != 3 {
		t.Errorf("total_clients = %d, want 3", m["total_clients"])
	}
	if m["up_to_date"] != 1 {
		t.Errorf("up_to_date = %d, want 1", m["up_to_date"])
	}
	if m["offered_update"] != 2 {
		t.Errorf("offered_update = %d, want 2", m["offered_update"])
	}
	if m["apparently_failing"] != 1 {
		t.Errorf("apparently_failing = %d, want 1", m["apparently_failing"])
	}
}

func TestHandleMetrics_NoLog(t *testing.T) {
	w := httptest.NewRecorder()
	handleMetrics(w, "")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHandleMetrics_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.tsv")
	w := httptest.NewRecorder()
	handleMetrics(w, path)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var m map[string]int
	json.NewDecoder(w.Body).Decode(&m)
	for _, key := range []string{"total_clients", "offered_update", "up_to_date", "apparently_failing"} {
		if m[key] != 0 {
			t.Errorf("%s = %d, want 0", key, m[key])
		}
	}
}
