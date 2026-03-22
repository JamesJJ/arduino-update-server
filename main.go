package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	port := flag.Int("port", 8080, "HTTP port to listen on")
	root := flag.String("root", "", "Root directory for firmware files (required)")
	noParseVersion := flag.Bool("no-parse-version", false, "Disable parsing version from __DATE__ __TIME__ format")
	clientLog := flag.String("client-log", "", "Path to client log file")
	flag.Parse()

	if *root == "" {
		fmt.Fprintln(os.Stderr, "Error: --root is required")
		flag.Usage()
		os.Exit(1)
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/ota", func(w http.ResponseWriter, r *http.Request) {
		handleOTA(w, r, *root, *noParseVersion, *clientLog)
	})
	http.HandleFunc("/clients", func(w http.ResponseWriter, r *http.Request) {
		handleClients(w, *clientLog)
	})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		handleMetrics(w, *clientLog)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Listening on %s, root=%s, no-parse-version=%v", addr, *root, *noParseVersion)
	log.Fatal(http.ListenAndServe(addr, nil))
}

var validMACRe = regexp.MustCompile(`^[0-9a-f:]+$`)
var macHexRe = regexp.MustCompile(`[0-9a-f]{2}`)

// sanitizeMAC validates and normalises a MAC to "aa-bb-cc-dd-ee-ff" format.
// Returns the sanitised MAC and true, or empty string and false if invalid.
func sanitizeMAC(raw string) (string, bool) {
	s := strings.ToLower(raw)
	if !validMACRe.MatchString(s) {
		return "", false
	}
	pairs := macHexRe.FindAllString(s, -1)
	if len(pairs) != 6 {
		return "", false
	}
	return strings.Join(pairs, "-"), true
}

var versionSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func sanitizeVersion(raw string) string {
	s := versionSanitizeRe.ReplaceAllString(raw, "-")
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

func parseVersion(raw string, parse bool) string {
	if parse && strings.HasPrefix(raw, "|D:") {
		parts := strings.SplitN(raw[1:], "|", 3)
		if len(parts) >= 2 && strings.HasPrefix(parts[0], "D:") && strings.HasPrefix(parts[1], "T:") {
			dt := parts[0][2:] + " " + parts[1][2:]
			t, err := time.Parse("Jan  2 2006 15:04:05", dt)
			if err != nil {
				t, err = time.Parse("Jan 2 2006 15:04:05", dt)
			}
			if err == nil {
				result := t.Format("20060102-150405")
				if len(parts) == 3 && parts[2] != "" {
					s := versionSanitizeRe.ReplaceAllString(parts[2], "-")
					result += "-" + s
				}
				return result
			}
		}
	}
	return sanitizeVersion(raw)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func handleOTA(w http.ResponseWriter, r *http.Request, root string, noParseVersion bool, clientLog string) {
	ip := clientIP(r)

	for name, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-esp8266-") {
			log.Printf("[%s] Header %s: %s", ip, name, strings.Join(values, ", "))
		}
	}

	mac := r.Header.Get("x-ESP8266-STA-MAC")
	version := r.Header.Get("x-ESP8266-version")

	if mac == "" || version == "" {
		log.Printf("[%s] Missing required headers", ip)
		http.Error(w, "Missing required headers", http.StatusBadRequest)
		return
	}

	sanitizedMAC, macOK := sanitizeMAC(mac)
	if !macOK {
		log.Printf("[%s] Invalid MAC address: %s", ip, mac)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	sanitizedVersion := parseVersion(version, !noParseVersion)

	dir := filepath.Join(root, sanitizedMAC)
	log.Printf("[%s] Search dir=%s, current version=%s", ip, dir, sanitizedVersion)

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("[%s] Cannot read directory %s: %v", ip, dir, err)
		writeClientLog(clientLog, sanitizedMAC, ip, version, "<NONE>")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	var candidates []string
	var numOlder int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".bin")
		if name > sanitizedVersion {
			candidates = append(candidates, e.Name())
		} else {
			numOlder++
		}
	}

	if len(candidates) == 0 {
		log.Printf("[%s] No update available (0 candidates)", ip)
		writeClientLog(clientLog, sanitizedMAC, ip, version, "<NONE>")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	sort.Strings(candidates)
	selected := candidates[0]
	log.Printf("[%s] Selected update=%s, skipped=%d newer/%d older", ip, selected, len(candidates)-1, numOlder)
	writeClientLog(clientLog, sanitizedMAC, ip, version, selected)

	filePath := filepath.Join(dir, selected)
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("[%s] Cannot open %s: %v", ip, filePath, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Printf("[%s] Cannot stat %s: %v", ip, filePath, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	http.ServeContent(w, r, selected, info.ModTime(), f)
}

// TSV columns: mac, callTime, ip, version, offered, failCount

var controlRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func stripControl(s string) string {
	return controlRe.ReplaceAllString(s, "")
}

var clientLogMu sync.Mutex

func writeClientLog(path, mac, ip, version, offered string) {
	if path == "" {
		return
	}

	clientLogMu.Lock()
	defer clientLogMu.Unlock()

	lines := map[string]string{}
	var order []string

	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if key, _, ok := strings.Cut(line, "\t"); ok && key != "" {
				if _, exists := lines[key]; !exists {
					order = append(order, key)
				}
				lines[key] = line
			}
		}
		f.Close()
	}

	failCount := 0
	if offered != "<NONE>" {
		if prev, exists := lines[mac]; exists {
			fields := strings.Split(prev, "\t")
			// If previous version and offered match current, increment counter
			if len(fields) >= 6 && stripControl(version) == fields[3] && offered == fields[4] {
				failCount, _ = strconv.Atoi(fields[5])
			}
			failCount++
		} else {
			failCount = 1
		}
	}

	now := time.Now().UTC().Format("20060102-150405")
	newLine := strings.Join([]string{
		mac, now, ip, stripControl(version), offered, strconv.Itoa(failCount),
	}, "\t")

	if _, exists := lines[mac]; !exists {
		order = append(order, mac)
	}
	lines[mac] = newLine

	var buf strings.Builder
	for _, key := range order {
		buf.WriteString(lines[key])
		buf.WriteByte('\n')
	}

	if err := os.WriteFile(path, []byte(buf.String()), 0644); err != nil {
		log.Printf("Failed to write client log: %v", err)
	}
}

type clientRecord struct {
	MAC       string
	CallTime  string
	IP        string
	Version   string
	Offered   string
	FailCount int
}

func readClientLog(path string) []clientRecord {
	if path == "" {
		return nil
	}
	clientLogMu.Lock()
	defer clientLogMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return []clientRecord{}
	}
	defer f.Close()

	var records []clientRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 5 {
			continue
		}
		fc := 0
		if len(fields) >= 6 {
			fc, _ = strconv.Atoi(fields[5])
		}
		records = append(records, clientRecord{
			MAC: fields[0], CallTime: fields[1], IP: fields[2],
			Version: fields[3], Offered: fields[4], FailCount: fc,
		})
	}
	return records
}

func handleClients(w http.ResponseWriter, clientLog string) {
	records := readClientLog(clientLog)
	if records == nil {
		http.Error(w, "Client log not configured", http.StatusServiceUnavailable)
		return
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].CallTime > records[j].CallTime
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Clients</title>
<style>table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:4px 8px;text-align:left}th{background:#f0f0f0}</style>
</head><body><table><tr><th>MAC</th><th>Last Seen</th><th>IP</th><th>Version</th><th>Offered</th><th>Fail Count</th></tr>`)
	for _, r := range records {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>",
			escHTML(r.MAC), escHTML(r.CallTime), escHTML(r.IP),
			escHTML(r.Version), escHTML(r.Offered), r.FailCount)
	}
	fmt.Fprint(w, "</table></body></html>")
}

func escHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func handleMetrics(w http.ResponseWriter, clientLog string) {
	records := readClientLog(clientLog)
	if records == nil {
		http.Error(w, "Client log not configured", http.StatusServiceUnavailable)
		return
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -30).Format("20060102-150405")

	total, offered, upToDate, failing := 0, 0, 0, 0
	for _, r := range records {
		if r.CallTime < cutoff {
			continue
		}
		total++
		if r.Offered == "<NONE>" {
			upToDate++
		} else {
			offered++
			if r.FailCount >= 3 {
				failing++
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"total_clients":          total,
		"offered_update":         offered,
		"up_to_date":             upToDate,
		"apparently_failing":     failing,
	})
}
