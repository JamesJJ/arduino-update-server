package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	port := flag.Int("port", 8080, "HTTP port to listen on")
	root := flag.String("root", "", "Root directory for firmware files (required)")
	noParseVersion := flag.Bool("no-parse-version", false, "Disable parsing version from __DATE__ __TIME__ format")
	clientLogPath := flag.String("client-log", "", "Path to client log file")
	flushCadence := flag.Int("flush-log-cadence", 60, "Seconds between client log flushes to disk")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *root == "" {
		fmt.Fprintln(os.Stderr, "Error: --root is required")
		flag.Usage()
		os.Exit(1)
	}

	var clog *clientLog
	if *clientLogPath != "" {
		clog = newClientLog(*clientLogPath)
		go clog.flushLoop(time.Duration(*flushCadence) * time.Second)
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/ota", func(w http.ResponseWriter, r *http.Request) {
		handleOTA(w, r, *root, *noParseVersion, clog)
	})
	http.HandleFunc("/clients", func(w http.ResponseWriter, r *http.Request) {
		handleClients(w, clog)
	})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		handleMetrics(w, clog)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("version=%s, listening on %s, root=%s, no-parse-version=%v", version, addr, *root, *noParseVersion)

	srv := &http.Server{Addr: addr}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		if clog != nil {
			clog.flush()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

var validMACRe = regexp.MustCompile(`^[0-9a-f:]+$`)
var macHexRe = regexp.MustCompile(`[0-9a-f]{2}`)

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

// espHeader reads a header trying x-ESP8266- prefix first, then x-ESP32-.
func espHeader(r *http.Request, suffix string) string {
	if v := r.Header.Get("x-ESP8266-" + suffix); v != "" {
		return v
	}
	return r.Header.Get("x-ESP32-" + suffix)
}

func handleOTA(w http.ResponseWriter, r *http.Request, root string, noParseVersion bool, clog *clientLog) {
	ip := clientIP(r)

	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-esp8266-") || strings.HasPrefix(lower, "x-esp32-") {
			log.Printf("[%s] Header %s: %s", ip, name, strings.Join(values, ", "))
		}
	}

	mac := espHeader(r, "STA-MAC")
	version := espHeader(r, "version")

	if mac == "" || version == "" {
		log.Printf("[%s] Missing required headers", ip)
		http.Error(w, "Missing required headers", http.StatusBadRequest)
		return
	}

	if espHeader(r, "mode") != "sketch" {
		log.Printf("[%s] Invalid or missing mode header", ip)
		w.WriteHeader(http.StatusNotModified)
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
		if clog != nil {
			clog.update(sanitizedMAC, ip, version, "<NONE>")
		}
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
		if clog != nil {
			clog.update(sanitizedMAC, ip, version, "<NONE>")
		}
		w.WriteHeader(http.StatusNotModified)
		return
	}

	sort.Strings(candidates)
	selected := candidates[0]

	filePath := filepath.Join(dir, selected)
	info, err := os.Stat(filePath)
	if err != nil {
		log.Printf("[%s] Cannot stat %s: %v", ip, filePath, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if freeStr := espHeader(r, "free-space"); freeStr != "" {
		if free, err := strconv.ParseInt(freeStr, 10, 64); err == nil && info.Size() >= free {
			log.Printf("[%s] Not enough free space: need %d, have %d", ip, info.Size(), free)
			if clog != nil {
				clog.update(sanitizedMAC, ip, version, selected)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	log.Printf("[%s] Selected update=%s, skipped=%d newer/%d older", ip, selected, len(candidates)-1, numOlder)
	if clog != nil {
		clog.update(sanitizedMAC, ip, version, selected)
	}

	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("[%s] Cannot open %s: %v", ip, filePath, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	http.ServeContent(w, r, selected, info.ModTime(), f)
}

// clientLog holds client records in memory and flushes to disk periodically.

var controlRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func stripControl(s string) string {
	return controlRe.ReplaceAllString(s, "")
}

type clientRecord struct {
	MAC       string
	CallTime  string
	IP        string
	Version   string
	Offered   string
	FailCount int
}

func (r clientRecord) toTSV() string {
	return strings.Join([]string{
		r.MAC, r.CallTime, r.IP, r.Version, r.Offered, strconv.Itoa(r.FailCount),
	}, "\t")
}

func parseRecord(line string) (clientRecord, bool) {
	fields := strings.Split(line, "\t")
	if len(fields) < 5 {
		return clientRecord{}, false
	}
	fc := 0
	if len(fields) >= 6 {
		fc, _ = strconv.Atoi(fields[5])
	}
	return clientRecord{
		MAC: fields[0], CallTime: fields[1], IP: fields[2],
		Version: fields[3], Offered: fields[4], FailCount: fc,
	}, true
}

type clientLog struct {
	path    string
	mu      sync.Mutex
	records map[string]clientRecord
	order   []string
	dirty   bool
}

func newClientLog(path string) *clientLog {
	cl := &clientLog{
		path:    path,
		records: make(map[string]clientRecord),
	}
	cl.loadFromDisk()
	return cl
}

func (cl *clientLog) loadFromDisk() {
	f, err := os.Open(cl.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rec, ok := parseRecord(sc.Text()); ok {
			if _, exists := cl.records[rec.MAC]; !exists {
				cl.order = append(cl.order, rec.MAC)
			}
			cl.records[rec.MAC] = rec
		}
	}
}

func (cl *clientLog) update(mac, ip, version, offered string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	failCount := 0
	cleanVersion := stripControl(version)
	if offered != "<NONE>" {
		if prev, exists := cl.records[mac]; exists {
			if prev.Version == cleanVersion && prev.Offered == offered {
				failCount = prev.FailCount
			}
			failCount++
		} else {
			failCount = 1
		}
	}

	if _, exists := cl.records[mac]; !exists {
		cl.order = append(cl.order, mac)
	}
	cl.records[mac] = clientRecord{
		MAC: mac, CallTime: time.Now().UTC().Format("20060102-150405"),
		IP: ip, Version: cleanVersion, Offered: offered, FailCount: failCount,
	}
	cl.dirty = true
}

func (cl *clientLog) snapshot() []clientRecord {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	out := make([]clientRecord, 0, len(cl.order))
	for _, key := range cl.order {
		out = append(out, cl.records[key])
	}
	return out
}

func (cl *clientLog) flush() {
	cl.mu.Lock()
	if !cl.dirty {
		cl.mu.Unlock()
		return
	}
	var buf strings.Builder
	for _, key := range cl.order {
		buf.WriteString(cl.records[key].toTSV())
		buf.WriteByte('\n')
	}
	cl.dirty = false
	cl.mu.Unlock()

	if err := os.WriteFile(cl.path, []byte(buf.String()), 0644); err != nil {
		log.Printf("Failed to write client log: %v", err)
	}
}

func (cl *clientLog) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		cl.flush()
	}
}

func handleClients(w http.ResponseWriter, clog *clientLog) {
	if clog == nil {
		http.Error(w, "Client log not configured", http.StatusServiceUnavailable)
		return
	}

	records := clog.snapshot()
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

func handleMetrics(w http.ResponseWriter, clog *clientLog) {
	if clog == nil {
		http.Error(w, "Client log not configured", http.StatusServiceUnavailable)
		return
	}

	records := clog.snapshot()
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
		"total_clients":      total,
		"offered_update":     offered,
		"up_to_date":         upToDate,
		"apparently_failing": failing,
	})
}
