package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleOTA(w, r, *root, *noParseVersion, *clientLog)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Listening on %s, root=%s, no-parse-version=%v", addr, *root, *noParseVersion)
	log.Fatal(http.ListenAndServe(addr, nil))
}

var sanitizeRe = regexp.MustCompile(`[^a-f0-9]`)

func sanitizeMAC(raw string) string {
	s := strings.ToLower(raw)
	s = sanitizeRe.ReplaceAllString(s, "-")
	if len(s) > 17 {
		s = s[:17]
	}
	return s
}

func sanitizeVersion(raw string) string {
	s := strings.ToLower(raw)
	s = sanitizeRe.ReplaceAllString(s, "-")
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

var filenameSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// parseVersion handles the "|D:...|T:...|<optional>" format.
// Returns parsed "yyyymmdd-hhmmss[-sanitized-suffix]" or falls back to sanitized filename.
func parseVersion(raw string, parse bool) string {
	if parse && strings.HasPrefix(raw, "|D:") {
		parts := strings.SplitN(raw[1:], "|", 3) // "D:...", "T:...", optional
		if len(parts) >= 2 && strings.HasPrefix(parts[0], "D:") && strings.HasPrefix(parts[1], "T:") {
			dt := parts[0][2:] + " " + parts[1][2:]
			t, err := time.Parse("Jan  2 2006 15:04:05", dt)
			if err != nil {
				t, err = time.Parse("Jan 2 2006 15:04:05", dt)
			}
			if err == nil {
				result := t.Format("20060102-150405")
				if len(parts) == 3 && parts[2] != "" {
					s := filenameSanitizeRe.ReplaceAllString(parts[2], "-")
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

	// Log all x-ESP8266-* headers
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

	sanitizedMAC := sanitizeMAC(mac)
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
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".bin")
		if name > sanitizedVersion {
			candidates = append(candidates, e.Name())
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
	log.Printf("[%s] Selected update=%s, skipped=%d newer versions", ip, selected, len(candidates)-1)
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

var controlRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func stripControl(s string) string {
	return controlRe.ReplaceAllString(s, "")
}

var clientLogMu sync.Mutex

func writeClientLog(path, mac, ip, version, offered string) {
	if path == "" {
		return
	}
	now := time.Now().UTC().Format("20060102-150405")
	newLine := mac + "\t" + now + "\t" + ip + "\t" + stripControl(version) + "\t" + offered

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
