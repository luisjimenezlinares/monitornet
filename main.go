// Versión optimizada del monitor de red sin dependencias externas
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
)

const (
	clave         = "clave_super_secreta"
	intervalMs    = 200 // Intervalo reducido
	refreshMin    = 10  // Minutos para refrescar IPs
	blacklistFile = "https://raw.githubusercontent.com/luisjimenezlinares/blacklist/refs/heads/main/ia_monitor_domains.txt"
)

var (
	whitelist   = map[string]bool{}
	blacklist   = map[string]bool{}
	seenConns   = sync.Map{}
	connCounter = sync.Map{} // key: string -> count (int)

)

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

func fetchDomainsFromGitHub(rawURL string) ([]string, error) {
	resp, err := http.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var domains []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

func resolveIADomainIPs(domains []string) map[string]string {
	ipMap := make(map[string]string)
	for _, domain := range domains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("Error resolviendo %s", domain)
			continue
		}
		for _, ip := range ips {
			ipMap[ip.String()] = domain
		}
	}
	return ipMap
}

func logMessage(path string, jsonPath string, msg string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(logLine)
	}
	entry := LogEntry{Timestamp: timestamp, Message: msg}
	jsonData, _ := json.Marshal(entry)
	jf, err := os.OpenFile(jsonPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer jf.Close()
		jf.WriteString(string(jsonData) + "\n")
	}
}

func monitorConnections(getIaIPSet func() map[string]string, logPath, jsonPath string, done chan struct{}) {
	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			conns, err := psnet.Connections("all")
			if err != nil {
				logMessage(logPath, jsonPath, fmt.Sprintf("Error obteniendo conexiones: %v", err))
				continue
			}
			iaIPSet := getIaIPSet()
			for _, conn := range conns {
				key := fmt.Sprintf("%d-%s-%d-%s-%d", conn.Pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)
				if _, seen := seenConns.LoadOrStore(key, true); seen || conn.Raddr.IP == "" {
					continue
				}
				rip := conn.Raddr.IP
				if whitelist[rip] {
					continue
				}
				if blacklist[rip] {
					msg := fmt.Sprintf("\u26a0\ufe0f Conexión a IP bloqueada detectada! PID:%d %s:%d -> %s:%d (%s)", conn.Pid, conn.Laddr.IP, conn.Laddr.Port, rip, conn.Raddr.Port, conn.Status)
					logMessage(logPath, jsonPath, msg)
					continue
				}
				if domain, ok := iaIPSet[rip]; ok {
					msg := fmt.Sprintf("\u26a0\ufe0f Conexión a IP monitoreada detectada! PID:%d %s:%d -> %s:%d (%s)[%s]", conn.Pid, conn.Laddr.IP, conn.Laddr.Port, rip, conn.Raddr.Port, conn.Status, domain)
					logMessage(logPath, jsonPath, msg)
				} else if !isPrivateIP(rip) {
					msg := fmt.Sprintf("🔵 Conexión a IP pública: PID:%d %s:%d -> %s:%d (%s)", conn.Pid, conn.Laddr.IP, conn.Laddr.Port, rip, conn.Raddr.Port, conn.Status)
					logMessage(logPath, jsonPath, msg)
				}
			}
		}
	}
}

func periodicIPRefresh(domains []string, mutex *sync.RWMutex, sharedMap *map[string]string, logPath, jsonPath string) {
	ticker := time.NewTicker(time.Duration(refreshMin) * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		newIPs := resolveIADomainIPs(domains)
		mutex.Lock()
		*sharedMap = newIPs
		mutex.Unlock()
		logMessage(logPath, jsonPath, fmt.Sprintf("🔄 Refrescadas %d IPs monitoreadas.", len(newIPs)))
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateBlocks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func firmarFicheroConHMAC(ficheroEntrada, ficheroSalida, clavestr string) error {
	clave := []byte(clavestr)
	original, err := os.ReadFile(ficheroEntrada)
	if err != nil {
		return err
	}
	h := hmac.New(sha256.New, clave)
	h.Write(original)
	hash := h.Sum(nil)
	hashHex := hex.EncodeToString(hash)

	f, err := os.Create(ficheroSalida)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Write(original)
	f.WriteString("\n---HMAC---\n" + hashHex)
	return nil
}

func cleanupLogFile(path string) {
	os.Remove(path)
}

func main() {
	storageDir := "."
	if len(os.Args) == 2 {
		storageDir = os.Args[1]
	}
	os.MkdirAll(storageDir, 0755)
	logPath := filepath.Join(storageDir, "netlog.txt")
	jsonPath := filepath.Join(storageDir, "netlog.json")

	logMessage(logPath, jsonPath, "🚀 Monitor iniciado")
	domains, err := fetchDomainsFromGitHub(blacklistFile)
	if err != nil {
		log.Fatalf("No se pudieron obtener los dominios: %v", err)
	}

	var iaIPs = resolveIADomainIPs(domains)
	var mutex sync.RWMutex
	go periodicIPRefresh(domains, &mutex, &iaIPs, logPath, jsonPath)

	getIaIPSet := func() map[string]string {
		mutex.RLock()
		defer mutex.RUnlock()
		copy := make(map[string]string)
		for k, v := range iaIPs {
			copy[k] = v
		}
		return copy
	}
	done := make(chan struct{})
	go monitorConnections(getIaIPSet, logPath, jsonPath, done)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	close(done)

	err = firmarFicheroConHMAC(logPath, "firma.txt", clave)
	if err == nil {
		os.Rename("firma.txt", filepath.Join(storageDir, "netlog_final.txt"))
	}
	cleanupLogFile(logPath)
	cleanupLogFile(jsonPath)
	fmt.Println("✅ Monitor detenido y archivo firmado")
}
