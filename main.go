package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
)

const (
	WaitSeconds = 10
	// IntervalSeconds = 10
)

var (
	iaDomains = []string{
		"api.openai.com", "chat.openai.com", "claude.ai",
		"api.anthropic.com", "gemini.google.com", "api.mistral.ai",
		"copilot-proxy.githubusercontent.com", "github-copilot.com", "vscode-auth.github.com",
	}
	whitelist = map[string]bool{}
	blacklist = map[string]bool{}
)

func resolveIADomainIPs(domains []string) map[string]string {
	ipMap := make(map[string]string)
	for _, domain := range domains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("Error resolviendo %s: %v", domain, err)
			continue
		}
		for _, ip := range ips {
			ipMap[ip.String()] = domain
		}
	}
	return ipMap
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
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

func calculateMD5(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := md5.New()
	_, err = h.Write([]byte(fmt.Sprintf("%v", time.Now().UnixNano())))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func monitorConnections(iaIPSet map[string]string, logPath, jsonPath string, interval time.Duration, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
			conns, err := psnet.Connections("all")
			if err != nil {
				logMessage(logPath, jsonPath, fmt.Sprintf("Error obteniendo conexiones: %v", err))
				time.Sleep(interval)
				continue
			}
			for _, conn := range conns {
				rIP := conn.Raddr.IP
				if rIP == "" {
					continue
				}
				if whitelist[rIP] {
					continue
				}
				if blacklist[rIP] {
					mgs := fmt.Sprintf("\u26a0\ufe0f Conexi\u00f3n a IP bloqueada detectada! PID:%d %s:%d -> %s:%d (%s)",
						conn.Pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status)
					logMessage(logPath, jsonPath, mgs)
					continue
				}
				if domain, ok := iaIPSet[rIP]; ok {
					msg := fmt.Sprintf("\u26a0\ufe0f Conexi\u00f3n a IP monitoreada detectada! PID:%d %s:%d -> %s:%d (%s)[%s]",
						conn.Pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status, domain)
					logMessage(logPath, jsonPath, msg)
				}
			}
			time.Sleep(interval)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Debe proporcionarse la ruta del log como argumento.")
	}
	storageDir := os.Args[1]
	os.MkdirAll(storageDir, 0755)

	logPath := filepath.Join(storageDir, "netlog.txt")
	jsonPath := filepath.Join(storageDir, "netlog.json")

	interval := WaitSeconds * time.Second
	if val := os.Getenv("NET_MONITOR_INTERVAL"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			interval = time.Duration(i) * time.Second
		}
	}

	logMessage(logPath, jsonPath, "Monitor de red iniciado.")
	iaIPs := resolveIADomainIPs(iaDomains)
	logMessage(logPath, jsonPath, fmt.Sprintf("Resueltas %d IPs de IA.", len(iaIPs)))

	done := make(chan struct{})
	go monitorConnections(iaIPs, logPath, jsonPath, interval, done)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	close(done)

	hash := calculateMD5(logPath)
	logMessage(logPath, jsonPath, fmt.Sprintf("Monitor detenido. MD5 del log: %s", hash))
	fmt.Printf("\n\u2714 Monitor detenido. MD5 del log: %s\n", hash)
}

// Eliminar el archivo de log al finalizar
func cleanupLogFile(logPath string) {
	err := os.Remove(logPath)
	if err != nil {
		log.Printf("Error al eliminar el archivo de log: %v", err)
	} else {
		fmt.Printf("Archivo de log eliminado: %s\n", logPath)
	}
}
