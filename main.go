package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
)

const interval = 10 * time.Second

var iaDomains = []string{
	"api.openai.com",
	"chat.openai.com",
	"claude.ai",
	"api.anthropic.com",
	"gemini.google.com",
	"api.mistral.ai",
	"copilot-proxy.githubusercontent.com",
	"github-copilot.com",
	"vscode-auth.github.com",
}

func resolveIADomainIPs(domains []string) map[string]bool {
	ipMap := make(map[string]bool)
	for _, domain := range domains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("Error resolviendo %s: %v", domain, err)
			continue
		}
		for _, ip := range ips {
			ipMap[ip.String()] = true
		}
	}
	return ipMap
}

func logMessage(path string, msg string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("No se pudo abrir el archivo de log: %v", err)
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)
	f.WriteString(logLine)
}

func monitorConnections(iaIPSet map[string]bool, logPath string) {
	for {
		conns, err := psnet.Connections("all")
		if err != nil {
			logMessage(logPath, fmt.Sprintf("Error obteniendo conexiones: %v", err))
			time.Sleep(interval)
			continue
		}

		for _, conn := range conns {
			rIP := conn.Raddr.IP
			if rIP != "" && iaIPSet[rIP] {
				msg := fmt.Sprintf("🚨 Conexión a IA detectada! PID:%d %s:%d -> %s:%d (%s)",
					conn.Pid,
					conn.Laddr.IP, conn.Laddr.Port,
					conn.Raddr.IP, conn.Raddr.Port,
					conn.Status)
				logMessage(logPath, msg)
			}
		}

		time.Sleep(interval)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Debe proporcionarse la ruta del log como argumento.")
	}
	storageDir := os.Args[1]
	os.MkdirAll(storageDir, 0755)
	logPath := filepath.Join(storageDir, "netlog.txt")

	logMessage(logPath, "Monitor de red iniciado.")
	iaIPs := resolveIADomainIPs(iaDomains)
	logMessage(logPath, fmt.Sprintf("Resueltas %d IPs de IA.", len(iaIPs)))
	monitorConnections(iaIPs, logPath)
}
