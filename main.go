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
	"strconv"
	"strings"
	"syscall"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
)

const (
	clave       = "clave_super_secreta"
	WaitSeconds = 1
	// IntervalSeconds = 10
	blacklistFile = "https://raw.githubusercontent.com/luisjimenezlinares/blacklist/refs/heads/main/ia_monitor_domains.txt"
)

var (
	//iaDomains = []string{}
	whitelist = map[string]bool{}
	blacklist = map[string]bool{}
)

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
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
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
					continue
				}
				// Si la IP no está en la lista de IA, pero es una IP pública, se registra como conexión normal
				if rIP != "" && !isPrivateIP(rIP) {
					msg := fmt.Sprintf("🔵 Conexión a IP pública detectada! PID:%d %s:%d -> %s:%d (%s)",
						conn.Pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status)
					logMessage(logPath, jsonPath, msg)
				}
			}
			time.Sleep(interval)
		}
	}
}

// firmarFicheroConHMAC firma un archivo usando HMAC-SHA256 y guarda el resultado en un nuevo fichero.
func firmarFicheroConHMAC(ficheroEntrada, ficheroSalida string, clavestr string) error {
	// Convertir la clave a un slice de bytes
	clave := []byte(clavestr)
	// Leer contenido original
	original, err := os.ReadFile(ficheroEntrada)
	if err != nil {
		return fmt.Errorf("error leyendo %s: %w", ficheroEntrada, err)
	}

	// Calcular HMAC-SHA256
	h := hmac.New(sha256.New, clave)
	h.Write(original)
	hash := h.Sum(nil)
	hashHex := hex.EncodeToString(hash)

	// Crear fichero de salida con contenido + separador + HMAC
	f, err := os.Create(ficheroSalida)
	if err != nil {
		return fmt.Errorf("error creando %s: %w", ficheroSalida, err)
	}
	defer f.Close()

	_, err = f.Write(original)
	if err != nil {
		return fmt.Errorf("error escribiendo contenido: %w", err)
	}
	_, err = f.WriteString("\n---HMAC---\n" + hashHex)
	if err != nil {
		return fmt.Errorf("error escribiendo HMAC: %w", err)
	}

	return nil
}

func main() {
	var storageDir string
	if len(os.Args) < 2 {
		storageDir = "."

	} else if len(os.Args) > 2 {
		fmt.Println("Uso: go run main.go [directorio_de_almacenamiento]")
		fmt.Println("Si no se especifica un directorio, se usará el directorio actual.")
		return
	} else {
		storageDir = os.Args[1]
	}

	if storageDir == "" {
		storageDir = "."
	}
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
	iaDomains, err := fetchDomainsFromGitHub(blacklistFile)
	if err != nil {
		log.Fatalf("No se pudieron obtener los dominios: %v", err)
	}
	iaIPs := resolveIADomainIPs(iaDomains)
	logMessage(logPath, jsonPath, fmt.Sprintf("Resueltas %d IPs de IA.", len(iaIPs)))

	done := make(chan struct{})
	go monitorConnections(iaIPs, logPath, jsonPath, interval, done)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	close(done)

	err = firmarFicheroConHMAC(logPath, "firma.txt", clave)
	if err != nil {
		fmt.Println("❌ Error:", err)
	}
	fmt.Printf("\n\u2714 Monitor detenido.\n")
	// Eliminar el archivo de log al finalizar
	cleanupLogFile(logPath)
	cleanupLogFile(jsonPath)
	// Renombrar el archivo de log
	err = os.Rename("firma.txt", filepath.Join(storageDir, "netlog_final.txt"))
	if err != nil {
		fmt.Println("❌ Error al renombrar el archivo de log:", err)
	} else {
		fmt.Printf("Archivo de log renombrado a: %s\n", filepath.Join(storageDir, "netlog_final.txt"))
	}

}

// isPrivateIP checks if the given IP string is a private IP address.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
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
