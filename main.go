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

// Escribe en el fichero de log
// El contenido de connCounter, que contiene las conexiones únicas y las veces que se han visto
func writeConnectionLog(path string, ialist map[string]string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error abriendo el fichero de log: %v", err)
		return
	}
	defer f.Close()

	connCounter.Range(func(key, value interface{}) bool {
		keyStr, ok := key.(string)
		if !ok {
			return true // skip if not string
		}
		count, ok := value.(int)
		if !ok {
			return true // skip if not int
		}
		parts := strings.Split(keyStr, "-")
		if len(parts) < 5 {
			return true // Formato inesperado
		}
		pid := parts[0]
		laddrIP := parts[1]
		laddrPort := parts[2]
		raddrIP := parts[3]
		raddrPort := parts[4]
		// Etiquetamos las IPs como:
		// - el dominio	 si están en la lista de Blacklist utilizando IaIPs
		// - Privada si son IPs privadas
		// - Pública si son IPs públicas
		var etiqueta string

		if domain, ok := ialist[laddrIP]; ok {
			etiqueta = fmt.Sprintf("Dominio: %s", domain)
		} else if _, ok := blacklist[laddrIP]; ok {
			etiqueta = "Blacklist"
		} else if isPrivateIP(laddrIP) {
			etiqueta = "Privada"
		} else {
			etiqueta = "Pública"
		}
		line := fmt.Sprintf("[%s]\tPID: %s, LADDR: %s:%s, RADDR: %s:%s, VECES VISTA: %d\n", etiqueta, pid, laddrIP, laddrPort, raddrIP, raddrPort, count)
		f.WriteString(line)
		return true
	})
}

func monitorConnections(done chan struct{}) {
	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			conns, err := psnet.Connections("all")
			if err != nil {
				fmt.Println(fmt.Sprintf("Error obteniendo conexiones: %v", err))
				continue
			}
			for _, conn := range conns {
				key := fmt.Sprintf("%d-%s-%d-%s-%d", conn.Pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)
				// Si ya hemos visto esta conexión, aumentamsos el contador
				if count, ok := connCounter.Load(key); ok {
					connCounter.Store(key, count.(int)+1)
					continue // No volvemos a procesar esta conexión
				}
				// Si no, la añadimos al contador
				connCounter.Store(key, 1)

			}
		}
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

	domains, err := fetchDomainsFromGitHub(blacklistFile)
	if err != nil {
		log.Fatalf("No se pudieron obtener los dominios: %v", err)
	}

	var iaIPs = resolveIADomainIPs(domains)

	done := make(chan struct{})
	go monitorConnections(done)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	close(done)
	writeConnectionLog(logPath, iaIPs)
	err = firmarFicheroConHMAC(logPath, "firma.txt", clave)
	if err == nil {
		os.Rename("firma.txt", filepath.Join(storageDir, "netlog_final.txt"))
	}
	cleanupLogFile(logPath)
	fmt.Println("✅ Monitor detenido y archivo firmado")
}
