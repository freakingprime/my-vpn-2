package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"golang.org/x/crypto/ssh"
)

// --- Constants & Configuration ---

const (
	ModeNUC     = "nuc"
	ModeGCE     = "gce"
	ModeVPNGate = "vpngate"

	VPNGateAPIURL        = "http://www.vpngate.net/api/iphone/"
	ServerCacheTTL       = 10 * time.Minute
	PingTimeout          = 5 * time.Second
	InactivityTimeout    = 4 * time.Hour
	HealthTimeout        = 90 * time.Second
	MaxServers           = 100
)

var (
	BuildTime        = ""
	dataDir          = getEnv("DATA_DIR", "/data")
	webPort          = getEnv("WEB_PORT", "8080")
	proxyPort        = getEnv("PROXY_PORT", "8888")
	gceHost          = getEnv("GCE_HOST", "203.0.113.10:22")
	gceUser          = getEnv("GCE_USER", "cloud-user")
	gceKeyPath       = getEnv("GCE_KEY_PATH", "/data/id_rsa")
	gluetunContainer = getEnv("GLUETUN_CONTAINER", "my-vpn-2_vpn")
	gluetunProxyAddr = getEnv("GLUETUN_PROXY_ADDR", "127.0.0.1:18888")
	dockerSockPath   = getEnv("DOCKER_SOCK", "/var/run/docker.sock")

	cipherLines = []string{
		"data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC",
		"data-ciphers-fallback AES-128-CBC",
	}

	privateCIDRs []*net.IPNet
)

func getBuildTime() string {
	if BuildTime != "" && BuildTime != "unknown" {
		return BuildTime
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.time" {
				t, err := time.Parse(time.RFC3339, setting.Value)
				if err == nil {
					return t.UTC().Format("2006-01-02 15:04 UTC")
				}
				return setting.Value
			}
		}
	}
	return "dev (" + time.Now().UTC().Format("2006-01-02") + ")"
}

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, block)
		}
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func isPrivateIP(RemoteAddr string) bool {
	host, _, err := net.SplitHostPort(RemoteAddr)
	if err != nil {
		host = RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, block := range privateCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// --- Data Models ---

type VPNServer struct {
	HostName   string  `json:"hostName"`
	IP         string  `json:"ip"`
	Score      int     `json:"score"`
	Ping       string  `json:"ping"`
	SpeedMbps  float64 `json:"speedMbps"`
	Country    string  `json:"country"`
	ConfigB64  string  `json:"configB64"`
	Proto      string  `json:"proto"`
	Port       int     `json:"port"`
}

type CountryGroup struct {
	Country     string      `json:"country"`
	ServerCount int         `json:"serverCount"`
	Servers     []VPNServer `json:"servers"`
}

type PingResult struct {
	IP        string `json:"ip"`
	Reachable bool   `json:"reachable"`
	LatencyMs int64  `json:"latencyMs"`
	Method    string `json:"method"`
}

type IPInfo struct {
	IP     string `json:"ip"`
	Place  string `json:"place"`
	Org    string `json:"org"`
	Source string `json:"source"`
}

type HistoryEntry struct {
	ExitIP  string `json:"exit_ip"`
	Place   string `json:"place"`
	Org     string `json:"org"`
	Checked int64  `json:"checked"`
	Age     string `json:"age"`
}

// --- Global Controller State ---

type Controller struct {
	mu               sync.RWMutex
	activeMode       string // ModeNUC, ModeGCE, ModeVPNGate
	isTransitioning  bool   // Fail-closed flag during mode transitions
	transitionStatus string
	vpngateServerIP  string
	vpngateCountry   string

	sshMu     sync.Mutex
	sshClient *ssh.Client

	lastActivityUnix atomic.Int64

	serverCacheMu   sync.RWMutex
	cachedServers   []VPNServer
	serverCacheTime time.Time

	pingResultsMu sync.RWMutex
	pingResults   map[string]PingResult

	ipCacheMu   sync.RWMutex
	cachedExit  *IPInfo
	cachedHome  *IPInfo
	ipCacheTime time.Time

	historyMu sync.Mutex
}

func NewController() *Controller {
	c := &Controller{
		activeMode:  ModeNUC,
		pingResults: make(map[string]PingResult),
	}
	c.touchActivity()
	return c
}

func (c *Controller) touchActivity() {
	c.lastActivityUnix.Store(time.Now().Unix())
}

func (c *Controller) remainingIdleDuration() time.Duration {
	last := time.Unix(c.lastActivityUnix.Load(), 0)
	elapsed := time.Since(last)
	rem := InactivityTimeout - elapsed
	if rem < 0 {
		return 0
	}
	return rem
}

// --- Docker Socket Helper (Lightweight HTTP over Unix Socket) ---

var dockerHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", dockerSockPath, 5*time.Second)
		},
	},
	Timeout: 30 * time.Second,
}

func inspectGluetunHealth() (running bool, healthStatus string) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost/containers/%s/json", gluetunContainer), nil)
	resp, err := dockerHTTPClient.Do(req)
	if err != nil {
		return false, "error"
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, "not-found"
	}
	var data struct {
		State struct {
			Running bool `json:"Running"`
			Health  *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false, "decode-error"
	}
	if !data.State.Running {
		return false, "stopped"
	}
	if data.State.Health == nil {
		return true, "no-healthcheck"
	}
	return true, data.State.Health.Status
}

func stopGluetunContainer() {
	running, _ := inspectGluetunHealth()
	if running {
		req, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost/containers/%s/stop?t=5", gluetunContainer), nil)
		resp, err := dockerHTTPClient.Do(req)
		if err == nil && resp != nil {
			resp.Body.Close()
		}
	}
}

func startOrRestartGluetun() error {
	running, _ := inspectGluetunHealth()
	action := "start"
	if running {
		action = "restart?t=5"
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost/containers/%s/%s", gluetunContainer, action), nil)
	resp, err := dockerHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != 304 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker %s HTTP %d: %s", action, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// --- GCE SSH On-Demand Client ---

func (c *Controller) closeSSH() {
	c.sshMu.Lock()
	defer c.sshMu.Unlock()
	if c.sshClient != nil {
		c.sshClient.Close()
		c.sshClient = nil
		log.Println("[SSH] Disconnected from GCE VM.")
	}
}

func (c *Controller) ensureSSHConnected() (*ssh.Client, error) {
	c.sshMu.Lock()
	defer c.sshMu.Unlock()

	if c.sshClient != nil {
		// Quick keepalive check
		_, _, err := c.sshClient.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return c.sshClient, nil
		}
		c.sshClient.Close()
		c.sshClient = nil
	}

	keyBytes, err := os.ReadFile(gceKeyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read SSH key at %s: %w", gceKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse SSH private key: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User: gceUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         12 * time.Second,
	}

	log.Printf("[SSH] Dialing GCE VM %s@%s...", gceUser, gceHost)
	client, err := ssh.Dial("tcp", gceHost, cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial to %s failed: %w", gceHost, err)
	}
	c.sshClient = client
	log.Printf("[SSH] Successfully connected to GCE VM %s!", gceHost)
	return client, nil
}

// --- Dynamic Upstream Dialer for goproxy & Exit IP Checker ---

func dialViaHTTPProxy(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("cannot reach internal Gluetun proxy (%s): %w", proxyAddr, err)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("gluetun proxy returned %s", resp.Status)
	}
	return conn, nil
}

func (c *Controller) dialUpstream(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mu.RLock()
	mode := c.activeMode
	transitioning := c.isTransitioning
	c.mu.RUnlock()

	// Fail-Closed during mode transitions
	if transitioning {
		return nil, fmt.Errorf("fail-closed: VPN/Proxy target is currently switching, blocking traffic to prevent IP leak")
	}

	c.touchActivity()

	switch mode {
	case ModeNUC:
		d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		return d.DialContext(ctx, network, addr)

	case ModeGCE:
		sshCli, err := c.ensureSSHConnected()
		if err != nil {
			return nil, fmt.Errorf("fail-closed (GCE SSH error): %w", err)
		}
		return sshCli.Dial(network, addr)

	case ModeVPNGate:
		running, health := inspectGluetunHealth()
		if !running || (health != "healthy" && health != "no-healthcheck") {
			return nil, fmt.Errorf("fail-closed: Gluetun VPN container is not healthy (status: %s)", health)
		}
		return dialViaHTTPProxy(ctx, gluetunProxyAddr, addr)

	default:
		return nil, fmt.Errorf("unknown mode: %s", mode)
	}
}

// --- Mode Switching Engine ---

func (c *Controller) SwitchToNUC() error {
	c.mu.Lock()
	c.isTransitioning = true
	c.transitionStatus = "Switching to Direct (Local ISP) and stopping background tunnels..."
	c.mu.Unlock()

	c.closeSSH()
	stopGluetunContainer()

	c.mu.Lock()
	c.activeMode = ModeNUC
	c.vpngateServerIP = ""
	c.vpngateCountry = ""
	c.isTransitioning = false
	c.transitionStatus = ""
	c.mu.Unlock()

	c.touchActivity()
	c.refreshIPStatus(true)
	log.Println("[MODE] Active target switched to Direct (Local ISP).")
	return nil
}

func (c *Controller) SwitchToGCE() error {
	c.mu.Lock()
	c.isTransitioning = true
	c.transitionStatus = fmt.Sprintf("Connecting on-demand SSH tunnel to Google Cloud VM (%s)...", gceHost)
	c.mu.Unlock()

	stopGluetunContainer()

	_, err := c.ensureSSHConnected()
	if err != nil {
		c.mu.Lock()
		c.activeMode = ModeNUC
		c.isTransitioning = false
		c.transitionStatus = ""
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	c.activeMode = ModeGCE
	c.vpngateServerIP = ""
	c.vpngateCountry = ""
	c.isTransitioning = false
	c.transitionStatus = ""
	c.mu.Unlock()

	c.touchActivity()
	c.refreshIPStatus(true)
	log.Printf("[MODE] Active target switched to GCE VM (%s).", gceHost)
	return nil
}

func buildOpenVPNConfig(b64 string) (string, error) {
	b64 = strings.ReplaceAll(b64, `\u002b`, "+")
	b64 = strings.ReplaceAll(b64, `\u002B`, "+")
	b64 = strings.ReplaceAll(b64, `\u002f`, "/")
	b64 = strings.ReplaceAll(b64, `\u002F`, "/")
	b64 = strings.ReplaceAll(b64, `\u003d`, "=")
	b64 = strings.ReplaceAll(b64, `\u003D`, "=")
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, b64)
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", err
	}
	var kept []string
	for _, ln := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "data-ciphers") || strings.HasPrefix(trimmed, "data-ciphers-fallback") {
			continue
		}
		kept = append(kept, strings.TrimRight(ln, "\r"))
	}
	return strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n\n" + strings.Join(cipherLines, "\n") + "\n", nil
}

func (c *Controller) SwitchToVPNGate(ip, country, b64Config string) error {
	cfgText, err := buildOpenVPNConfig(b64Config)
	if err != nil {
		return fmt.Errorf("invalid base64 OpenVPN config: %w", err)
	}

	c.mu.Lock()
	c.activeMode = ModeVPNGate
	c.vpngateServerIP = ip
	c.vpngateCountry = country
	c.isTransitioning = true
	c.transitionStatus = fmt.Sprintf("Starting Gluetun & connecting to VPNGate %s (%s)...", ip, country)
	c.mu.Unlock()

	// Close GCE SSH if active
	c.closeSSH()

	// Write /data/custom.conf
	confPath := filepath.Join(dataDir, "custom.conf")
	if err := os.WriteFile(confPath, []byte(cfgText), 0644); err != nil {
		c.mu.Lock()
		c.activeMode = ModeNUC
		c.vpngateServerIP = ""
		c.vpngateCountry = ""
		c.isTransitioning = false
		c.transitionStatus = ""
		c.mu.Unlock()
		return fmt.Errorf("failed writing custom.conf: %w", err)
	}

	// Ensure we know Home IP so we can verify tunnel exit IP differs from Home IP
	c.ipCacheMu.RLock()
	homeInfo := c.cachedHome
	c.ipCacheMu.RUnlock()
	if homeInfo == nil {
		d := net.Dialer{Timeout: 6 * time.Second}
		homeInfo = c.fetchIPWithDialer(d.DialContext)
	}

	// Start/Restart Gluetun container
	if err := startOrRestartGluetun(); err != nil {
		c.mu.Lock()
		c.activeMode = ModeNUC
		c.vpngateServerIP = ""
		c.vpngateCountry = ""
		c.isTransitioning = false
		c.transitionStatus = ""
		c.mu.Unlock()
		return fmt.Errorf("failed starting Gluetun container: %w", err)
	}

	// Poll healthcheck & tunnel exit verification up to HealthTimeout
	deadline := time.Now().Add(HealthTimeout)
	finalStatus := "timeout"
	var verifiedExit *IPInfo
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		running, health := inspectGluetunHealth()
		if !running {
			finalStatus = "container-stopped"
			break
		}
		finalStatus = health
		if health == "healthy" || health == "no-healthcheck" {
			probeExit := c.fetchIPWithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialViaHTTPProxy(ctx, gluetunProxyAddr, addr)
			})
			if probeExit != nil && (homeInfo == nil || probeExit.IP != homeInfo.IP) {
				verifiedExit = probeExit
				finalStatus = "healthy"
				break
			}
			finalStatus = "connecting-tunnel"
		}
	}

	if finalStatus != "healthy" && finalStatus != "no-healthcheck" {
		stopGluetunContainer()
		c.mu.Lock()
		c.activeMode = ModeNUC
		c.vpngateServerIP = ""
		c.vpngateCountry = ""
		c.isTransitioning = false
		c.transitionStatus = ""
		c.mu.Unlock()
		c.refreshIPStatus(true)
		return fmt.Errorf("VPNGate server %s did not become healthy within %v (status: %s). Reverted to Direct (Local ISP).", ip, HealthTimeout, finalStatus)
	}

	c.mu.Lock()
	c.isTransitioning = false
	c.transitionStatus = ""
	c.mu.Unlock()

	c.touchActivity()
	if verifiedExit != nil {
		c.ipCacheMu.Lock()
		c.cachedExit = verifiedExit
		if homeInfo != nil {
			c.cachedHome = homeInfo
		}
		c.ipCacheTime = time.Now()
		c.ipCacheMu.Unlock()
		c.recordExitHistory(ip, verifiedExit)
	} else {
		exitInfo, hInfo, _ := c.refreshIPStatus(true)
		if exitInfo != nil && (hInfo == nil || exitInfo.IP != hInfo.IP) {
			c.recordExitHistory(ip, exitInfo)
		}
	}
	log.Printf("[MODE] Successfully connected to VPNGate server %s (%s)!", ip, country)
	return nil
}

// --- 4-Hour Inactivity Watchdog ---

func (c *Controller) startInactivityWatchdog() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			c.mu.RLock()
			mode := c.activeMode
			transitioning := c.isTransitioning
			c.mu.RUnlock()

			if mode != ModeNUC && !transitioning {
				if c.remainingIdleDuration() == 0 {
					log.Printf("[IDLE] 4 hours of inactivity elapsed in mode '%s'. Auto-reverting to Direct (Local ISP)...", mode)
					_ = c.SwitchToNUC()
				}
			}
		}
	}()
}

// --- VPNGate Server List Fetching & Caching ---

func parseOpenVPNProtoPort(b64 string) (string, int) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "tcp", 443
	}
	proto := "tcp"
	port := 443
	for _, ln := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(ln))
		if len(fields) >= 2 && fields[0] == "proto" {
			if strings.HasPrefix(strings.ToLower(fields[1]), "udp") {
				proto = "udp"
			} else {
				proto = "tcp"
			}
		} else if len(fields) >= 3 && fields[0] == "remote" {
			if p, err := strconv.Atoi(fields[2]); err == nil && p > 0 {
				port = p
			}
		}
	}
	return proto, port
}

func (c *Controller) getServers(forceRefresh bool) ([]VPNServer, time.Duration, error) {
	c.serverCacheMu.RLock()
	if !forceRefresh && len(c.cachedServers) > 0 && time.Since(c.serverCacheTime) < ServerCacheTTL {
		servers := make([]VPNServer, len(c.cachedServers))
		copy(servers, c.cachedServers)
		age := time.Since(c.serverCacheTime)
		c.serverCacheMu.RUnlock()
		return servers, age, nil
	}
	c.serverCacheMu.RUnlock()

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(VPNGateAPIURL)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	var cleanLines []string
	for _, ln := range strings.Split(string(bodyBytes), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "*") {
			continue
		}
		cleanLines = append(cleanLines, ln)
	}
	if len(cleanLines) == 0 {
		return nil, 0, fmt.Errorf("empty server list from VPNGate")
	}
	cleanLines[0] = strings.TrimPrefix(cleanLines[0], "#")

	reader := csv.NewReader(strings.NewReader(strings.Join(cleanLines, "\n")))
	headers, err := reader.Read()
	if err != nil {
		return nil, 0, err
	}
	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[h] = i
	}

	var servers []VPNServer
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(row) < len(headers) {
			continue
		}
		b64 := row[colIdx["OpenVPN_ConfigData_Base64"]]
		if b64 == "" {
			continue
		}
		score, _ := strconv.Atoi(row[colIdx["Score"]])
		speedBps, _ := strconv.ParseFloat(row[colIdx["Speed"]], 64)
		speedMbps := math.Round((speedBps/1_000_000.0)*100) / 100
		proto, port := parseOpenVPNProtoPort(b64)

		servers = append(servers, VPNServer{
			HostName:  row[colIdx["HostName"]],
			IP:        row[colIdx["IP"]],
			Score:     score,
			Ping:      row[colIdx["Ping"]],
			SpeedMbps: speedMbps,
			Country:   row[colIdx["CountryLong"]],
			ConfigB64: b64,
			Proto:     proto,
			Port:      port,
		})
	}

	sort.Slice(servers, func(i, j int) bool {
		return servers[i].Score > servers[j].Score
	})
	if len(servers) > MaxServers {
		servers = servers[:MaxServers]
	}

	c.serverCacheMu.Lock()
	c.cachedServers = servers
	c.serverCacheTime = time.Now()
	c.serverCacheMu.Unlock()

	return servers, 0, nil
}

func sortCountryServers(servers []VPNServer, pingResults map[string]PingResult) {
	sort.SliceStable(servers, func(i, j int) bool {
		pA, hasA := pingResults[servers[i].IP]
		pB, hasB := pingResults[servers[j].IP]

		// State: 1 = reachable (available), 2 = unpinged, 3 = offline
		state := func(p PingResult, has bool) int {
			if !has {
				return 2
			}
			if p.Reachable {
				return 1
			}
			return 3
		}

		sA := state(pA, hasA)
		sB := state(pB, hasB)

		if sA != sB {
			return sA < sB
		}
		// Within the same availability tier, sort by Score descending
		if servers[i].Score != servers[j].Score {
			return servers[i].Score > servers[j].Score
		}
		// Tie-breaker: if both reachable and same score, sort by latency ascending
		if sA == 1 && pA.LatencyMs != pB.LatencyMs {
			return pA.LatencyMs < pB.LatencyMs
		}
		return servers[i].IP < servers[j].IP
	})
}

func groupServersByCountry(servers []VPNServer, pingResults map[string]PingResult) []CountryGroup {
	countryMap := make(map[string][]VPNServer)
	for _, s := range servers {
		countryMap[s.Country] = append(countryMap[s.Country], s)
	}

	var groups []CountryGroup
	for country, srvs := range countryMap {
		copied := make([]VPNServer, len(srvs))
		copy(copied, srvs)
		sortCountryServers(copied, pingResults)
		groups = append(groups, CountryGroup{
			Country:     country,
			ServerCount: len(copied),
			Servers:     copied,
		})
	}

	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].ServerCount != groups[j].ServerCount {
			return groups[i].ServerCount > groups[j].ServerCount
		}
		return groups[i].Country < groups[j].Country
	})

	return groups
}

// --- Smart Multi-Protocol Latency & Availability Prober (5s Timeout) ---

func probeSingleServer(ip, proto string, port int) PingResult {
	ctx, cancel := context.WithTimeout(context.Background(), PingTimeout)
	defer cancel()

	type probeOut struct {
		ms     int64
		method string
	}
	resChan := make(chan probeOut, 8)

	// 1. If TCP OpenVPN config, probe the exact OpenVPN TCP port first
	if proto == "tcp" && port > 0 {
		go func(p int) {
			start := time.Now()
			d := net.Dialer{Timeout: PingTimeout}
			conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, p))
			if err == nil {
				conn.Close()
				resChan <- probeOut{ms: time.Since(start).Milliseconds(), method: fmt.Sprintf("TCP:%d", p)}
			}
		}(port)
	}

	// 2. If UDP OpenVPN config, send a real OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 UDP packet
	if proto == "udp" && port > 0 {
		go func(p int) {
			start := time.Now()
			d := net.Dialer{Timeout: PingTimeout}
			conn, err := d.DialContext(ctx, "udp", fmt.Sprintf("%s:%d", ip, p))
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(PingTimeout))

			// 14-byte OpenVPN Hard Reset v2 client packet (opcode 0x38 + 8-byte session ID + 5 zero bytes)
			pkt := make([]byte, 14)
			pkt[0] = 0x38
			_, _ = rand.Read(pkt[1:9])
			if _, err := conn.Write(pkt); err != nil {
				return
			}
			buf := make([]byte, 64)
			if n, err := conn.Read(buf); err == nil && n > 0 {
				resChan <- probeOut{ms: time.Since(start).Milliseconds(), method: fmt.Sprintf("UDP:%d", p)}
			}
		}(port)
	}

	// 3. Also probe common SoftEther / VPN TCP ports in parallel so UDP-only servers still yield TCP availability & latency
	fallbackPorts := []int{443, 995, 5555, 1194, 80}
	for _, fp := range fallbackPorts {
		if proto == "tcp" && fp == port {
			continue
		}
		go func(p int) {
			start := time.Now()
			d := net.Dialer{Timeout: PingTimeout}
			conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, p))
			if err == nil {
				conn.Close()
				resChan <- probeOut{ms: time.Since(start).Milliseconds(), method: fmt.Sprintf("TCP:%d", p)}
			}
		}(fp)
	}

	select {
	case win := <-resChan:
		if win.ms < 1 {
			win.ms = 1
		}
		return PingResult{
			IP:        ip,
			Reachable: true,
			LatencyMs: win.ms,
			Method:    win.method,
		}
	case <-ctx.Done():
		return PingResult{
			IP:        ip,
			Reachable: false,
			LatencyMs: -1,
			Method:    "timeout",
		}
	}
}

// --- Exit IP & Home IP Lookup ---

var ipSources = []struct {
	Name string
	URL  string
}{
	{"ipwho.is", "https://ipwho.is/"},
	{"ipinfo", "https://ipinfo.io/json"},
	{"cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"},
}

func parseIPPayload(source, body string) *IPInfo {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	if source == "cloudflare" {
		kv := make(map[string]string)
		for _, ln := range strings.Split(body, "\n") {
			if parts := strings.SplitN(ln, "=", 2); len(parts) == 2 {
				kv[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		if ip := kv["ip"]; ip != "" {
			return &IPInfo{IP: ip, Place: kv["loc"], Org: "", Source: source}
		}
		return nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil
	}
	if s, ok := data["success"].(bool); ok && !s {
		return nil
	}
	ip, _ := data["ip"].(string)
	if ip == "" {
		return nil
	}
	city, _ := data["city"].(string)
	country, _ := data["country"].(string)
	var placeParts []string
	if city != "" {
		placeParts = append(placeParts, city)
	}
	if country != "" {
		placeParts = append(placeParts, country)
	}
	org, _ := data["org"].(string)
	if org == "" {
		if connMap, ok := data["connection"].(map[string]interface{}); ok {
			org, _ = connMap["org"].(string)
		}
	}
	place := strings.Join(placeParts, ", ")
	if place == "" {
		place = "Unknown location"
	}
	return &IPInfo{IP: ip, Place: place, Org: org, Source: source}
}

func (c *Controller) fetchIPWithDialer(dialFn func(ctx context.Context, network, addr string) (net.Conn, error)) *IPInfo {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialFn,
		},
		Timeout: 8 * time.Second,
	}
	for _, src := range ipSources {
		resp, err := client.Get(src.URL)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if info := parseIPPayload(src.Name, string(b)); info != nil {
			return info
		}
	}
	return nil
}

func (c *Controller) refreshIPStatus(force bool) (exit *IPInfo, home *IPInfo, ageSec int) {
	c.ipCacheMu.RLock()
	if !force && !c.ipCacheTime.IsZero() && time.Since(c.ipCacheTime) < 60*time.Second {
		exit, home = c.cachedExit, c.cachedHome
		ageSec = int(time.Since(c.ipCacheTime).Seconds())
		c.ipCacheMu.RUnlock()
		return
	}
	c.ipCacheMu.RUnlock()

	var wg sync.WaitGroup
	var newExit, newHome *IPInfo
	wg.Add(2)
	go func() {
		defer wg.Done()
		newExit = c.fetchIPWithDialer(c.dialUpstream)
	}()
	go func() {
		defer wg.Done()
		d := net.Dialer{Timeout: 8 * time.Second}
		newHome = c.fetchIPWithDialer(d.DialContext)
	}()
	wg.Wait()

	c.ipCacheMu.Lock()
	c.cachedExit = newExit
	c.cachedHome = newHome
	c.ipCacheTime = time.Now()
	c.ipCacheMu.Unlock()

	return newExit, newHome, 0
}

// --- Exit History Persistence ---

func (c *Controller) historyFilePath() string {
	return filepath.Join(dataDir, "exit_history.json")
}

func (c *Controller) loadExitHistory() map[string]HistoryEntry {
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	b, err := os.ReadFile(c.historyFilePath())
	if err != nil {
		return map[string]HistoryEntry{}
	}
	var m map[string]HistoryEntry
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]HistoryEntry{}
	}
	now := time.Now().Unix()
	for k, v := range m {
		secs := now - v.Checked
		if secs < 3600 {
			v.Age = fmt.Sprintf("%d min ago", secs/60)
		} else if secs < 86400 {
			v.Age = fmt.Sprintf("%d h ago", secs/3600)
		} else {
			v.Age = fmt.Sprintf("%d d ago", secs/86400)
		}
		m[k] = v
	}
	return m
}

func (c *Controller) recordExitHistory(serverIP string, info *IPInfo) {
	if serverIP == "" || info == nil {
		return
	}
	m := c.loadExitHistory()
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	m[serverIP] = HistoryEntry{
		ExitIP:  info.IP,
		Place:   info.Place,
		Org:     info.Org,
		Checked: time.Now().Unix(),
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err == nil {
		_ = os.WriteFile(c.historyFilePath(), b, 0644)
	}
}

// --- HTTP/HTTPS Proxy Server (elazarl/goproxy) ---

func setupProxyHandler(c *Controller) http.Handler {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Configure dynamic upstream transport
	proxy.Tr = &http.Transport{
		DialContext:           c.dialUpstream,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   12 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return c.dialUpstream(ctx, network, addr)
	}

	// Enforce Private LAN & Tailscale IP Whitelist
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPrivateIP(r.RemoteAddr) {
			http.Error(w, "Forbidden: Proxy restricted to private LAN and Tailscale subnets.", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func startProxyServer(c *Controller) {
	handler := setupProxyHandler(c)
	addr := ":" + proxyPort
	log.Printf("[PROXY] Starting HTTP/HTTPS CONNECT Proxy on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("[PROXY] Fatal error on %s: %v", addr, err)
	}
}

// --- Web UI & API Routes ---

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>my-vpn-2 — Multi-Target HTTPS Proxy Gateway</title>
    <style>
        :root {
            --bg: #1e1e2e;
            --surface: #313244;
            --surface-hover: #45475a;
            --text: #cdd6f4;
            --subtext: #a6adc8;
            --blue: #89b4fa;
            --green: #a6e3a1;
            --yellow: #f9e2af;
            --red: #f38ba8;
            --muted: #6c7086;
        }
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: var(--bg);
            color: var(--text);
        }
        .header-bar {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 18px;
        }
        .title-area {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        h1 { margin: 0; color: var(--blue); font-size: 24px; }
        .build-badge {
            background: rgba(137, 180, 250, 0.15);
            color: var(--blue);
            border: 1px solid rgba(137, 180, 250, 0.35);
            padding: 3px 9px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }
        .proxy-pill {
            background: var(--surface);
            border: 1px solid var(--blue);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 13px;
        }
        .proxy-pill code {
            color: var(--green);
            font-weight: bold;
            font-size: 14px;
        }
        .targets-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 14px;
            margin-bottom: 18px;
        }
        .target-card {
            background: var(--surface);
            border: 2px solid transparent;
            border-radius: 8px;
            padding: 16px;
            transition: all 0.15s ease;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .target-card.active {
            border-color: var(--green);
            box-shadow: 0 0 15px rgba(166, 227, 161, 0.18);
        }
        .target-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .target-title { font-size: 17px; font-weight: 700; color: #fff; }
        .badge {
            padding: 3px 9px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-active { background: var(--green); color: #1e1e2e; }
        .badge-standby { background: var(--surface-hover); color: var(--subtext); }
        .target-desc { font-size: 13px; color: var(--subtext); margin-bottom: 14px; line-height: 1.4; }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }
        .stat-card {
            background: var(--surface);
            border-radius: 6px;
            padding: 12px 15px;
        }
        .stat-label { font-size: 11px; color: var(--subtext); text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-val { font-size: 19px; font-weight: bold; margin-top: 4px; }
        .stat-sub { font-size: 12px; color: var(--subtext); margin-top: 4px; }
        .good { color: var(--green); }
        .warn { color: var(--yellow); }
        .bad { color: var(--red); }
        .muted { color: var(--muted); font-style: italic; }
        .btn {
            padding: 8px 14px;
            background-color: var(--green);
            color: #1e1e2e;
            border: none;
            cursor: pointer;
            border-radius: 5px;
            font-weight: 700;
            font-size: 13px;
            transition: opacity 0.15s;
        }
        .btn:hover { opacity: 0.9; }
        .btn:disabled { background-color: var(--muted); cursor: wait; opacity: 0.7; }
        .btn-blue { background-color: var(--blue); }
        .btn-yellow { background-color: var(--yellow); }
        .btn-sm { padding: 6px 11px; font-size: 12px; }
        #banner {
            display: none;
            padding: 14px 16px;
            border-radius: 6px;
            margin-bottom: 16px;
            font-weight: 600;
            background: var(--yellow);
            color: #1e1e2e;
        }
        #banner.error { background: var(--red); }
        #banner.success { background: var(--green); }
        .toolbar {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            margin-top: 22px;
            margin-bottom: 10px;
        }
        .toolbar-actions { display: flex; gap: 8px; align-items: center; }
        table {
            border-collapse: collapse;
            width: 100%;
            background-color: var(--surface);
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.25);
        }
        th, td {
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--surface-hover);
            font-size: 14px;
        }
        th { background-color: var(--blue); color: #1e1e2e; font-weight: 700; }
        tr:hover { background-color: rgba(69, 71, 90, 0.55); }
        tr.active-row td { background-color: var(--surface-hover); font-weight: 600; }
        .country-divider-row td {
            background-color: #24273a;
            border-top: 2px solid var(--blue);
            border-bottom: 2px solid var(--surface-hover);
            padding: 9px 14px;
        }
        .country-divider-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .country-name {
            font-size: 15px;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .country-badge {
            background: var(--surface-hover);
            color: var(--blue);
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 600;
        }
        .action-group { display: flex; gap: 6px; align-items: center; }
    </style>
</head>
<body>
    <div class="header-bar">
        <div class="title-area">
            <h1>my-vpn-2 — Multi-Target Proxy Gateway</h1>
            <span class="build-badge" title="Container Build Timestamp">Build: {{ .BuildTime }}</span>
        </div>
        <div class="proxy-pill">
            HTTP / HTTPS Proxy: <code id="proxyAddrText">{{ .HostIP }}:{{ .ProxyPort }}</code>
            &nbsp;|&nbsp; PAC URL: <code>http://{{ .HostIP }}:{{ .WebPort }}/proxy.pac</code>
        </div>
    </div>

    <div id="banner"></div>

    <!-- 3 Selectable Target Mode Cards -->
    <div class="targets-grid">
        <div class="target-card {{ if eq .ActiveMode "nuc" }}active{{ end }}" id="card-nuc">
            <div>
                <div class="target-header">
                    <span class="target-title">1. Direct (Local ISP)</span>
                    <span class="badge {{ if eq .ActiveMode "nuc" }}badge-active{{ else }}badge-standby{{ end }}">
                        {{ if eq .ActiveMode "nuc" }}ACTIVE{{ else }}STANDBY{{ end }}
                    </span>
                </div>
                <div class="target-desc">
                    Routes proxy traffic directly out through your local ISP connection. Both GCE SSH and Gluetun sleep (0 background resources).
                </div>
            </div>
            <button class="btn {{ if eq .ActiveMode "nuc" }}btn-blue{{ end }}" onclick="switchMode('nuc')" {{ if eq .ActiveMode "nuc" }}disabled{{ end }}>
                {{ if eq .ActiveMode "nuc" }}Currently Active{{ else }}Switch to Direct (Local ISP){{ end }}
            </button>
        </div>

        <div class="target-card {{ if eq .ActiveMode "gce" }}active{{ end }}" id="card-gce">
            <div>
                <div class="target-header">
                    <span class="target-title">2. Google Cloud VM (SSH Tunnel)</span>
                    <span class="badge {{ if eq .ActiveMode "gce" }}badge-active{{ else }}badge-standby{{ end }}">
                        {{ if eq .ActiveMode "gce" }}ACTIVE{{ else }}ON-DEMAND{{ end }}
                    </span>
                </div>
                <div class="target-desc">
                    Establishes an encrypted on-demand SSH tunnel to <code>{{ .GCEHost }}</code>.
                </div>
            </div>
            <button class="btn {{ if eq .ActiveMode "gce" }}btn-blue{{ end }}" onclick="switchMode('gce')" {{ if eq .ActiveMode "gce" }}disabled{{ end }}>
                {{ if eq .ActiveMode "gce" }}Currently Active{{ else }}Connect GCE SSH Tunnel{{ end }}
            </button>
        </div>

        <div class="target-card {{ if eq .ActiveMode "vpngate" }}active{{ end }}" id="card-vpngate">
            <div>
                <div class="target-header">
                    <span class="target-title">3. VPNGate Volunteer Server</span>
                    <span class="badge {{ if eq .ActiveMode "vpngate" }}badge-active{{ else }}badge-standby{{ end }}" id="badge-vpngate">
                        {{ if eq .ActiveMode "vpngate" }}ACTIVE{{ else }}ON-DEMAND{{ end }}
                    </span>
                </div>
                <div class="target-desc">
                    {{ if eq .ActiveMode "vpngate" }}
                        Connected to VPNGate server <strong>{{ .VPNGateIP }}</strong> ({{ .VPNGateCountry }}).
                    {{ else }}
                        Starts Gluetun OpenVPN container on-demand when you click <strong>Connect</strong> on any server in the table below.
                    {{ end }}
                </div>
            </div>
            <button class="btn btn-blue" onclick="document.getElementById('serversTable').scrollIntoView({behavior:'smooth'})">
                {{ if eq .ActiveMode "vpngate" }}Change Server Below ↓{{ else }}Choose Server Below ↓{{ end }}
            </button>
        </div>
    </div>

    <!-- Live Status Verification Cards -->
    <div class="status-grid">
        <div class="stat-card">
            <div class="stat-label">Proxy Exit IP (What Websites See)</div>
            {{ if .ExitInfo }}
                <div class="stat-val good">{{ .ExitInfo.IP }}</div>
                <div class="stat-sub">{{ .ExitInfo.Place }}{{ if .ExitInfo.Org }} &middot; {{ .ExitInfo.Org }}{{ end }} ({{ .ExitInfo.Source }})</div>
            {{ else }}
                <div class="stat-val warn">Checking / Unavailable</div>
                <div class="stat-sub">Click Refresh IP Status</div>
            {{ end }}
        </div>

        <div class="stat-card">
            <div class="stat-label">Local Home IP (Direct ISP)</div>
            {{ if .HomeInfo }}
                <div class="stat-val">{{ .HomeInfo.IP }}</div>
                <div class="stat-sub">{{ .HomeInfo.Place }}{{ if .HomeInfo.Org }} &middot; {{ .HomeInfo.Org }}{{ end }}</div>
            {{ else }}
                <div class="stat-val warn">Unavailable</div>
            {{ end }}
        </div>

        <div class="stat-card">
            <div class="stat-label">4-Hour Inactivity Auto-Shutoff</div>
            {{ if eq .ActiveMode "nuc" }}
                <div class="stat-val good">Sleeping (0 VPN/SSH Load)</div>
                <div class="stat-sub">Timer starts when GCE or VPNGate is active</div>
            {{ else }}
                <div class="stat-val warn">{{ .IdleRemaining }}</div>
                <div class="stat-sub">Resets automatically on any proxy traffic</div>
            {{ end }}
        </div>
    </div>

    <div class="toolbar">
        <div>
            <strong>VPNGate Public Servers ({{ .TotalServers }} available across {{ len .CountryGroups }} countries)</strong>
            <span class="stat-sub" style="margin-left:8px;">
                List cached {{ .ServerCacheAge }} ago &middot;
                <a href="/?refresh_ips=1" style="color:var(--blue);">Re-check Exit IP</a>
            </span>
        </div>
        <div class="toolbar-actions">
            <button class="btn btn-yellow" id="pingAllBtn" onclick="pingAllServers()">⚡ Ping All (5s timeout)</button>
            <button class="btn btn-blue" onclick="window.location.href='/?refresh_servers=1'">🔄 Refresh Server List</button>
        </div>
    </div>

    <table id="serversTable">
        <thead>
            <tr>
                <th>Country</th>
                <th>Speed (Mbps)</th>
                <th>VPNGate Ping</th>
                <th>Live Ping</th>
                <th>Score</th>
                <th>Server IP</th>
                <th>Exit IP (Last Seen)</th>
                <th>Action</th>
            </tr>
        </thead>
        {{ range .CountryGroups }}
        <tbody class="country-tbody" data-country="{{ .Country }}">
            <tr class="country-divider-row">
                <td colspan="8">
                    <div class="country-divider-content">
                        <div class="country-name">
                            <span>🌐 {{ .Country }}</span>
                            <span class="country-badge">{{ .ServerCount }} servers</span>
                        </div>
                        <button class="btn btn-yellow btn-sm" onclick="pingCountry('{{ .Country }}', this)">⚡ Ping {{ .Country }}</button>
                    </div>
                </td>
            </tr>
            {{ range .Servers }}
            <tr id="row-{{ .IP }}" class="server-row {{ if and (eq $.ActiveMode "vpngate") (eq $.VPNGateIP .IP) }}active-row{{ end }}" data-ip="{{ .IP }}" data-country="{{ .Country }}" data-score="{{ .Score }}">
                <td>{{ .Country }}</td>
                <td>{{ printf "%.2f" .SpeedMbps }}</td>
                <td>{{ .Ping }} ms</td>
                <td id="ping-cell-{{ .IP }}">
                    {{ $p := index $.PingResults .IP }}
                    {{ if $p.IP }}
                        {{ if $p.Reachable }}
                            <span class="good">{{ $p.LatencyMs }} ms</span> <span class="stat-sub">({{ $p.Method }})</span>
                        {{ else }}
                            <span class="bad">Offline</span>
                        {{ end }}
                    {{ else }}
                        <span class="muted">Not tested</span>
                    {{ end }}
                </td>
                <td>{{ .Score }}</td>
                <td>{{ .IP }}</td>
                <td>
                    {{ $h := index $.History .IP }}
                    {{ if $h.ExitIP }}
                        <span class="{{ if eq $h.ExitIP .IP }}good{{ else }}warn{{ end }}">{{ $h.ExitIP }}</span>
                        <div class="stat-sub">{{ $h.Place }} &middot; {{ $h.Age }}</div>
                    {{ else }}
                        <span class="muted">not checked yet</span>
                    {{ end }}
                </td>
                <td>
                    <div class="action-group">
                        <button class="btn btn-yellow btn-sm ping-row-btn" onclick="pingSingleServer('{{ .IP }}', '{{ .Proto }}', {{ .Port }}, this)">Ping</button>
                        <button class="btn btn-sm connect-btn" onclick="connectVPNGate('{{ .IP }}', '{{ .Country }}', '{{ .ConfigB64 }}')">Connect</button>
                    </div>
                </td>
            </tr>
            {{ end }}
        </tbody>
        {{ end }}
    </table>

    <script>
        const pingCache = {};
        {{ range $ip, $p := .PingResults }}
        pingCache['{{ $ip }}'] = {
            ip: '{{ $ip }}',
            reachable: {{ $p.Reachable }},
            latencyMs: {{ $p.LatencyMs }},
            method: '{{ $p.Method }}'
        };
        {{ end }}

        function showBanner(text, type) {
            const b = document.getElementById('banner');
            b.className = type || '';
            b.textContent = text;
            b.style.display = 'block';
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function setAllButtonsDisabled(disabled) {
            document.querySelectorAll('button').forEach(btn => btn.disabled = disabled);
        }

        function sortCountryTbody(tbody) {
            const rows = Array.from(tbody.querySelectorAll('tr.server-row'));
            rows.sort((a, b) => {
                const ipA = a.dataset.ip;
                const ipB = b.dataset.ip;
                const pA = pingCache[ipA];
                const pB = pingCache[ipB];

                // State: 1 = reachable (available), 2 = unpinged, 3 = offline
                const getState = (p) => {
                    if (!p) return 2;
                    if (p.reachable) return 1;
                    return 3;
                };

                const sa = getState(pA);
                const sb = getState(pB);

                if (sa !== sb) {
                    return sa - sb;
                }
                const scoreA = parseInt(a.dataset.score || '0', 10);
                const scoreB = parseInt(b.dataset.score || '0', 10);
                if (scoreA !== scoreB) {
                    return scoreB - scoreA;
                }
                if (sa === 1 && pA && pB && pA.latencyMs !== pB.latencyMs) {
                    return pA.latencyMs - pB.latencyMs;
                }
                return 0;
            });
            rows.forEach(r => tbody.appendChild(r));
        }

        async function switchMode(mode) {
            setAllButtonsDisabled(true);
            showBanner(mode === 'gce'
                ? 'Establishing encrypted SSH tunnel to Google Cloud VM ({{ .GCEHost }})...'
                : 'Switching to Direct (Local ISP) and stopping background tunnels...', '');
            try {
                const res = await fetch('/api/mode', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mode })
                });
                const data = await res.json();
                if (!res.ok || !data.ok) {
                    showBanner('Error: ' + (data.error || 'Failed to switch mode'), 'error');
                    setAllButtonsDisabled(false);
                    return;
                }
                showBanner(data.message || 'Switched successfully! Reloading status...', 'success');
                setTimeout(() => window.location.href = '/', 600);
            } catch (e) {
                showBanner('Network error: ' + e.message, 'error');
                setAllButtonsDisabled(false);
            }
        }

        async function connectVPNGate(ip, country, b64) {
            setAllButtonsDisabled(true);
            showBanner('Starting Gluetun & connecting to VPNGate server ' + ip + ' (' + country + '). Fail-closed active; this takes ~10-30s...', '');
            try {
                const res = await fetch('/api/connect-vpngate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, country, b64 })
                });
                const data = await res.json();
                if (!res.ok || !data.ok) {
                    showBanner('Error: ' + (data.error || 'Failed to connect'), 'error');
                    setAllButtonsDisabled(false);
                    return;
                }
                showBanner(data.message, 'success');
                setTimeout(() => window.location.href = '/', 800);
            } catch (e) {
                showBanner('Request error: ' + e.message, 'error');
                setAllButtonsDisabled(false);
            }
        }

        function renderPingCell(ip, r) {
            const cell = document.getElementById('ping-cell-' + ip);
            if (!cell) return;
            if (r.reachable) {
                cell.innerHTML = '<span class="good">' + r.latencyMs + ' ms</span> <span class="stat-sub">(' + r.method + ')</span>';
            } else {
                cell.innerHTML = '<span class="bad">Offline</span>';
            }
        }

        async function pingSingleServer(ip, proto, port, btn) {
            const origText = btn.textContent;
            btn.disabled = true;
            btn.textContent = '...';
            const cell = document.getElementById('ping-cell-' + ip);
            if (cell) cell.innerHTML = '<span class="warn">Pinging...</span>';
            try {
                const res = await fetch('/api/ping', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, proto, port })
                });
                const data = await res.json();
                pingCache[ip] = data;
                renderPingCell(ip, data);
                const row = document.getElementById('row-' + ip);
                if (row) {
                    const tbody = row.closest('tbody.country-tbody');
                    if (tbody) sortCountryTbody(tbody);
                }
            } catch (e) {
                if (cell) cell.innerHTML = '<span class="bad">Error</span>';
            } finally {
                btn.disabled = false;
                btn.textContent = origText;
            }
        }

        async function pingCountry(country, btn) {
            const tbodies = Array.from(document.querySelectorAll('tbody.country-tbody'));
            const tbody = tbodies.find(b => b.dataset.country === country);
            if (!tbody) return;
            const origText = btn.textContent;
            btn.disabled = true;
            btn.textContent = '⏳ Pinging...';
            tbody.querySelectorAll('[id^="ping-cell-"]').forEach(el => {
                el.innerHTML = '<span class="warn">Probing...</span>';
            });
            try {
                const res = await fetch('/api/ping-country', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ country })
                });
                const data = await res.json();
                if (data.results) {
                    Object.values(data.results).forEach(r => {
                        pingCache[r.ip] = r;
                        renderPingCell(r.ip, r);
                    });
                    sortCountryTbody(tbody);
                }
            } catch (e) {
                showBanner('Ping ' + country + ' failed: ' + e.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = origText;
            }
        }

        async function pingAllServers() {
            const btn = document.getElementById('pingAllBtn');
            const origText = btn.textContent;
            btn.disabled = true;
            btn.textContent = '⏳ Pinging all servers (up to 5s)...';
            document.querySelectorAll('[id^="ping-cell-"]').forEach(el => {
                el.innerHTML = '<span class="warn">Probing...</span>';
            });
            try {
                const res = await fetch('/api/ping-all', { method: 'POST' });
                const data = await res.json();
                if (data.results) {
                    Object.values(data.results).forEach(r => {
                        pingCache[r.ip] = r;
                        renderPingCell(r.ip, r);
                    });
                    document.querySelectorAll('tbody.country-tbody').forEach(tbody => {
                        sortCountryTbody(tbody);
                    });
                }
            } catch (e) {
                showBanner('Ping All failed: ' + e.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = origText;
            }
        }
    </script>
</body>
</html>`

func formatDurationShort(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	mins := secs / 60
	if mins < 60 {
		return fmt.Sprintf("%dm %ds", mins, secs%60)
	}
	hrs := mins / 60
	return fmt.Sprintf("%dh %dm", hrs, mins%60)
}

func setupWebRoutes(c *Controller) http.Handler {
	tmpl := template.Must(template.New("index").Parse(htmlTemplate))
	mux := http.NewServeMux()

	// Main Web UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		forceServers := r.URL.Query().Get("refresh_servers") == "1"
		forceIPs := r.URL.Query().Get("refresh_ips") == "1"

		servers, cacheAge, _ := c.getServers(forceServers)
		exitInfo, homeInfo, _ := c.refreshIPStatus(forceIPs)

		c.mu.RLock()
		activeMode := c.activeMode
		vpngateIP := c.vpngateServerIP
		vpngateCountry := c.vpngateCountry
		c.mu.RUnlock()

		c.pingResultsMu.RLock()
		pingCopy := make(map[string]PingResult, len(c.pingResults))
		for k, v := range c.pingResults {
			pingCopy[k] = v
		}
		c.pingResultsMu.RUnlock()

		countryGroups := groupServersByCountry(servers, pingCopy)

		hostIP := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil && h != "" {
			hostIP = h
		}

		data := map[string]interface{}{
			"BuildTime":      getBuildTime(),
			"HostIP":         hostIP,
			"WebPort":        webPort,
			"ProxyPort":      proxyPort,
			"GCEHost":        gceHost,
			"ActiveMode":     activeMode,
			"VPNGateIP":      vpngateIP,
			"VPNGateCountry": vpngateCountry,
			"ExitInfo":       exitInfo,
			"HomeInfo":       homeInfo,
			"IdleRemaining":  formatDurationShort(c.remainingIdleDuration()),
			"CountryGroups":  countryGroups,
			"TotalServers":   len(servers),
			"ServerCacheAge": formatDurationShort(cacheAge),
			"PingResults":    pingCopy,
			"History":        c.loadExitHistory(),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	})

	// PAC (Proxy Auto-Config) file for iOS / Android / Windows / macOS
	mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		hostIP := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil && h != "" {
			hostIP = h
		}
		pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "100.64.0.0", "255.192.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    return "PROXY %s:%s; DIRECT";
}
`, hostIP, proxyPort)
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		_, _ = w.Write([]byte(pac))
	})

	// JSON Status API
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		c.mu.RLock()
		mode := c.activeMode
		transitioning := c.isTransitioning
		vpngateIP := c.vpngateServerIP
		vpngateCountry := c.vpngateCountry
		c.mu.RUnlock()

		exitInfo, homeInfo, _ := c.refreshIPStatus(false)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":              true,
			"buildTime":       getBuildTime(),
			"activeMode":      mode,
			"isTransitioning": transitioning,
			"vpngateIP":       vpngateIP,
			"vpngateCountry":  vpngateCountry,
			"exitInfo":        exitInfo,
			"homeInfo":        homeInfo,
			"idleRemaining":   formatDurationShort(c.remainingIdleDuration()),
		})
	})

	// Switch Mode (Direct Local ISP or GCE SSH Tunnel)
	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Mode {
		case ModeNUC:
			if err := c.SwitchToNUC(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":      true,
				"message": "Switched to Direct (Local ISP). Background VPN/SSH tunnels stopped.",
			})
		case ModeGCE:
			if err := c.SwitchToGCE(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
				return
			}
			exitInfo, _, _ := c.refreshIPStatus(false)
			exitStr := gceHost
			if exitInfo != nil {
				exitStr = fmt.Sprintf("%s (%s)", exitInfo.IP, exitInfo.Place)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":      true,
				"message": fmt.Sprintf("Connected to Google Cloud VM! Proxy now exits at %s.", exitStr),
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "Unsupported mode"})
		}
	})

	// Connect VPNGate Server
	mux.HandleFunc("/api/connect-vpngate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			B64     string `json:"b64"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := c.SwitchToVPNGate(req.IP, req.Country, req.B64); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		exitInfo, _, _ := c.refreshIPStatus(false)
		msg := fmt.Sprintf("Connected to VPNGate %s (%s)!", req.IP, req.Country)
		if exitInfo != nil {
			msg = fmt.Sprintf("Connected to VPNGate %s! Websites now see %s (%s).", req.IP, exitInfo.IP, exitInfo.Place)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"message": msg,
		})
	})

	// Single Server Ping
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP    string `json:"ip"`
			Proto string `json:"proto"`
			Port  int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res := probeSingleServer(req.IP, req.Proto, req.Port)
		c.pingResultsMu.Lock()
		c.pingResults[req.IP] = res
		c.pingResultsMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})

	// Ping Country Servers (Concurrent)
	mux.HandleFunc("/api/ping-country", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Country string `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		servers, _, err := c.getServers(false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var targetServers []VPNServer
		for _, s := range servers {
			if s.Country == req.Country {
				targetServers = append(targetServers, s)
			}
		}

		results := make(map[string]PingResult, len(targetServers))
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 25)

		for _, srv := range targetServers {
			wg.Add(1)
			go func(s VPNServer) {
				defer wg.Done()
				sem <- struct{}{}
				res := probeSingleServer(s.IP, s.Proto, s.Port)
				<-sem
				mu.Lock()
				results[s.IP] = res
				mu.Unlock()
			}(srv)
		}
		wg.Wait()

		c.pingResultsMu.Lock()
		for k, v := range results {
			c.pingResults[k] = v
		}
		c.pingResultsMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"results": results,
		})
	})

	// Ping All Servers (Concurrent, No Re-Sort)
	mux.HandleFunc("/api/ping-all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		servers, _, err := c.getServers(false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		results := make(map[string]PingResult, len(servers))
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 35) // concurrency limiter

		for _, srv := range servers {
			wg.Add(1)
			go func(s VPNServer) {
				defer wg.Done()
				sem <- struct{}{}
				res := probeSingleServer(s.IP, s.Proto, s.Port)
				<-sem
				mu.Lock()
				results[s.IP] = res
				mu.Unlock()
			}(srv)
		}
		wg.Wait()

		c.pingResultsMu.Lock()
		for k, v := range results {
			c.pingResults[k] = v
		}
		c.pingResultsMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"results": results,
		})
	})

	// Suppress unused import warning for url package if any
	_ = url.PathEscape

	return mux
}

func startWebServer(c *Controller) {
	mux := setupWebRoutes(c)
	addr := ":" + webPort
	log.Printf("[WEB] Starting Web Dashboard on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[WEB] Fatal error on %s: %v", addr, err)
	}
}

func ensureStandbyCustomConf() {
	confPath := filepath.Join(dataDir, "custom.conf")
	info, err := os.Stat(confPath)
	if os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		standby := "# my-vpn-2 standby configuration for Gluetun\nclient\ndev tun\nproto udp\nremote 127.0.0.1 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nverb 1\n"
		if err := os.WriteFile(confPath, []byte(standby), 0644); err == nil {
			log.Println("[CONFIG] Initialized valid standby custom.conf for Gluetun.")
		}
	}
}

func main() {
	_ = os.MkdirAll(dataDir, 0755)
	_ = os.RemoveAll(filepath.Join(dataDir, "auth"))
	ensureStandbyCustomConf()
	ctrl := NewController()

	// Ensure default startup state: Direct (Local ISP) (stop Gluetun if running)
	stopGluetunContainer()
	ctrl.startInactivityWatchdog()

	// Pre-warm IP check & server list in background
	go func() {
		_, _, _ = ctrl.getServers(true)
		ctrl.refreshIPStatus(true)
	}()

	go startProxyServer(ctrl)
	startWebServer(ctrl)
}
