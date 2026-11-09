package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestPAC verifies that the /proxy.pac endpoint returns valid PAC scripts
func TestPAC(t *testing.T) {
	ctrl := NewController()
	handler := setupWebRoutes(ctrl)

	req := httptest.NewRequest("GET", "http://192.168.1.50:8080/proxy.pac", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "function FindProxyForURL") {
		t.Errorf("expected PAC function definition, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "PROXY 192.168.1.50:"+proxyPort) {
		t.Errorf("expected proxy host/port in PAC, got: %s", bodyStr)
	}
}

// TestWebUIHeader verifies that the web dashboard renders with the build time badge
func TestWebUIHeader(t *testing.T) {
	ctrl := NewController()
	handler := setupWebRoutes(ctrl)

	req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Build: ") {
		t.Errorf("expected 'Build: ' in web header HTML, got: %s", bodyStr)
	}
}

// TestAPIStatus verifies that /api/status returns the correct JSON payload
func TestAPIStatus(t *testing.T) {
	ctrl := NewController()
	handler := setupWebRoutes(ctrl)

	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed decoding JSON: %v", err)
	}

	if data["activeMode"] != ModeNUC {
		t.Errorf("expected activeMode %s, got %v", ModeNUC, data["activeMode"])
	}
	if data["ok"] != true {
		t.Errorf("expected ok: true, got %v", data["ok"])
	}
	if data["buildTime"] == nil || data["buildTime"] == "" {
		t.Errorf("expected non-empty buildTime, got %v", data["buildTime"])
	}
}

// TestAPIModeSwitchNUC verifies switching back to Direct ISP mode
func TestAPIModeSwitchNUC(t *testing.T) {
	ctrl := NewController()
	handler := setupWebRoutes(ctrl)

	body := bytes.NewBufferString(`{"mode":"nuc"}`)
	req := httptest.NewRequest("POST", "/api/mode", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed decoding JSON: %v", err)
	}
	if data["ok"] != true {
		t.Errorf("expected ok: true, got %v", data["ok"])
	}
}

// TestPrivateIPWhitelist checks that private LAN / Tailscale subnets are allowed and public IPs blocked
func TestPrivateIPWhitelist(t *testing.T) {
	tests := []struct {
		ip      string
		allowed bool
	}{
		{"127.0.0.1:54321", true},
		{"10.0.0.5:12345", true},
		{"172.16.0.1:443", true},
		{"192.168.1.100:8888", true},
		{"100.64.0.1:9999", true},   // Tailscale CGNAT
		{"8.8.8.8:12345", false},     // Public IP
		{"1.1.1.1:80", false},        // Public IP
		{"203.0.113.50:5000", false}, // Public IP
	}

	for _, tt := range tests {
		if got := isPrivateIP(tt.ip); got != tt.allowed {
			t.Errorf("isPrivateIP(%s) = %v; expected %v", tt.ip, got, tt.allowed)
		}
	}
}

// TestOpenVPNConfigBuilder verifies that buildOpenVPNConfig correctly appends cipher compatibility
func TestOpenVPNConfigBuilder(t *testing.T) {
	rawConf := "client\ndev tun\nproto udp\nremote 1.2.3.4 1194\nresolv-retry infinite\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(rawConf))

	built, err := buildOpenVPNConfig(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(built, "data-ciphers AES-256-GCM") {
		t.Errorf("expected data-ciphers in built config, got:\n%s", built)
	}
	if !strings.Contains(built, "remote 1.2.3.4 1194") {
		t.Errorf("expected original remote line in built config, got:\n%s", built)
	}
}

// TestFailClosedProtection ensures proxy drops traffic during mode transitions
func TestFailClosedProtection(t *testing.T) {
	ctrl := NewController()
	ctrl.mu.Lock()
	ctrl.isTransitioning = true
	ctrl.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ctrl.dialUpstream(ctx, "tcp", "1.1.1.1:80")
	if err == nil {
		t.Fatal("expected fail-closed error, got nil")
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Errorf("expected 'fail-closed' in error message, got: %v", err)
	}
}

// TestDirectProxying tests proxying an HTTP request through goproxy in ModeNUC
func TestDirectProxying(t *testing.T) {
	// Target backend server
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "Hello-From-Target")
		_, _ = w.Write([]byte("Target response payload"))
	}))
	defer targetSrv.Close()

	ctrl := NewController()
	proxyHandler := setupProxyHandler(ctrl)

	proxySrv := httptest.NewServer(proxyHandler)
	defer proxySrv.Close()

	// Client using proxy
	proxyURL, err := url.Parse(proxySrv.URL)
	if err != nil {
		t.Fatalf("failed parsing proxy url: %v", err)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	resp, err := client.Get(targetSrv.URL)
	if err != nil {
		t.Fatalf("failed proxying request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Test-Header") != "Hello-From-Target" {
		t.Errorf("expected X-Test-Header, got: %s", resp.Header.Get("X-Test-Header"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Target response payload" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

// TestProxyBlockedForPublicIP verifies that public remote addresses are forbidden
func TestProxyBlockedForPublicIP(t *testing.T) {
	ctrl := NewController()
	handler := setupProxyHandler(ctrl)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:12345" // Public IP
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for public IP, got %d", resp.StatusCode)
	}
}

// TestMockGCESSHServer tests the GCE SSH tunnel mode by launching a local mock SSH server
func TestMockGCESSHServer(t *testing.T) {
	// 1. Generate temporary SSH key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating RSA key: %v", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_id_rsa")
	if err := os.WriteFile(keyPath, privKeyPEM, 0600); err != nil {
		t.Fatalf("failed writing test key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privKeyPEM)
	if err != nil {
		t.Fatalf("failed parsing private key: %v", err)
	}

	// 2. Start mock SSH server
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil // Accept client key
		},
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed starting SSH listener: %v", err)
	}
	defer listener.Close()

	// Target backend server to be reached through SSH dial
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("gce-tunnel-ok"))
	}))
	defer backend.Close()

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sConn, chans, reqs, err := ssh.NewServerConn(c, sshConfig)
				if err != nil {
					return
				}
				defer sConn.Close()
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "direct-tcpip" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					var d struct {
						DestAddr string
						DestPort uint32
						OrigAddr string
						OrigPort uint32
					}
					_ = ssh.Unmarshal(newChannel.ExtraData(), &d)
					dest := fmt.Sprintf("%s:%d", d.DestAddr, d.DestPort)
					upstream, err := net.Dial("tcp", dest)
					if err != nil {
						_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					ch, reqs2, err := newChannel.Accept()
					if err != nil {
						upstream.Close()
						continue
					}
					go ssh.DiscardRequests(reqs2)
					go func() {
						defer ch.Close()
						defer upstream.Close()
						_, _ = io.Copy(ch, upstream)
					}()
					go func() {
						defer ch.Close()
						defer upstream.Close()
						_, _ = io.Copy(upstream, ch)
					}()
				}
			}(nConn)
		}
	}()

	// 3. Configure Controller to use mock SSH server
	origHost, origKey, origUser := gceHost, gceKeyPath, gceUser
	defer func() {
		gceHost, gceKeyPath, gceUser = origHost, origKey, origUser
	}()

	gceHost = listener.Addr().String()
	gceKeyPath = keyPath
	gceUser = "mock-user"

	ctrl := NewController()
	if err := ctrl.SwitchToGCE(); err != nil {
		t.Fatalf("SwitchToGCE failed: %v", err)
	}

	if ctrl.activeMode != ModeGCE {
		t.Fatalf("expected mode %s, got %s", ModeGCE, ctrl.activeMode)
	}

	// 4. Test proxying through the mock GCE SSH tunnel
	conn, err := ctrl.dialUpstream(context.Background(), "tcp", backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed dialing backend through SSH tunnel: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed reading from SSH proxied conn: %v", err)
	}
	if !strings.Contains(string(respBytes), "gce-tunnel-ok") {
		t.Errorf("expected 'gce-tunnel-ok' through GCE SSH tunnel, got: %s", string(respBytes))
	}

	// 5. Test reverting to NUC closes SSH
	if err := ctrl.SwitchToNUC(); err != nil {
		t.Fatalf("SwitchToNUC failed: %v", err)
	}
	if ctrl.activeMode != ModeNUC {
		t.Fatalf("expected mode %s, got %s", ModeNUC, ctrl.activeMode)
	}
}

// TestMockDockerGluetunLifecycle tests Gluetun container start/restart and health check handling via mock Docker socket
func TestMockDockerGluetunLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "docker.sock")

	// 1. Mock Gluetun HTTP proxy
	gluetunBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			// Connect proxy simulation
			w.WriteHeader(http.StatusOK)
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				defer conn.Close()
				_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				targetConn, err := net.Dial("tcp", r.URL.Host)
				if err == nil {
					defer targetConn.Close()
					go func() { _, _ = io.Copy(targetConn, conn) }()
					_, _ = io.Copy(conn, targetConn)
				}
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("gluetun-proxy-response"))
	}))
	defer gluetunBackend.Close()

	// 2. Mock Docker Unix Socket HTTP API
	dockerListener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed listening on mock unix socket: %v", err)
	}
	defer dockerListener.Close()

	var startedCount int
	var stoppedCount int

	dockerMux := http.NewServeMux()
	dockerMux.HandleFunc("/containers/"+gluetunContainer+"/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"State": map[string]interface{}{
				"Running": startedCount > stoppedCount,
				"Health": map[string]interface{}{
					"Status": "healthy",
				},
			},
		})
	})
	dockerMux.HandleFunc("/containers/"+gluetunContainer+"/start", func(w http.ResponseWriter, r *http.Request) {
		startedCount++
		w.WriteHeader(http.StatusNoContent)
	})
	dockerMux.HandleFunc("/containers/"+gluetunContainer+"/restart", func(w http.ResponseWriter, r *http.Request) {
		startedCount++
		w.WriteHeader(http.StatusNoContent)
	})
	dockerMux.HandleFunc("/containers/"+gluetunContainer+"/stop", func(w http.ResponseWriter, r *http.Request) {
		stoppedCount++
		w.WriteHeader(http.StatusNoContent)
	})

	dockerServer := &http.Server{Handler: dockerMux}
	go func() { _ = dockerServer.Serve(dockerListener) }()
	defer dockerServer.Close()

	// 3. Patch global envs for test
	origSock := dockerSockPath
	origData := dataDir
	origGluetun := gluetunProxyAddr
	defer func() {
		dockerSockPath = origSock
		dataDir = origData
		gluetunProxyAddr = origGluetun
	}()

	dockerSockPath = sockPath
	dataDir = tmpDir
	gluetunProxyAddr = strings.TrimPrefix(gluetunBackend.URL, "http://")

	// Verify inspectGluetunHealth initially stopped
	running, status := inspectGluetunHealth()
	if running {
		t.Errorf("expected running false, got %v (status: %s)", running, status)
	}

	// Verify startOrRestartGluetun
	if err := startOrRestartGluetun(); err != nil {
		t.Fatalf("startOrRestartGluetun failed: %v", err)
	}
	running, status = inspectGluetunHealth()
	if !running || status != "healthy" {
		t.Errorf("expected running true and healthy, got running=%v, status=%s", running, status)
	}

	// Verify stopGluetunContainer
	stopGluetunContainer()
	running, _ = inspectGluetunHealth()
	if running {
		t.Errorf("expected running false after stop, got %v", running)
	}
}

// TestCountryGroupingAndSorting checks that VPN servers are properly grouped by country and sorted by availability & score
func TestCountryGroupingAndSorting(t *testing.T) {
	servers := []VPNServer{
		{IP: "1.1.1.1", Country: "Japan", Score: 100},
		{IP: "1.1.1.2", Country: "Japan", Score: 500},
		{IP: "2.2.2.1", Country: "United States", Score: 200},
		{IP: "3.3.3.1", Country: "Japan", Score: 300},
	}

	pingResults := map[string]PingResult{
		"1.1.1.1": {IP: "1.1.1.1", Reachable: true, LatencyMs: 50},
		"1.1.1.2": {IP: "1.1.1.2", Reachable: false, LatencyMs: -1}, // offline
		"3.3.3.1": {IP: "3.3.3.1", Reachable: true, LatencyMs: 20},  // reachable
	}

	groups := groupServersByCountry(servers, pingResults)
	if len(groups) != 2 {
		t.Fatalf("expected 2 country groups, got %d", len(groups))
	}

	// Japan should be first because it has 3 servers vs United States 1
	if groups[0].Country != "Japan" || groups[0].ServerCount != 3 {
		t.Errorf("expected first group to be Japan with 3 servers, got %s (%d)", groups[0].Country, groups[0].ServerCount)
	}

	// Within Japan: Reachable servers first (3.3.3.1, 1.1.1.1), then unpinged, then offline (1.1.1.2)
	japanServers := groups[0].Servers
	if japanServers[0].IP != "3.3.3.1" || japanServers[1].IP != "1.1.1.1" || japanServers[2].IP != "1.1.1.2" {
		t.Errorf("unexpected sorting within Japan: %+v", japanServers)
	}
}
