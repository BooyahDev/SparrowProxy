package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"gopkg.in/yaml.v3"
)

type Config struct {
	TLS       []TLSCert      `yaml:"tls"`
	Services  []Service      `yaml:"services"`
	Redirects []RedirectRule `yaml:"redirects"`
	HTTP      Listener       `yaml:"http"`
	HTTPS     Listener       `yaml:"https"`
}

type Listener struct {
	Addr string `yaml:"addr"`
}

type TLSCert struct {
	SNIHosts []string `yaml:"sni_hosts"`
	CertPEM  string   `yaml:"cert_pem"`
	KeyPEM   string   `yaml:"key_pem"`
	CertB64  string   `yaml:"cert_b64"`
	KeyB64   string   `yaml:"key_b64"`
	CertPath string   `yaml:"cert_path"`
	KeyPath  string   `yaml:"key_path"`
}

type Service struct {
	Name           string     `yaml:"name"`
	Hosts          []string   `yaml:"hosts"`
	Routes         []string   `yaml:"routes"`
	Upstreams      []Upstream `yaml:"upstreams"`
	HealthCheck    Health     `yaml:"health_check"`
	PassHostHeader *bool      `yaml:"pass_host_header"`
}

type Upstream struct {
	URL string `yaml:"url"`
}

type Health struct {
	Path     string        `yaml:"path"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

type RedirectRule struct {
	FromHost   string `yaml:"from_host"`
	To         string `yaml:"to"`
	StatusCode int    `yaml:"status_code"`
}

type StatsResponse struct {
	Status          string `json:"status"`
	TotalRequests   uint64 `json:"total_requests"`
	SuccessRequests uint64 `json:"success_requests"`
	FailRequests    uint64 `json:"fail_requests"`
	Uptime          string `json:"uptime"`
}

type backend struct {
	target *url.URL
	alive  atomic.Bool
}

type lb struct {
	name     string
	backends []*backend
	idx      atomic.Uint32
}

func newLB(name string, ups []Upstream) (*lb, error) {
	if len(ups) == 0 {
		return nil, errors.New("no upstreams")
	}
	bks := make([]*backend, 0, len(ups))
	for _, u := range ups {
		pu, err := url.Parse(u.URL)
		if err != nil {
			return nil, fmt.Errorf("parse upstream: %w", err)
		}
		b := &backend{target: pu}
		b.alive.Store(true)
		bks = append(bks, b)
	}
	return &lb{name: name, backends: bks}, nil
}

func (l *lb) nextAlive() *backend {
	n := uint32(len(l.backends))
	for i := uint32(0); i < n; i++ {
		idx := l.idx.Add(1)
		b := l.backends[idx%n]
		if b.alive.Load() {
			return b
		}
	}
	return l.backends[0]
}

type proxyServer struct {
	mu              sync.RWMutex
	cfg             *Config
	lbs             map[string]*lb
	certMap         map[string]*tls.Certificate
	defaultCert     *tls.Certificate
	startTime       time.Time
	totalRequests   atomic.Uint64
	successRequests atomic.Uint64
	failRequests    atomic.Uint64
	configRepoURL   string
	configRepoPath  string
}

type configSyncer struct {
	repoURL  string
	repoPath string
	mu       sync.Mutex
}

func newConfigSyncer(repoURL, repoPath string) *configSyncer {
	return &configSyncer{
		repoURL:  repoURL,
		repoPath: repoPath,
	}
}

func (cs *configSyncer) setupHTTPAuth() (*githttp.BasicAuth, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is not set")
	}

	// GitHub Personal Access Tokenを使用したHTTPS認証
	auth := &githttp.BasicAuth{
		Username: "git", // GitHubの場合、usernameは任意の値でよい
		Password: token,
	}

	log.Printf("Using HTTPS authentication with Personal Access Token")
	return auth, nil
}

func (cs *configSyncer) syncRepo() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	auth, err := cs.setupHTTPAuth()
	if err != nil {
		return fmt.Errorf("HTTP auth setup failed: %w", err)
	}

	// Check if repository already exists
	if _, err := os.Stat(cs.repoPath); os.IsNotExist(err) {
		// Clone repository
		log.Printf("Cloning config repository from %s to %s", cs.repoURL, cs.repoPath)
		_, err := git.PlainClone(cs.repoPath, false, &git.CloneOptions{
			URL:      cs.repoURL,
			Auth:     auth,
			Progress: os.Stdout,
		})
		if err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}
		log.Printf("Successfully cloned config repository")
		return nil
	}

	// Open existing repository
	repo, err := git.PlainOpen(cs.repoPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	// Get working tree
	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Get current head before pull
	ref, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}
	oldHash := ref.Hash()

	// Pull latest changes
	err = worktree.Pull(&git.PullOptions{
		Auth:         auth,
		RemoteName:   "origin",
		SingleBranch: true,
	})

	if err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("failed to pull repository: %w", err)
	}

	// Check if there were changes
	newRef, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get new HEAD: %w", err)
	}
	newHash := newRef.Hash()

	if oldHash != newHash {
		log.Printf("Repository updated from %s to %s", oldHash.String()[:8], newHash.String()[:8])
		return nil
	}

	if err == git.NoErrAlreadyUpToDate {
		log.Printf("Repository is already up to date")
	}

	return nil
}

func (cs *configSyncer) startPeriodicSync(ctx context.Context, interval time.Duration, callback func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial sync
	if err := cs.syncRepo(); err != nil {
		log.Printf("Initial config sync failed: %v", err)
	} else if callback != nil {
		callback()
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("Stopping config sync")
			return
		case <-ticker.C:
			if err := cs.syncRepo(); err != nil {
				log.Printf("Config sync failed: %v", err)
			} else if callback != nil {
				callback()
			}
		}
	}
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.HTTP.Addr == "" {
		c.HTTP.Addr = ":80"
	}
	if c.HTTPS.Addr == "" {
		c.HTTPS.Addr = ":443"
	}
	return &c, nil
}

func (p *proxyServer) loadConfigFromRepo() error {
	configPath := filepath.Join(p.configRepoPath, "config.yaml")

	// Check if config file exists in the synced repository
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config.yaml not found in repository: %s", configPath)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config from repository: %w", err)
	}

	// Update certificate paths to point to the synced repository
	for i := range cfg.TLS {
		if cfg.TLS[i].CertPath != "" && !filepath.IsAbs(cfg.TLS[i].CertPath) {
			cfg.TLS[i].CertPath = filepath.Join(p.configRepoPath, cfg.TLS[i].CertPath)
		}
		if cfg.TLS[i].KeyPath != "" && !filepath.IsAbs(cfg.TLS[i].KeyPath) {
			cfg.TLS[i].KeyPath = filepath.Join(p.configRepoPath, cfg.TLS[i].KeyPath)
		}
	}

	if err := p.applyConfig(cfg); err != nil {
		return fmt.Errorf("failed to apply config from repository: %w", err)
	}

	log.Printf("Successfully loaded and applied config from repository")
	return nil
}

func (p *proxyServer) applyConfig(c *Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cfg = c

	p.lbs = make(map[string]*lb)
	for i := range c.Services {
		s := &c.Services[i]
		l, err := newLB(s.Name, s.Upstreams)
		if err != nil {
			return err
		}
		p.lbs[s.Name] = l
	}

	p.certMap = make(map[string]*tls.Certificate)
	var defaultSet bool
	for _, tc := range c.TLS {
		cert, err := materializeCert(tc)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		for _, h := range tc.SNIHosts {
			ch := h
			p.certMap[strings.ToLower(ch)] = cert
		}
		if !defaultSet {
			p.defaultCert = cert
			defaultSet = true
		}
	}
	return nil
}

func materializeCert(tc TLSCert) (*tls.Certificate, error) {
	var certPEM, keyPEM []byte
	switch {
	case tc.CertPEM != "" && tc.KeyPEM != "":
		certPEM = []byte(tc.CertPEM)
		keyPEM = []byte(tc.KeyPEM)
	case tc.CertB64 != "" && tc.KeyB64 != "":
		var err error
		certPEM, err = base64.StdEncoding.DecodeString(tc.CertB64)
		if err != nil {
			return nil, err
		}
		keyPEM, err = base64.StdEncoding.DecodeString(tc.KeyB64)
		if err != nil {
			return nil, err
		}
	case tc.CertPath != "" && tc.KeyPath != "":
		var err error
		certPEM, err = os.ReadFile(tc.CertPath)
		if err != nil {
			return nil, err
		}
		keyPEM, err = os.ReadFile(tc.KeyPath)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid TLS cert source")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (p *proxyServer) matchService(host, path string) *Service {
	p.mu.RLock()
	defer p.mu.RUnlock()
	host = strings.ToLower(host)
	for i := range p.cfg.Services {
		s := &p.cfg.Services[i]
		if !containsHost(s.Hosts, host) {
			continue
		}
		if len(s.Routes) == 0 {
			return s
		}
		for _, pr := range s.Routes {
			if strings.HasPrefix(path, pr) {
				return s
			}
		}
	}
	return nil
}

func containsHost(list []string, h string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), h) {
			return true
		}
	}
	return false
}

func (p *proxyServer) directorFor(s *Service) func(*http.Request) {
	passHost := true
	if s.PassHostHeader != nil {
		passHost = *s.PassHostHeader
	}

	return func(r *http.Request) {
		lb := p.lbs[s.Name]
		b := lb.nextAlive()

		r.URL.Scheme = b.target.Scheme
		r.URL.Host = b.target.Host

		if !passHost {
			r.Host = b.target.Host
			r.Header.Set("Host", b.target.Host)
		}

		// X-Forwarded
		r.Header.Set("X-Forwarded-Proto", protoFromTLS(r))
		r.Header.Set("X-Forwarded-Host", r.Host)
		r.Header.Add("X-Forwarded-For", clientIP(r))
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func protoFromTLS(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func (p *proxyServer) transport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (p *proxyServer) makeProxy(s *Service) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Director:  p.directorFor(s),
		Transport: p.transport(),
		ModifyResponse: func(res *http.Response) error {
			// プロトコルバージョンを動的に判定してViaヘッダーを設定
			protoVersion := "1.1"
			if res.ProtoMajor == 2 {
				protoVersion = "2"
			}
			viaValue := fmt.Sprintf("%s SparrowProxy/0.0.1", protoVersion)
			res.Header.Set("Via", viaValue)

			// 成功・失敗の統計更新
			if res.StatusCode >= 200 && res.StatusCode < 400 {
				p.successRequests.Add(1)
			} else {
				p.failRequests.Add(1)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.failRequests.Add(1)
			log.Printf("proxy error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
		FlushInterval: 50 * time.Millisecond,
	}
	return rp
}

func (p *proxyServer) startHealthChecks(ctx context.Context) {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()
	hc := &http.Client{Timeout: 2 * time.Second}
	for i := range cfg.Services {
		s := &cfg.Services[i]
		path := s.HealthCheck.Path
		if path == "" {
			path = "/healthz"
		}
		interval := s.HealthCheck.Interval
		if interval == 0 {
			interval = 5 * time.Second
		}
		timeout := s.HealthCheck.Timeout
		if timeout == 0 {
			timeout = 1 * time.Second
		}

		clent := &http.Client{Timeout: timeout}
		lb := p.lbs[s.Name]

		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					for _, b := range lb.backends {
						u := *b.target
						u.Path = path
						ok := checkOnce(clent, u.String())
						b.alive.Store(ok)
					}
				}
			}
		}()
	}
	_ = hc
}

func checkOnce(c *http.Client, url string) bool {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (p *proxyServer) httpRedirectMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		for _, rr := range p.cfg.Redirects {
			if strings.EqualFold(rr.FromHost, host) {
				code := rr.StatusCode
				if code == 0 {
					code = http.StatusMovedPermanently
				}
				http.Redirect(w, r, rr.To, code)
				return
			}
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
	return mux
}

func (p *proxyServer) httpsMux() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.totalRequests.Add(1) // 総リクエスト数をカウント
		s := p.matchService(r.Host, r.URL.Path)
		if s == nil {
			p.failRequests.Add(1) // 404の場合は失敗としてカウント
			http.NotFound(w, r)
			return
		}
		rp := p.makeProxy(s)
		rp.ServeHTTP(w, r)
	})
}

func (p *proxyServer) healthCheckMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		uptime := time.Since(p.startTime)
		uptimeStr := p.formatUptime(uptime)

		stats := StatsResponse{
			Status:          "ok",
			TotalRequests:   p.totalRequests.Load(),
			SuccessRequests: p.successRequests.Load(),
			FailRequests:    p.failRequests.Load(),
			Uptime:          uptimeStr,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(stats)
	})

	return mux
}

func (p *proxyServer) formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%d days %d hours %d minutes", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%d hours %d minutes", hours, minutes)
	} else {
		return fmt.Sprintf("%d minutes", minutes)
	}
}

func (p *proxyServer) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(chi.ServerName)
			p.mu.RLock()
			defer p.mu.RUnlock()
			if cert, ok := p.certMap[name]; ok {
				return cert, nil
			}
			if p.defaultCert != nil {
				return p.defaultCert, nil
			}
			return nil, errors.New("no certificate available")
		},
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}
}

func (p *proxyServer) watchAndReload(path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Watch both the original config file and the repository config file
	watchPaths := []string{filepath.Dir(path)}
	if p.configRepoPath != "" {
		repoConfigDir := filepath.Dir(filepath.Join(p.configRepoPath, "config.yaml"))
		watchPaths = append(watchPaths, repoConfigDir)

		// Watch certs directory in repository if it exists
		certsDirPath := filepath.Join(p.configRepoPath, "certs")
		if _, err := os.Stat(certsDirPath); err == nil {
			watchPaths = append(watchPaths, certsDirPath)
		}
	}

	for _, watchPath := range watchPaths {
		if err := watcher.Add(watchPath); err != nil {
			log.Printf("Failed to watch %s: %v", watchPath, err)
		} else {
			log.Printf("Watching directory: %s", watchPath)
		}
	}

	go func() {
		debounce := time.NewTimer(0)
		<-debounce.C
		for {
			select {
			case ev := <-watcher.Events:
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					// Check if it's a config file or certificate file
					fileName := filepath.Base(ev.Name)
					isConfigFile := fileName == "config.yaml"
					isCertFile := strings.HasSuffix(fileName, ".pem") || strings.HasSuffix(fileName, ".crt") || strings.HasSuffix(fileName, ".key")

					if isConfigFile || isCertFile {
						log.Printf("Detected change in %s", ev.Name)
						// debounce
						if !debounce.Stop() {
							<-debounce.C
						}
						debounce.Reset(300 * time.Millisecond)
					}
				}
			case <-debounce.C:
				// Try to reload from repository first, then fallback to local config
				var reloadErr error
				if p.configRepoPath != "" {
					reloadErr = p.loadConfigFromRepo()
				}

				if reloadErr != nil {
					log.Printf("Failed to reload from repository, trying local config: %v", reloadErr)
					cfg, err := loadConfig(path)
					if err != nil {
						log.Printf("Local config reload error: %v", err)
						continue
					}
					if err := p.applyConfig(cfg); err != nil {
						log.Printf("Local config apply error: %v", err)
						continue
					}
					log.Printf("Local config reloaded")
				} else {
					log.Printf("Repository config reloaded")
				}
			}
		}
	}()
	return nil
}

func main() {
	var cfgPath string
	var configRepoURL string
	var configRepoPath string
	var syncInterval time.Duration

	flag.StringVar(&cfgPath, "config", getenv("CONFIG_PATH", "./config.yaml"), "config file path")
	flag.StringVar(&configRepoURL, "config-repo", getenv("CONFIG_REPO_URL", ""), "config repository URL (e.g., git@github.com:user/repo.git)")
	flag.StringVar(&configRepoPath, "config-repo-path", getenv("CONFIG_REPO_PATH", "./config-repo"), "local path to clone config repository")
	flag.DurationVar(&syncInterval, "sync-interval", time.Minute, "interval for syncing config repository")
	flag.Parse()

	// Load initial config from local file
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	p := &proxyServer{
		startTime:      time.Now(),
		configRepoURL:  configRepoURL,
		configRepoPath: configRepoPath,
	}

	if err := p.applyConfig(cfg); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start config repository syncing if URL is provided
	if configRepoURL != "" {
		log.Printf("Starting config repository sync from %s every %v", configRepoURL, syncInterval)
		syncer := newConfigSyncer(configRepoURL, configRepoPath)

		go syncer.startPeriodicSync(ctx, syncInterval, func() {
			// Callback function called after successful sync
			if err := p.loadConfigFromRepo(); err != nil {
				log.Printf("Failed to reload config after sync: %v", err)
			}
		})
	} else {
		log.Printf("No config repository URL provided, using local config only")
	}

	p.startHealthChecks(ctx)

	if err := p.watchAndReload(cfgPath); err != nil {
		log.Printf("watch error: %v", err)
	}

	go func() {
		srv := &http.Server{Addr: cfg.HTTP.Addr, Handler: p.httpRedirectMux()}
		log.Printf("HTTP redirect listening on %s", cfg.HTTP.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	go func() {
		healthSrv := &http.Server{Addr: ":8000", Handler: p.healthCheckMux()}
		log.Printf("Health check server listening on :8000")
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	httpsSrv := &http.Server{Addr: cfg.HTTPS.Addr, Handler: p.httpsMux(), TLSConfig: p.tlsConfig()}
	log.Printf("HTTPS proxy listening on %s", cfg.HTTPS.Addr)
	ln, err := net.Listen("tcp", cfg.HTTPS.Addr)
	if err != nil {
		log.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, httpsSrv.TLSConfig)
	if err := httpsSrv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
