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
	"os/exec"
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

type contextKey string

const (
	selectedBackendKey contextKey = "selectedBackend"
	loadBalancerKey    contextKey = "loadBalancer"
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
	Name           string          `yaml:"name"`
	Hosts          []string        `yaml:"hosts"`
	Routes         []string        `yaml:"routes"`
	Upstreams      []Upstream      `yaml:"upstreams"`
	HealthCheck    Health          `yaml:"health_check"`
	PassHostHeader *bool           `yaml:"pass_host_header"`
	CircuitBreaker *CircuitBreaker `yaml:"circuit_breaker,omitempty"`
}

type CircuitBreaker struct {
	MaxFailures  uint32        `yaml:"max_failures"`
	RecoveryTime time.Duration `yaml:"recovery_time"`
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
	target           *url.URL
	alive            atomic.Bool
	consecutiveFails atomic.Uint32
	lastFailTime     atomic.Int64
	recoveryTime     atomic.Int64 // time when backend can be retried
}

type lb struct {
	name           string
	backends       []*backend
	idx            atomic.Uint32
	maxFailures    uint32
	recoveryTimeMs int64
}

func newLB(name string, ups []Upstream, circuitBreaker *CircuitBreaker) (*lb, error) {
	if len(ups) == 0 {
		return nil, errors.New("no upstreams")
	}

	// Circuit Breaker のデフォルト値
	maxFailures := uint32(3)
	recoveryTimeMs := int64(10 * 1000) // 10秒

	if circuitBreaker != nil {
		if circuitBreaker.MaxFailures > 0 {
			maxFailures = circuitBreaker.MaxFailures
		}
		if circuitBreaker.RecoveryTime > 0 {
			recoveryTimeMs = circuitBreaker.RecoveryTime.Milliseconds()
		}
	}

	bks := make([]*backend, 0, len(ups))
	for _, u := range ups {
		pu, err := url.Parse(u.URL)
		if err != nil {
			return nil, fmt.Errorf("parse upstream: %w", err)
		}
		b := &backend{target: pu}
		b.alive.Store(true)
		b.consecutiveFails.Store(0)
		b.lastFailTime.Store(0)
		b.recoveryTime.Store(0)
		bks = append(bks, b)
	}

	log.Printf("Created load balancer for %s with circuit breaker: max_failures=%d, recovery_time=%dms",
		name, maxFailures, recoveryTimeMs)

	return &lb{
		name:           name,
		backends:       bks,
		maxFailures:    maxFailures,
		recoveryTimeMs: recoveryTimeMs,
	}, nil
}

func (l *lb) nextAlive() *backend {
	n := uint32(len(l.backends))
	if n == 0 {
		return nil
	}

	currentTime := time.Now().UnixMilli()
	var fallbackBackend *backend

	// 最大2周回してでも健全なbackendを探す
	for attempts := uint32(0); attempts < n*2; attempts++ {
		idx := l.idx.Add(1)
		b := l.backends[idx%n]

		// ヘルスチェックで生きていることが確認されている
		if b.alive.Load() {
			// Circuit Breakerが開いているかチェック
			if l.isCircuitBreakerOpen(b, currentTime) {
				// Circuit Breakerが開いているが、recovery timeを過ぎていればリトライを許可
				if currentTime >= b.recoveryTime.Load() {
					log.Printf("Backend %s: Circuit breaker half-open, allowing retry", b.target.String())
					return b
				}
				// まだrecovery timeに達していない場合は、fallbackとして記憶しておく
				if fallbackBackend == nil {
					fallbackBackend = b
				}
				continue
			}
			return b
		}

		// ヘルスチェックでダウンしているが、fallbackとして記憶
		if fallbackBackend == nil {
			fallbackBackend = b
		}
	}

	// 健全なbackendが見つからない場合
	if fallbackBackend != nil {
		log.Printf("No healthy backends available for service %s, using fallback: %s", l.name, fallbackBackend.target.String())
		return fallbackBackend
	}

	// 最後の手段として最初のbackendを返す
	log.Printf("All backends down for service %s, using first backend as last resort", l.name)
	return l.backends[0]
}

func (l *lb) isCircuitBreakerOpen(b *backend, currentTime int64) bool {
	consecutiveFails := b.consecutiveFails.Load()
	return consecutiveFails >= l.maxFailures
}

func (l *lb) recordSuccess(b *backend) {
	if b.consecutiveFails.Load() > 0 {
		log.Printf("Backend %s recovered, resetting failure count", b.target.String())
		b.consecutiveFails.Store(0)
		b.recoveryTime.Store(0)
	}
}

func (l *lb) recordFailure(b *backend) {
	currentTime := time.Now().UnixMilli()
	failures := b.consecutiveFails.Add(1)
	b.lastFailTime.Store(currentTime)

	if failures >= l.maxFailures {
		recoveryTime := currentTime + l.recoveryTimeMs
		b.recoveryTime.Store(recoveryTime)
		log.Printf("Backend %s: Circuit breaker opened after %d failures, recovery at %v",
			b.target.String(), failures, time.UnixMilli(recoveryTime))
	} else {
		log.Printf("Backend %s: Recorded failure %d/%d", b.target.String(), failures, l.maxFailures)
	}
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

func (cs *configSyncer) setupGitConfig() error {
	// Set up git configuration if not already done
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/tmp"
	}

	// Configure git globally (removed init.defaultBranch to let git use repository's default)
	commands := [][]string{
		{"git", "config", "--global", "user.email", "sparrowproxy@booyah.dev"},
		{"git", "config", "--global", "user.name", "SparrowProxy"},
		{"git", "config", "--global", "--add", "safe.directory", cs.repoPath},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			log.Printf("Warning: Git config command failed: %v", err)
			// Continue even if git config fails - it's not critical
		}
	}

	log.Printf("Git configuration completed")
	return nil
}

func (cs *configSyncer) setupHTTPAuth() (*githttp.BasicAuth, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is not set")
	}

	// Log token length for debugging (without exposing the actual token)
	log.Printf("Using HTTPS authentication with Personal Access Token (length: %d)", len(token))

	// GitHub Personal Access Tokenを使用したHTTPS認証
	auth := &githttp.BasicAuth{
		Username: "git", // GitHubの場合、usernameは任意の値でよい
		Password: token,
	}

	return auth, nil
}

func (cs *configSyncer) fallbackClone() error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN not available for fallback")
	}

	// Remove any existing directory
	if err := os.RemoveAll(cs.repoPath); err != nil {
		log.Printf("Warning: failed to remove existing directory: %v", err)
	}

	// Use system git command with token in URL (like the debug pod)
	cloneURL := fmt.Sprintf("https://git:%s@github.com/BooyahDev/SparrowProxyConfig.git", token)

	cmd := exec.Command("git", "clone", cloneURL, cs.repoPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("Executing: git clone [REDACTED_URL] %s", cs.repoPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("system git clone failed: %w", err)
	}

	// Verify the cloned repository
	if _, err := os.Stat(filepath.Join(cs.repoPath, ".git")); err != nil {
		return fmt.Errorf("cloned repository does not have .git directory: %w", err)
	}

	// Detect and set the default branch
	if err := cs.detectAndSetDefaultBranch(); err != nil {
		log.Printf("Warning: failed to detect default branch: %v", err)
	}

	log.Printf("Fallback clone completed successfully")
	return nil
}

func (cs *configSyncer) detectAndSetDefaultBranch() error {
	// Check which branch we're currently on
	cmd := exec.Command("git", "-C", cs.repoPath, "branch", "--show-current")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get current branch: %w", err)
	}

	currentBranch := strings.TrimSpace(string(output))
	log.Printf("Repository default branch detected: %s", currentBranch)

	// If it's not main, we might need to handle this in pull operations
	if currentBranch != "main" && currentBranch != "master" {
		log.Printf("Warning: Unexpected default branch '%s', will try main/master during pulls", currentBranch)
	}

	return nil
}

func (cs *configSyncer) fallbackPull() error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN not available for fallback")
	}

	// Try main branch first
	log.Printf("Executing: git -C %s pull origin main", cs.repoPath)
	cmd := exec.Command("git", "-C", cs.repoPath, "pull", "origin", "main")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Printf("Pull from main branch failed: %v", err)
		log.Printf("Attempting pull from master branch...")

		// Try master branch as fallback
		log.Printf("Executing: git -C %s pull origin master", cs.repoPath)
		cmdMaster := exec.Command("git", "-C", cs.repoPath, "pull", "origin", "master")
		cmdMaster.Stdout = os.Stdout
		cmdMaster.Stderr = os.Stderr

		if masterErr := cmdMaster.Run(); masterErr != nil {
			log.Printf("Pull from master branch also failed: %v", masterErr)

			// Check for repository corruption indicators
			mainErrStr := err.Error()
			masterErrStr := masterErr.Error()

			if strings.Contains(mainErrStr, "bad object") ||
				strings.Contains(masterErrStr, "bad object") ||
				strings.Contains(mainErrStr, "did not send all necessary objects") ||
				strings.Contains(masterErrStr, "did not send all necessary objects") ||
				strings.Contains(mainErrStr, "fatal: couldn't find remote ref") ||
				strings.Contains(masterErrStr, "fatal: couldn't find remote ref") {
				return fmt.Errorf("repository corruption detected: pull failed from both main and master branches with corruption indicators: main=%v, master=%v", err, masterErr)
			}

			return fmt.Errorf("pull failed from both main and master branches: main=%v, master=%v", err, masterErr)
		}
		log.Printf("Successfully pulled from master branch")
		return nil
	}

	log.Printf("Successfully pulled from main branch")
	return nil
}

func (cs *configSyncer) checkRepositoryHealth() error {
	// Check if .git directory exists
	gitDir := filepath.Join(cs.repoPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("repository .git directory missing")
	}

	// Try to get current HEAD to verify repository integrity
	cmd := exec.Command("git", "-C", cs.repoPath, "rev-parse", "HEAD")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("repository HEAD verification failed: %w", err)
	}

	// Check if we can access remote
	cmd = exec.Command("git", "-C", cs.repoPath, "remote", "-v")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("repository remote verification failed: %w", err)
	}

	return nil
}

func (cs *configSyncer) syncRepo() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Setup git configuration first
	if err := cs.setupGitConfig(); err != nil {
		log.Printf("Warning: Git configuration failed: %v", err)
	}

	auth, err := cs.setupHTTPAuth()
	if err != nil {
		return fmt.Errorf("HTTP auth setup failed: %w", err)
	}

	// Ensure parent directory exists with proper permissions
	parentDir := filepath.Dir(cs.repoPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w", parentDir, err)
	}

	// Check if repository already exists
	log.Printf("Checking if repository exists at: %s", cs.repoPath)
	if _, err := os.Stat(cs.repoPath); os.IsNotExist(err) {
		log.Printf("Repository does not exist, will clone from %s", cs.repoURL)

		// Create the target directory with proper permissions
		if err := os.MkdirAll(cs.repoPath, 0755); err != nil {
			return fmt.Errorf("failed to create repository directory %s: %w", cs.repoPath, err)
		}
		// Remove the empty directory so git.PlainClone can create it
		if err := os.Remove(cs.repoPath); err != nil {
			log.Printf("Warning: failed to remove empty directory: %v", err)
		}

		// Clone repository with detailed logging
		log.Printf("Starting clone operation...")
		log.Printf("  URL: %s", cs.repoURL)
		log.Printf("  Target: %s", cs.repoPath)
		log.Printf("  Auth: Using Personal Access Token")

		_, err := git.PlainClone(cs.repoPath, false, &git.CloneOptions{
			URL:             cs.repoURL,
			Auth:            auth,
			Progress:        os.Stdout,
			InsecureSkipTLS: false,
		})
		if err != nil {
			// More detailed error logging
			log.Printf("CLONE FAILED:")
			log.Printf("  URL: %s", cs.repoURL)
			log.Printf("  Path: %s", cs.repoPath)
			log.Printf("  Error: %v", err)
			log.Printf("  Error Type: %T", err)

			// Check if directory was created
			if info, statErr := os.Stat(cs.repoPath); statErr == nil {
				log.Printf("  Directory exists after failed clone: %v", info.IsDir())
			} else {
				log.Printf("  Directory stat error: %v", statErr)
			}

			// Try fallback method using system git command
			log.Printf("Attempting fallback clone using system git command...")
			if fallbackErr := cs.fallbackClone(); fallbackErr != nil {
				log.Printf("Fallback clone also failed: %v", fallbackErr)
				return fmt.Errorf("failed to clone repository (both go-git and system git failed): %w", err)
			}
			log.Printf("Fallback clone succeeded!")
			return nil
		}
		log.Printf("Successfully cloned config repository")
		return nil
	} else if err != nil {
		log.Printf("Error checking repository existence: %v", err)
		return fmt.Errorf("failed to check repository existence: %w", err)
	} else {
		log.Printf("Repository already exists at: %s", cs.repoPath)

		// Perform comprehensive repository health check
		if healthErr := cs.checkRepositoryHealth(); healthErr != nil {
			log.Printf("Repository health check failed: %v", healthErr)
			log.Printf("Repository appears corrupted, performing complete re-clone...")

			// Remove the corrupted directory
			if rmErr := os.RemoveAll(cs.repoPath); rmErr != nil {
				log.Printf("Failed to remove corrupted repository: %v", rmErr)
			}

			// Retry clone using fallback method
			if fallbackErr := cs.fallbackClone(); fallbackErr != nil {
				log.Printf("Fallback clone failed: %v", fallbackErr)
				return fmt.Errorf("failed to re-clone corrupted repository: %w", fallbackErr)
			}
			log.Printf("Successfully re-cloned repository after health check failure")
			return nil
		}

		// Check if it's a valid git repository (secondary check)
		if _, err := git.PlainOpen(cs.repoPath); err != nil {
			log.Printf("Existing directory is not a valid git repository: %v", err)
			log.Printf("Removing invalid repository directory and re-cloning...")

			// Remove the invalid directory
			if rmErr := os.RemoveAll(cs.repoPath); rmErr != nil {
				log.Printf("Failed to remove invalid repository: %v", rmErr)
			}

			// Retry clone using fallback method
			if fallbackErr := cs.fallbackClone(); fallbackErr != nil {
				log.Printf("Fallback clone failed: %v", fallbackErr)
				return fmt.Errorf("failed to re-clone repository: %w", fallbackErr)
			}
			log.Printf("Successfully re-cloned repository using fallback method")
			return nil
		}
	}

	// Open existing repository
	repo, err := git.PlainOpen(cs.repoPath)
	if err != nil {
		log.Printf("Failed to open repository even after validation: %v", err)
		// Last resort: try fallback clone
		log.Printf("Attempting complete re-clone as last resort...")
		if rmErr := os.RemoveAll(cs.repoPath); rmErr != nil {
			log.Printf("Failed to remove directory: %v", rmErr)
		}
		if fallbackErr := cs.fallbackClone(); fallbackErr != nil {
			return fmt.Errorf("all repository access methods failed: %w", err)
		}
		log.Printf("Last resort clone succeeded")
		return nil
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
	// First, try to determine the current branch
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get current HEAD reference: %w", err)
	}

	// Extract branch name from the reference
	branchName := "main" // default fallback
	if head.Name().IsBranch() {
		branchName = head.Name().Short()
	}
	log.Printf("Attempting to pull from branch: %s", branchName)

	err = worktree.Pull(&git.PullOptions{
		Auth:          auth,
		RemoteName:    "origin",
		SingleBranch:  true,
		ReferenceName: head.Name(), // Use the current branch reference
	})

	if err != nil && err != git.NoErrAlreadyUpToDate {
		log.Printf("go-git pull failed (branch: %s): %v", branchName, err)

		// Check if it's a repository corruption issue
		isCorruption := strings.Contains(err.Error(), "reference has changed concurrently") ||
			strings.Contains(err.Error(), "bad object") ||
			strings.Contains(err.Error(), "did not send all necessary objects")

		if isCorruption {
			log.Printf("Repository corruption detected, performing complete re-clone...")
			if recloneErr := cs.fallbackClone(); recloneErr != nil {
				log.Printf("Complete re-clone failed: %v", recloneErr)
				return fmt.Errorf("failed to recover corrupted repository: %w", recloneErr)
			}
			log.Printf("Repository successfully re-cloned")
			return nil
		}

		log.Printf("Attempting fallback pull using system git...")
		if fallbackErr := cs.fallbackPull(); fallbackErr != nil {
			log.Printf("Fallback pull also failed: %v", fallbackErr)

			// Check if fallback pull also indicates corruption
			fallbackErrStr := fallbackErr.Error()
			isCorruptionFallback := strings.Contains(fallbackErrStr, "bad object") ||
				strings.Contains(fallbackErrStr, "did not send all necessary objects") ||
				strings.Contains(fallbackErrStr, "corrupted") ||
				strings.Contains(fallbackErrStr, "fatal:")

			if isCorruptionFallback {
				log.Printf("System git also indicates repository corruption, performing complete re-clone...")
				if recloneErr := cs.fallbackClone(); recloneErr != nil {
					log.Printf("Complete re-clone failed: %v", recloneErr)
					return fmt.Errorf("failed to recover corrupted repository after all attempts: %w", recloneErr)
				}
				log.Printf("Repository successfully re-cloned after corruption")
				return nil
			}

			return fmt.Errorf("failed to pull repository (both go-git and system git failed): %w", err)
		}
		log.Printf("Fallback pull succeeded")
		return nil
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
		l, err := newLB(s.Name, s.Upstreams, s.CircuitBreaker)
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

		if b == nil {
			log.Printf("No backends available for service %s", s.Name)
			return
		}

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

		// 選択されたbackendをcontextに保存（エラーハンドラーで使用）
		ctx := context.WithValue(r.Context(), selectedBackendKey, b)
		ctx = context.WithValue(ctx, loadBalancerKey, lb)
		*r = *r.WithContext(ctx)
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

			// 成功・失敗の統計更新と Circuit Breaker の状態更新
			if res.StatusCode >= 200 && res.StatusCode < 400 {
				p.successRequests.Add(1)
				// Backend の成功を記録
				if b, ok := res.Request.Context().Value(selectedBackendKey).(*backend); ok {
					if lb, ok := res.Request.Context().Value(loadBalancerKey).(*lb); ok {
						lb.recordSuccess(b)
					}
				}
			} else if res.StatusCode >= 500 {
				// 5xx エラーはbackend側の問題として扱う
				p.failRequests.Add(1)
				if b, ok := res.Request.Context().Value(selectedBackendKey).(*backend); ok {
					if lb, ok := res.Request.Context().Value(loadBalancerKey).(*lb); ok {
						lb.recordFailure(b)
					}
				}
			} else {
				// 4xx エラーはクライアント側の問題として扱い、backendの統計には影響しない
				p.failRequests.Add(1)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.failRequests.Add(1)
			log.Printf("proxy error: %v", err)

			// Backend の失敗を記録
			if b, ok := r.Context().Value(selectedBackendKey).(*backend); ok {
				if lb, ok := r.Context().Value(loadBalancerKey).(*lb); ok {
					lb.recordFailure(b)
				}
			}

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

		client := &http.Client{Timeout: timeout}
		lb := p.lbs[s.Name]

		go func(serviceName string) {
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

						// ヘルスチェック実行
						ok := checkOnce(client, u.String())
						previousState := b.alive.Load()
						b.alive.Store(ok)

						// 状態が変化した場合はログを出力
						if ok != previousState {
							if ok {
								log.Printf("Backend %s for service %s is now healthy", b.target.String(), serviceName)
								// ヘルスチェックで回復した場合は Circuit Breaker もリセット
								lb.recordSuccess(b)
							} else {
								log.Printf("Backend %s for service %s is now unhealthy", b.target.String(), serviceName)
							}
						}
					}
				}
			}
		}(s.Name)
	}
}

func checkOnce(c *http.Client, url string) bool {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Health check request creation failed for %s: %v", url, err)
		return false
	}

	resp, err := c.Do(req)
	if err != nil {
		log.Printf("Health check failed for %s: %v", url, err)
		return false
	}
	defer resp.Body.Close()

	// レスポンスボディを読み取って破棄
	io.Copy(io.Discard, resp.Body)

	healthy := resp.StatusCode >= 200 && resp.StatusCode < 400
	if !healthy {
		log.Printf("Health check returned unhealthy status %d for %s", resp.StatusCode, url)
	}

	return healthy
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

		// Ensure the config repository directory structure exists
		if err := os.MkdirAll(filepath.Dir(configRepoPath), 0755); err != nil {
			log.Printf("Warning: Failed to create config repo parent directory: %v", err)
		}

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
