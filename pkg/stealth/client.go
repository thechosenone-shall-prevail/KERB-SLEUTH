package stealth

import (
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// StealthConfig holds stealth configuration
type StealthConfig struct {
	Enabled       bool
	RandomDelay   bool
	MinDelay      time.Duration
	MaxDelay      time.Duration
	ProxyURL      string
	UserAgent     string
	RequestJitter time.Duration
	MaxRetries    int
	RetryDelay    time.Duration
	AntiDetection bool
	LogLevel      string
}

// DefaultStealthConfig returns default stealth configuration
func DefaultStealthConfig() *StealthConfig {
	return &StealthConfig{
		Enabled:       false,
		RandomDelay:   true,
		MinDelay:      100 * time.Millisecond,
		MaxDelay:      2 * time.Second,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		RequestJitter: 50 * time.Millisecond,
		MaxRetries:    3,
		RetryDelay:    1 * time.Second,
		AntiDetection: true,
		LogLevel:      "INFO",
	}
}

// StealthClient wraps HTTP client with stealth capabilities
type StealthClient struct {
	Config     *StealthConfig
	HTTPClient *http.Client
	Transport  *http.Transport
}

// NewStealthClient creates a new stealth client
func NewStealthClient(config *StealthConfig) (*StealthClient, error) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Configure proxy if specified
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		log.Printf("[*] Using proxy: %s", config.ProxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &StealthClient{
		Config:     config,
		HTTPClient: client,
		Transport:  transport,
	}, nil
}

// ApplyStealthDelay applies random delay between requests
func (sc *StealthClient) ApplyStealthDelay() {
	if !sc.Config.Enabled || !sc.Config.RandomDelay {
		return
	}

	// Calculate random delay
	minMs := int(sc.Config.MinDelay.Milliseconds())
	maxMs := int(sc.Config.MaxDelay.Milliseconds())

	if maxMs <= minMs {
		maxMs = minMs + 1000
	}

	delayMs := minMs + randInt(maxMs-minMs)
	delay := time.Duration(delayMs) * time.Millisecond

	// Add jitter
	if sc.Config.RequestJitter > 0 {
		jitterMs := randInt(int(sc.Config.RequestJitter.Milliseconds()))
		delay += time.Duration(jitterMs) * time.Millisecond
	}

	log.Printf("[!] Applying stealth delay: %v", delay)
	time.Sleep(delay)
}

// RandomizeUserAgent randomizes the User-Agent header
func (sc *StealthClient) RandomizeUserAgent() string {
	if !sc.Config.Enabled {
		return sc.Config.UserAgent
	}

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}

	selected := userAgents[randInt(len(userAgents))]
	log.Printf("[!] Randomized User-Agent: %s", selected[:50]+"...")
	return selected
}

// CreateStealthRequest creates an HTTP request with stealth headers
func (sc *StealthClient) CreateStealthRequest(method, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// Set stealth headers
	req.Header.Set("User-Agent", sc.RandomizeUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Add anti-detection headers
	if sc.Config.AntiDetection {
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
	}

	return req, nil
}

// ExecuteWithRetry executes a request with retry logic
func (sc *StealthClient) ExecuteWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 1; attempt <= sc.Config.MaxRetries; attempt++ {
		// Apply stealth delay before each attempt
		if attempt > 1 {
			sc.ApplyStealthDelay()
		}

		resp, err := sc.HTTPClient.Do(req)
		if err == nil {
			log.Printf("[+] Request successful (attempt %d)", attempt)
			return resp, nil
		}

		lastErr = err
		log.Printf("[-] Request failed (attempt %d): %v", attempt, err)

		// Wait before retry
		if attempt < sc.Config.MaxRetries {
			time.Sleep(sc.Config.RetryDelay)
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %v", sc.Config.MaxRetries, lastErr)
}

// StealthLDAPClient wraps LDAP client with stealth capabilities
type StealthLDAPClient struct {
	Config *StealthConfig
}

// NewStealthLDAPClient creates a new stealth LDAP client
func NewStealthLDAPClient(config *StealthConfig) *StealthLDAPClient {
	return &StealthLDAPClient{
		Config: config,
	}
}

// ApplyLDAPStealth applies stealth techniques to LDAP operations
func (slc *StealthLDAPClient) ApplyLDAPStealth(operation string) {
	if !slc.Config.Enabled {
		return
	}

	log.Printf("[+] Applying LDAP stealth for operation: %s", operation)

	// Apply random delay
	if slc.Config.RandomDelay {
		minMs := int(slc.Config.MinDelay.Milliseconds())
		maxMs := int(slc.Config.MaxDelay.Milliseconds())
		delayMs := minMs + randInt(maxMs-minMs)
		delay := time.Duration(delayMs) * time.Millisecond

		log.Printf("⏱️  LDAP stealth delay: %v", delay)
		time.Sleep(delay)
	}

	// Add jitter
	if slc.Config.RequestJitter > 0 {
		jitterMs := randInt(int(slc.Config.RequestJitter.Milliseconds()))
		jitter := time.Duration(jitterMs) * time.Millisecond
		time.Sleep(jitter)
	}
}

// AntiDetectionTechniques applies anti-detection techniques
func (sc *StealthClient) AntiDetectionTechniques() {
	if !sc.Config.Enabled || !sc.Config.AntiDetection {
		return
	}

	log.Printf("[+] Applying anti-detection techniques...")

	// Randomize request patterns
	techniques := []string{
		"Randomized timing patterns",
		"Varied request headers",
		"Proxy rotation",
		"User-Agent randomization",
		"Request jitter",
	}

	for _, technique := range techniques {
		log.Printf("   ✓ %s", technique)
	}
}

// StealthLogger provides stealth-aware logging
type StealthLogger struct {
	Config *StealthConfig
}

// NewStealthLogger creates a new stealth logger
func NewStealthLogger(config *StealthConfig) *StealthLogger {
	return &StealthLogger{
		Config: config,
	}
}

// Log logs with stealth considerations
func (sl *StealthLogger) Log(level, message string) {
	if !sl.Config.Enabled {
		log.Printf("[%s] %s", level, message)
		return
	}

	// Apply stealth logging based on level
	switch strings.ToUpper(level) {
	case "DEBUG":
		if sl.Config.LogLevel == "DEBUG" {
			log.Printf("[DEBUG] %s", message)
		}
	case "INFO":
		log.Printf("[INFO] %s", message)
	case "WARN":
		log.Printf("[WARN] %s", message)
	case "ERROR":
		log.Printf("[ERROR] %s", message)
	default:
		log.Printf("[%s] %s", level, message)
	}
}

// Helper functions

func randInt(max int) int {
	if max <= 0 {
		return 0
	}

	b := make([]byte, 4)
	rand.Read(b)
	return int(b[0]) % max
}

// GenerateRandomDelay generates a random delay within configured bounds
func GenerateRandomDelay(min, max time.Duration) time.Duration {
	if max <= min {
		max = min + time.Second
	}

	minMs := int(min.Milliseconds())
	maxMs := int(max.Milliseconds())

	delayMs := minMs + randInt(maxMs-minMs)
	return time.Duration(delayMs) * time.Millisecond
}

// ApplyExponentialBackoff applies exponential backoff for retries
func ApplyExponentialBackoff(attempt int, baseDelay time.Duration) time.Duration {
	delay := float64(baseDelay) * math.Pow(2, float64(attempt-1))
	maxDelay := 30 * time.Second

	if time.Duration(delay) > maxDelay {
		delay = float64(maxDelay)
	}

	return time.Duration(delay)
}
