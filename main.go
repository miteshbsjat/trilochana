package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// --- Configuration & Constants ---

const (
	Version = "0.3.0-go"
)

// Config holds command line arguments
type Config struct {
	Path       string
	Format     string
	Output     string
	MinEntropy float64
	Threads    int
	Verbose    bool
	GitIgnore  bool
}

// Finding represents a detected secret
type Finding struct {
	FilePath    string  `json:"file_path"`
	LineNumber  int     `json:"line_number"`
	LineContent string  `json:"line_content"`
	PatternName string  `json:"pattern_name"`
	MatchedText string  `json:"matched_text"`
	Entropy     float64 `json:"entropy"`
}

// --- Entropy Logic ---

func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	total := float64(utf8.RuneCountInString(s))
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// --- Pattern Definitions ---

// patterns is the global map of regexes. We initialize it with defaults,
// then merge external config into it.
var patterns = map[string]*regexp.Regexp{
	// AWS
	"AWS Access Key ID": regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
	"AWS Secret Key":    regexp.MustCompile(`(?i)(aws[_\s\-]?secret[_\s\-]?(access[_\s\-]?)?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),

	// GitHub
	"GitHub Token": regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}`),
	"GitHub OAuth": regexp.MustCompile(`[0-9a-f]{40}`),

	// Private Keys
	"RSA Private Key":     regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
	"SSH Private Key":     regexp.MustCompile(`-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----`),
	"Generic Private Key": regexp.MustCompile(`-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----`),

	// API Keys
	"Stripe API Key": regexp.MustCompile(`(sk|pk)_(test|live)_[0-9A-Za-z]{24,}`),
	"Slack Token":    regexp.MustCompile(`xox[baprs]-[0-9A-Za-z]{10,48}`),
	"Google API Key": regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),

	// Database
	"Postgres URL": regexp.MustCompile(`postgres(ql)?://[a-z0-9]+:[^@\s]+@[^\s]+`),
	"MySQL URL":    regexp.MustCompile(`mysql://[a-z0-9]+:[^@\s]+@[^\s]+`),
	"Mongo URL":    regexp.MustCompile(`mongodb(\+srv)?://[a-z0-9]+:[^@\s]+@[^\s]+`),

	// Generic
	"Generic Secret Assignment": regexp.MustCompile(`(?i)(api[_\s\-]?key|secret|token|password|auth)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{16,})["']?`),
}

// --- External Config Logic ---

// LoadExternalPatterns reads a JSON file from ~/.config/trilochana/regex
// and merges the patterns into the global map.
func LoadExternalPatterns(verbose bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		if verbose {
			fmt.Printf("Warning: Could not determine home directory: %v\n", err)
		}
		return
	}

	configPath := filepath.Join(home, ".config", "trilochana", "regex.json")
	
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if verbose {
			fmt.Printf("No external config found at %s, skipping.\n", configPath)
		}
		return
	}

	file, err := os.Open(configPath)
	if err != nil {
		if verbose {
			fmt.Printf("Warning: Could not open config file: %v\n", err)
		}
		return
	}
	defer file.Close()

	// Parse JSON: map[string]string -> "Pattern Name": "Regex String"
	var externalPatterns map[string]string
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&externalPatterns); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON from %s: %v\n", configPath, err)
		return
	}

	// Merge into global patterns
	count := 0
	for name, regexStr := range externalPatterns {
		// Compile the regex
		re, err := regexp.Compile(regexStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error compiling regex for '%s': %v\n", name, err)
			continue
		}
		
		// Add or Overwrite
		patterns[name] = re
		count++
	}

	if verbose {
		fmt.Printf("Loaded %d patterns from %s\n", count, configPath)
	}
}

// --- GitIgnore Logic ---

type GitIgnoreMatcher struct {
	patterns []string
	baseDir  string
}

func NewGitIgnoreMatcher(rootPath string) *GitIgnoreMatcher {
	matcher := &GitIgnoreMatcher{
		baseDir: rootPath,
	}

	gitIgnorePath := filepath.Join(rootPath, ".gitignore")
	file, err := os.Open(gitIgnorePath)
	if err != nil {
		return matcher
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matcher.patterns = append(matcher.patterns, line)
	}
	return matcher
}

func (m *GitIgnoreMatcher) IsIgnored(path string) bool {
	if len(m.patterns) == 0 {
		return false
	}
	relPath, err := filepath.Rel(m.baseDir, path)
	if err != nil {
		return false
	}
	relPath = filepath.ToSlash(relPath)

	for _, pattern := range m.patterns {
		isDirPattern := strings.HasSuffix(pattern, "/")
		cleanPattern := strings.TrimSuffix(pattern, "/")

		if relPath == cleanPattern || strings.HasPrefix(relPath, cleanPattern+"/") {
			return true
		}

		matched, _ := filepath.Match(cleanPattern, filepath.Base(relPath))
		if matched {
			if !isDirPattern {
				return true
			}
			return true
		}

		matchedFull, _ := filepath.Match(cleanPattern, relPath)
		if matchedFull {
			return true
		}
	}
	return false
}

// --- Scanning Logic ---

func shouldSkipPath(path string, ignoreMatcher *GitIgnoreMatcher, useGitIgnore bool) bool {
	lowerPath := strings.ToLower(path)

	ignoredDirs := []string{".git", ".idea", ".vscode", "node_modules", "vendor", "target", "dist", "build"}
	for _, dir := range ignoredDirs {
		if strings.Contains(lowerPath, string(os.PathSeparator)+dir+string(os.PathSeparator)) || strings.HasPrefix(lowerPath, dir+string(os.PathSeparator)) {
			return true
		}
	}

	ext := filepath.Ext(lowerPath)
	binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".zip", ".tar", ".gz", ".png", ".jpg", ".jpeg", ".pdf", ".lock", ".bin"}
	for _, bin := range binaryExts {
		if ext == bin {
			return true
		}
	}

	if useGitIgnore && ignoreMatcher != nil {
		if ignoreMatcher.IsIgnored(path) {
			return true
		}
	}

	return false
}

func scanFile(path string, minEntropy float64) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		if len(line) > 2000 {
			continue
		}

		for name, regex := range patterns {
			matches := regex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				secretVal := match[0]
				if len(match) > 1 {
					secretVal = match[len(match)-1]
				}

				entropy := CalculateShannonEntropy(secretVal)

				if entropy >= minEntropy {
					findings = append(findings, Finding{
						FilePath:    path,
						LineNumber:  lineNumber,
						LineContent: strings.TrimSpace(line),
						PatternName: name,
						MatchedText: secretVal,
						Entropy:     entropy,
					})
				}
			}
		}
	}
	return findings, scanner.Err()
}

// --- Main Execution ---

func main() {
	os.Exit(run())
}

func run() int {
	config := Config{}
	flag.StringVar(&config.Path, "path", ".", "Path to scan")
	flag.StringVar(&config.Format, "format", "text", "Output format (json, text)")
	flag.StringVar(&config.Output, "output", "", "Output file")
	flag.Float64Var(&config.MinEntropy, "min-entropy", 3.0, "Minimum entropy to report")
	flag.BoolVar(&config.GitIgnore, "git-ignore", true, "Honor .gitignore files")
	flag.IntVar(&config.Threads, "threads", 8, "Concurrent threads")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose logging")
	flag.Parse()

	if config.Verbose {
		fmt.Printf("SecretScan %s | Path: %s | GitIgnore: %v | MinEntropy: %.2f\n",
			Version, config.Path, config.GitIgnore, config.MinEntropy)
	}

	// 1. Load External Patterns
	LoadExternalPatterns(config.Verbose)

	// 2. Setup GitIgnore
	var ignoreMatcher *GitIgnoreMatcher
	if config.GitIgnore {
		ignoreMatcher = NewGitIgnoreMatcher(config.Path)
	}

	// 3. Start Workers
	filesChan := make(chan string, 100)
	resultsChan := make(chan []Finding, 100)
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range filesChan {
				findings, err := scanFile(path, config.MinEntropy)
				if err == nil && len(findings) > 0 {
					resultsChan <- findings
				}
			}
		}()
	}

	// 4. Collector
	var allFindings []Finding
	doneChan := make(chan bool)
	go func() {
		for findings := range resultsChan {
			allFindings = append(allFindings, findings...)
		}
		doneChan <- true
	}()

	// 5. Walk Files
	startTime := time.Now()
	count := 0

	err := filepath.Walk(config.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if shouldSkipPath(path, ignoreMatcher, config.GitIgnore) {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() || shouldSkipPath(path, ignoreMatcher, config.GitIgnore) {
			return nil
		}

		count++
		filesChan <- path
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	close(filesChan)
	wg.Wait()
	close(resultsChan)
	<-doneChan

	duration := time.Since(startTime)

	// --- Output ---

	if config.Output != "" {
		f, err := os.Create(config.Output)
		if err != nil {
			fmt.Printf("Error creating output: %v\n", err)
			return 1
		}
		defer f.Close()
		os.Stdout = f
	}

	if config.Format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(allFindings)
	} else {
		if len(allFindings) == 0 {
			fmt.Println("\x1b[32mNo secrets found! \x1b[0m")
		} else {
			fmt.Printf("\x1b[33mFound %d potential secrets:\x1b[0m\n\n", len(allFindings))
			for _, f := range allFindings {
				fmt.Printf("\x1b[33mFile: %s\x1b[0m\n", f.FilePath)
				fmt.Printf("Line %d: %s\n", f.LineNumber, f.LineContent)
				fmt.Printf("Pattern: \x1b[31m%s\x1b[0m\n", f.PatternName)
				fmt.Printf("Entropy: %.2f\n\n", f.Entropy)
			}
			fmt.Printf("Summary: Scanned %d files in %v\n", count, duration)
		}
	}

	if len(allFindings) > 0 {
		return 1
	}
	return 0
}