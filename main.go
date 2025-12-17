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
	Version = "0.2.0-go"
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

// --- GitIgnore Logic ---

type GitIgnoreMatcher struct {
	patterns []string
	baseDir  string
}

// NewGitIgnoreMatcher loads .gitignore from the scan root if it exists
func NewGitIgnoreMatcher(rootPath string) *GitIgnoreMatcher {
	matcher := &GitIgnoreMatcher{
		baseDir: rootPath,
	}

	gitIgnorePath := filepath.Join(rootPath, ".gitignore")
	file, err := os.Open(gitIgnorePath)
	if err != nil {
		// No .gitignore found or readable, return empty matcher
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

// IsIgnored checks if a file path matches any gitignore pattern
func (m *GitIgnoreMatcher) IsIgnored(path string) bool {
	if len(m.patterns) == 0 {
		return false
	}

	// Get relative path from the scan root
	relPath, err := filepath.Rel(m.baseDir, path)
	if err != nil {
		return false
	}
	
	// Normalize path separators for pattern matching
	relPath = filepath.ToSlash(relPath)

	for _, pattern := range m.patterns {
		// Handle directory specific patterns (ending in /)
		isDirPattern := strings.HasSuffix(pattern, "/")
		cleanPattern := strings.TrimSuffix(pattern, "/")

		// 1. Exact Match (e.g., "node_modules")
		if relPath == cleanPattern || strings.HasPrefix(relPath, cleanPattern+"/") {
			return true
		}

		// 2. Wildcard Match (e.g., "*.log")
		matched, _ := filepath.Match(cleanPattern, filepath.Base(relPath))
		if matched {
			if !isDirPattern {
				return true
			}
			// If it's a dir pattern, we must ensure we are inside that dir
			// (Simple heuristic: filepath.Match matched the name, so check context if needed)
			return true 
		}

		// 3. Path Glob Match (e.g., "dist/*.js")
		matchedFull, _ := filepath.Match(cleanPattern, relPath)
		if matchedFull {
			return true
		}
	}
	return false
}

// --- Scanning Logic ---

// shouldSkipPath checks system defaults + gitignore
func shouldSkipPath(path string, ignoreMatcher *GitIgnoreMatcher, useGitIgnore bool) bool {
	lowerPath := strings.ToLower(path)
	
	// 1. Built-in hardcoded ignores (always active)
	ignoredDirs := []string{".git", ".idea", ".vscode", "node_modules", "vendor", "target", "dist", "build"}
	for _, dir := range ignoredDirs {
		if strings.Contains(lowerPath, string(os.PathSeparator)+dir+string(os.PathSeparator)) || strings.HasPrefix(lowerPath, dir+string(os.PathSeparator)) {
			return true
		}
	}

	// 2. Binary extensions
	ext := filepath.Ext(lowerPath)
	binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".zip", ".tar", ".gz", ".png", ".jpg", ".jpeg", ".pdf", ".lock", ".bin"}
	for _, bin := range binaryExts {
		if ext == bin {
			return true
		}
	}

	// 3. Dynamic .gitignore check
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
	
	// Increase buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		
		if len(line) > 2000 { // Optimization: skip excessively long lines
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

				// --- MIN ENTROPY FILTER ---
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

	// Initialize GitIgnore Matcher
	var ignoreMatcher *GitIgnoreMatcher
	if config.GitIgnore {
		ignoreMatcher = NewGitIgnoreMatcher(config.Path)
		if config.Verbose && len(ignoreMatcher.patterns) > 0 {
			fmt.Printf("Loaded %d patterns from .gitignore\n", len(ignoreMatcher.patterns))
		}
	}

	filesChan := make(chan string, 100)
	resultsChan := make(chan []Finding, 100)
	var wg sync.WaitGroup

	// Start Workers
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

	// Result Collector
	var allFindings []Finding
	doneChan := make(chan bool)
	go func() {
		for findings := range resultsChan {
			allFindings = append(allFindings, findings...)
		}
		doneChan <- true
	}()

	// File Walker
	startTime := time.Now()
	count := 0
	
	err := filepath.Walk(config.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// Check ignores for directory
			if shouldSkipPath(path, ignoreMatcher, config.GitIgnore) {
				if config.Verbose {
					fmt.Printf("[Skip Dir] %s\n", path)
				}
				return filepath.SkipDir
			}
			return nil
		}
		
		// Check ignores for file
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

	// Output
	if config.Output != "" {
		f, err := os.Create(config.Output)
		if err != nil {
			fmt.Printf("Error creating output: %v\n", err)
			os.Exit(1)
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
}