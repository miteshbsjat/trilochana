package main

import (
    "bufio"
	"bytes"
	"fmt"
	"log"
    "os"
    "path/filepath"
    "regexp"
    "strings"
	"unicode"
)

// isDockerfile returns true if the supplied path points to a real Dockerfile.
// It checks two things:
//
// 1. The file name – it must be “Dockerfile” (case‑insensitive) or end with
//    “.Dockerfile” / “.dockerfile”. This catches the common naming conventions.
// 2. The file contents – at least one non‑empty line must start with a known
//    Dockerfile instruction (e.g. FROM, RUN, CMD, COPY, …). This helps avoid
//    false‑positives such as a plain text file named “Dockerfile.txt”.
func isDockerfile(filePath string) (bool, error) {
    // ----- 1. Name check ----------------------------------------------------
    base := filepath.Base(filePath)
    lower := strings.ToLower(base)

    if lower != "dockerfile" && !strings.HasSuffix(lower, ".dockerfile") {
        return false, nil
    }

    // ----- 2. Content check --------------------------------------------------
    f, err := os.Open(filePath)
    if err != nil {
        return false, err // caller can decide what to do (e.g. treat as non‑Dockerfile)
    }
    defer f.Close()

    // Dockerfile instructions (most common ones). The list can be extended.
    instructions := []string{
        "FROM", "MAINTAINER", "RUN", "CMD", "LABEL", "EXPOSE",
        "ENV", "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER",
        "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK",
        "SHELL",
    }
    // Build a regex that matches any of the above at the start of a line,
    // optionally preceded by whitespace and followed by a space, tab or end‑of‑line.
    pattern := `(?i)^\s*(` + strings.Join(instructions, "|") + `)(\s|$)`
    re := regexp.MustCompile(pattern)

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        // Skip empty lines and comments.
        trim := strings.TrimSpace(line)
        if trim == "" || strings.HasPrefix(trim, "#") {
            continue
        }
        if re.MatchString(line) {
            return true, nil // we found a Dockerfile instruction
        }
    }
    // If we reach here either the file is empty / has no Dockerfile
    // directives or it failed to read.
    if err := scanner.Err(); err != nil {
        return false, err
    }
    return false, nil
}

// ParseDockerCopy extracts the source paths from all COPY/ADD instructions
// in the Dockerfile located at dockerfilePath.
// The returned slice contains the raw strings that appear before the final
// destination argument of each instruction.
// Errors are returned only for I/O problems; a malformed instruction is
// reported as an error but does not stop the whole scan.
func ParseDockerCopy(dockerfilePath string) ([]string, error) {
    f, err := os.Open(dockerfilePath)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var (
        // pattern that matches a COPY or ADD line (ignoring leading whitespace)
        instrRe = regexp.MustCompile(`(?i)^\s*(COPY|ADD)\s+(.*)`)
        // temporary buffer that holds a possibly multi‑line instruction
        continued bytes.Buffer
        // final result
        sources []string
    )

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()

        // Remove comments – everything after an unescaped '#'
        if idx := strings.Index(line, "#"); idx != -1 {
            line = line[:idx]
        }
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        // Handle line continuation with backslash
        if strings.HasSuffix(line, "\\") {
            continued.WriteString(strings.TrimSuffix(line, "\\")) // keep the part before '\'
            continued.WriteByte(' ')                              // separate tokens
            continue
        }

        // If we were collecting a continued line, finish it now
        if continued.Len() > 0 {
            continued.WriteString(line)
            line = continued.String()
            continued.Reset()
        }

        // See whether this line is a COPY/ADD instruction
        matches := instrRe.FindStringSubmatch(line)
        if matches == nil {
            continue // not a COPY/ADD – ignore
        }
        args := matches[2] // the raw argument string after the keyword

        // Split args while respecting quoted strings.
        // Dockerfile syntax allows single or double quotes around paths.
        parts, err := splitDockerArgs(args)
        if err != nil {
            return nil, fmt.Errorf("failed to parse arguments on line %q: %w", line, err)
        }
        if len(parts) < 2 {
            // At least one source and one destination are required
            return nil, fmt.Errorf("invalid COPY/ADD instruction (too few arguments): %q", line)
        }

        // Remove any leading option flags (e.g. --chown=user:group, --from=stage, --chmod=777)
        srcStart := 0
        for srcStart < len(parts) && strings.HasPrefix(parts[srcStart], "--") {
            srcStart++
        }
        // The destination is always the last argument; everything before it are sources
        destIdx := len(parts) - 1
        if srcStart > destIdx-1 {
            // No source left after stripping flags – malformed line
            return nil, fmt.Errorf("no source paths found in instruction: %q", line)
        }
        sources = append(sources, parts[srcStart:destIdx]...)
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return sources, nil
}

// splitDockerArgs splits a Dockerfile instruction argument string into separate
// tokens, honouring single‑ and double‑quoted values and escaped spaces.
// It mirrors the behaviour of Docker's own parser sufficiently for COPY/ADD.
func splitDockerArgs(s string) ([]string, error) {
    var (
        parts   []string
        current bytes.Buffer
        inQuote rune // 0 = not in quote, otherwise '\'' or '"'
        escaped bool
    )

    for _, r := range s {
        switch {
        case escaped:
            // Whatever follows a backslash is taken literally
            current.WriteRune(r)
            escaped = false
        case r == '\\':
            escaped = true
        case inQuote != 0:
            if r == inQuote {
                // End of quoted segment
                inQuote = 0
            } else {
                current.WriteRune(r)
            }
        case r == '\'' || r == '"':
            inQuote = r // start quoted segment
        case unicode.IsSpace(r):
            if current.Len() > 0 {
                parts = append(parts, current.String())
                current.Reset()
            }
        default:
            current.WriteRune(r)
        }
    }
    if escaped {
        return nil, fmt.Errorf("dangling escape character at end of argument list")
    }
    if inQuote != 0 {
        return nil, fmt.Errorf("unterminated quote in argument list")
    }
    if current.Len() > 0 {
        parts = append(parts, current.String())
    }
    return parts, nil
}

func main() {
    // path := "./Dockerfile"
    path := "./go.mod"

    ok, err := isDockerfile(path)
    if err != nil {
        fmt.Printf("error checking %s: %v\n", path, err)
        return
    }
    if ok {
        fmt.Println(path, "looks like a Dockerfile")
    } else {
        fmt.Println(path, "does NOT look like a Dockerfile")
    }

	// ---------------
	sources, err := ParseDockerCopy("./Dockerfile")
    if err != nil {
        log.Fatalf("error parsing Dockerfile: %v", err)
    }
    fmt.Println("Sources that will be copied into the image:")
    for _, src := range sources {
        fmt.Println(" -", src)
    }
}