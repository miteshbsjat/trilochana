# Trilochana 👁️👁️👁️

![TriLochana](docs/images/trilochana.png)

**Trilochana** (Sanskrit for "Three-eyed", implying all-seeing) is a blazing-fast, concurrent secret scanning tool written in Go. It helps developers detect hardcoded secrets, API keys, and credentials in their codebase before they are committed to version control.

It features parallel file scanning, entropy-based filtering, and flexible ignore mechanisms (including `.gitignore` and a custom `.trilochanaignore`).

## ✨ Features

* **🚀 High Performance**: Concurrent scanning using Go routines (worker pool pattern).
* **🔍 Entropy Analysis**: Calculates Shannon entropy to filter out false positives (e.g., skips simple strings like `password123` while catching complex keys).
* **🛡️ Ignore Systems**:
    * **`.gitignore`**: Automatically respects your project's existing ignore rules.
    * **`.trilochanaignore`**: Fine-grained ignoring of specific file/line combinations, with optional entropy thresholds.
* **🔧 Customizable Patterns**: Extend the built-in regex library with your own JSON configuration file.
* **📊 Output Formats**: Supports human-readable text output and machine-readable JSON for CI/CD pipelines.

## 📦 Installation

### Build from Source

**Requirements:** Go 1.18+

```bash
# Clone the repository
git clone https://github.com/miteshbsjat/trilochana.git
cd trilochana

# Initialize module (if not already done)
go mod init trilochana
go mod tidy

# Build the binary
go build -o trilochana main.go

# (Optional) Move to your path
sudo mv trilochana /usr/local/bin/
```


## 🚀 Usage

Basic scan of the current directory:

```bash
trilochana

```

### Command Line Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--path` | Directory path to scan | `.` (current dir) |
| `--min-entropy` | Minimum Shannon entropy threshold. Matches below this are ignored. | `3.0` |
| `--git-ignore` | Honor `.gitignore` files. Set to `false` to scan everything. | `true` |
| `--format` | Output format: `text` or `json`. | `text` |
| `--output` | Write results to a specific file instead of stdout. | (stdout) |
| `--threads` | Number of concurrent worker threads. | `8` |
| `--verbose` | Enable verbose logging (useful for debugging config loading). | `false` |

### Examples

**Scan a specific project with strict entropy filtering:**

```bash
trilochana --path /path/to/project --min-entropy 4.5

```

**Generate JSON report for CI/CD:**

```bash
trilochana --format json --output secrets_report.json

```

**Scan everything (ignoring .gitignore):**

```bash
trilochana --git-ignore=false

```

## ⚙️ Configuration

### 1. Custom Regex Patterns

You can add your own secret detection patterns without recompiling.
Create a file at `~/.config/trilochana/regex.json`:

```json
{
  "Company Internal Token": "INT-[A-Z0-9]{12}",
  "Stripe Test Key": "sk_test_[0-9a-zA-Z]{24}"
}

```

*Note: These will merge with (or override) the built-in patterns.*

### 2. Ignoring False Positives (`.trilochanaignore`)

Create a `.trilochanaignore` file in the root of your scan path to whitelist specific findings.

**Format:** `relative_path:line_number[:max_entropy]`

* **Hard Ignore**: `file:line`
  * Ignores *any* match on that line, regardless of entropy.


* **Entropy Threshold Ignore**: `file:line:entropy`
  * Ignores the match *only if* its entropy is **less than or equal to** the specified value.
  * If a new secret with *higher* entropy appears on that line, it will trigger an alert.



**Example `.trilochanaignore`:**

```text
# Ignore the dummy password in the config example (hard ignore)
config/example.yaml:12

# Ignore this specific test token (entropy ~3.5), 
# but alert me if a real high-entropy key (entropy > 4.0) is put here.
src/tests/auth_test.go:45:4.0

```

## 🛡️ Built-in Detection Patterns

Trilochana comes pre-configured to detect:

* AWS Access Key IDs & Secret Keys (with flexible prefixes)
* GitHub Personal Access Tokens & OAuth
* Private Keys (RSA, SSH, Generic PEM)
* Stripe, Slack, & Google API Keys
* Database Connection Strings (Postgres, MySQL, Mongo)
* Generic "high entropy" assignments (e.g., `api_key = "..."`)

---

## 🚀 Pre-commit Integration

Trilochana supports [pre-commit](https://pre-commit.com/), allowing you to automate security scans every time you commit code.

To use Trilochana with pre-commit, add the following configuration to your `.pre-commit-config.yaml` file:

```yaml
repos:
  # Standard hooks for code hygiene
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v3.2.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-added-large-files

  # Trilochana local hook for secret scanning
  - repo: local
    hooks:
      - id: secretscan
        name: Secret Scanning
        entry: trilochana -min-entropy 4.2 git file://. --since-commit HEAD --only-verified --fail
        language: system
        stages: [pre-commit, pre-push]
        pass_filenames: false

```

---

### 🛠 Configuration Details

The Trilochana hook used in the example above performs the following actions:

* **`-min-entropy 4.2`**: Flags any strings with an entropy score higher than 4.2 (common for encrypted keys or hashes).
* **`--since-commit HEAD`**: Scans changes introduced in the current session.
* **`--only-verified`**: Reduces noise by only reporting high-confidence matches.
* **`--fail`**: Ensures the commit process stops if a secret is detected.

### Requirements

To use the local hook, ensure that the `trilochana` binary is installed on your system and available in your `$PATH`.

---

### 📖 How to Install Pre-commit

If you haven't installed the pre-commit framework yet, you can do so via pip:

```bash
pip install pre-commit

```

Then, install the git hook scripts:

```bash
pre-commit install

```
---

## Using `trilochana` with CI/CD using docker container

This [document](docs/docker.md) shows how to use trilochana docker image on local machine or CI/CD stage.

---

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request or open an issue for bug reports.

## 📄 License

Apache 2.0 License