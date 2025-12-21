# Dockerizing Trilochana to Run in CI/CD

This Dockerfile uses a **Builder** stage to compile the Go binary and a minimal **Runner** stage (Alpine Linux) to keep the final image size small while ensuring you have the necessary environment to scan files.

### 🛠️ How to Build and Run

**1. Build the Image**

```bash
docker build -t miteshsjat/trilochana .

```

**2. Run a Scan**
Since Trilochana is a CLI tool designed to scan files, you must mount the directory you want to scan into the container's `/scan` directory.

To scan your current directory:

```bash
docker run --rm -it -v "$(pwd):/scan" miteshsjat/trilochana

```

**3. Pass Custom Arguments**
You can override the default `CMD` to pass specific flags (like `--min-entropy` or `--format`):

```bash
# Example: Scan with JSON output and custom entropy
docker run --rm -it -v "$(pwd):/scan" miteshsjat/trilochana \
  --path /scan --format json --min-entropy 4.5

```

**4. Pass Custom Regex Configuration**
You can provide custom regex patterns in two ways: mounting to the default global location or using the specific `--config` argument.

**Option A: Mount to Default Location** (Global Config)
Mount your local config to `/root/.config/trilochana/regex.json`. This is loaded automatically.

```bash
docker run --rm -it -v "$HOME/.config/trilochana/regex.json:/root/.config/trilochana/regex.json" \
  -v "$(pwd):/scan" miteshsjat/trilochana

```

**Option B: Use `--config` Argument** (Project Specific)
Mount your specific config file to a path inside the container and point Trilochana to it.

```bash
# Mount local 'custom-secrets.json' to '/custom-secrets.json' inside container
docker run --rm -it \
  -v "$(pwd)/custom-secrets.json:/custom-secrets.json" \
  -v "$(pwd):/scan" \
  miteshsjat/trilochana \
  --path /scan --config /custom-secrets.json

```

### 🔍 Key Design Decisions

* **Golang Version**: `golang:1.24-alpine` is selected to match the `go 1.24.5` directive given in `go.mod` file.
* **Static Linking**: The `CGO_ENABLED=0` flag is used during the build. This ensures the binary does not rely on external C libraries, making it perfectly safe to run in a stripped-down Alpine or even Scratch container.
* **Stripping Debug Info**: The `-ldflags="-s -w"` reduces the final binary size by removing symbol tables and DWARF debug information.
* **Volume Mount**: The default `CMD` points to `/scan`, encouraging the standard Docker pattern of mounting your source code volume to that specific path.
