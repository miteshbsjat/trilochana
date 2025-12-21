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
docker run --rm -v "$(pwd):/scan" miteshsjat/trilochana

```

**3. Pass Custom Arguments**
You can override the default `CMD` to pass specific flags (like `--min-entropy` or `--format`):

```bash
# Example: Scan with JSON output and custom entropy
docker run --rm -v "$(pwd):/scan" miteshsjat/trilochana \
  --path /scan --format json --min-entropy 4.5
```

### 🔍 Key Design Decisions

* **Golang Version**: I selected `golang:1.24-alpine` to match the `go 1.24.5` directive found in your `go.mod` file.
* **Static Linking**: The `CGO_ENABLED=0` flag is used during the build. This ensures the binary does not rely on external C libraries, making it perfectly safe to run in a stripped-down Alpine or even Scratch container.
* **Stripping Debug Info**: The `-ldflags="-s -w"` reduces the final binary size by removing symbol tables and DWARF debug information.
* **Volume Mount**: The default `CMD` points to `/scan`, encouraging the standard Docker pattern of mounting your source code volume to that specific path.

