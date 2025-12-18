#!/bin/bash

BASE_DIR="/tmp/trilochana_test"
# Configuration
BINARY="$BASE_DIR/trilochana"
# Base test environment folder
TEST_ENV="$BASE_DIR"
# Sub-directory where actual test files will reside
TEST_DIR="$TEST_ENV/tests"
# Config directory for external regex
CONFIG_DIR="$HOME/.config/trilochana"
REGEX_FILE="$CONFIG_DIR/regex.json"
BACKUP_FILE="$CONFIG_DIR/regex.json.bak"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "🔨 Building Trilochana..."
go build -o trilochana main.go || { echo "Build failed"; exit 1; }

# Setup Test Environment
# 1. Clean previous runs
rm -rf "$TEST_ENV"
# 2. Create base structure
mkdir -p "$TEST_DIR"
# 3. Copy binary to base test env
cp "trilochana" "$TEST_ENV/"

# Save current path to jump back later
START_DIR=$(pwd)
cd "$TEST_ENV"

# Function to check exit code
check_exit() {
    expected=$1
    actual=$2
    msg=$3
    if [ $expected -eq $actual ]; then
        echo -e "${GREEN}PASS:${NC} $msg"
    else
        echo -e "${RED}FAIL:${NC} $msg (Expected $expected, got $actual)"
    fi
}

echo "----------------------------------------"
echo "Running tests on directory: tests/"
echo "----------------------------------------"

# Note: We are running ./trilochana from TEST_ENV, pointing it to tests/ directory.

# TEST 1: Basic Detection
# Objective: Scan 'tests/' and find the secret
echo 'aws_key = "AKIAIOSFODNN7EXAMPLE"' > "tests/secrets.txt"
./trilochana --path tests > /dev/null
check_exit 1 $? "Basic Secret Detection"
rm -f tests/secrets.txt

# TEST 2: Entropy Filtering
# Objective: "password" (low entropy) vs "7f8a9b..." (high entropy) inside tests/
echo 'key="password"' > "tests/entropy.txt"
echo 'secret="63OCAnowX/2sKk3UdFb8rzXT55bjSpV1SPEDxxxx"' >> "tests/entropy.txt"
# Run scan on tests/ with min-entropy 3.5
# We expect exactly 1 finding (the high entropy one)
count=$(./trilochana --path tests --min-entropy 3.9 | grep "Found 1 potential" | wc -l)
if [ "$count" -eq "1" ]; then
    echo -e "${GREEN}PASS:${NC} Entropy Filtering"
else
    echo -e "${RED}FAIL:${NC} Entropy Filtering"
fi
rm -f tests/entropy.txt

# TEST 3: GitIgnore Integration
# Objective: .gitignore in 'tests/' root should prevent scanning of ignored files
echo "secret=AKIAIOSFODNN7EXAMPLE" > "tests/ignored.txt"
echo "ignored.txt" > "tests/.gitignore"

# 3a. Default behavior (Honors .gitignore) -> Should NOT find secret -> Exit 0
./trilochana --path tests > /dev/null
check_exit 0 $? "GitIgnore Integration (Default)"

# 3b. Disabled gitignore -> Should FIND secret -> Exit 1
./trilochana --path tests --git-ignore=false > /dev/null
check_exit 1 $? "GitIgnore Disabled flag"

# TEST 4: Trilochana Ignore (Hard Ignore)
# Objective: Ignore specific file:line in tests/
echo "hard_ignore_secret=AKIAIOSFODNN7EXAMPLE" > "tests/hard_ignore.txt"
# IMPORTANT: paths in .trilochanaignore are relative to the scan root.
# Since we scan "--path tests", the file relative path is just "hard_ignore.txt".
echo "hard_ignore.txt:1" > "tests/.trilochanaignore"
./trilochana --path tests > /dev/null
check_exit 0 $? "Trilochana Hard Ignore"

# TEST 5: Trilochana Ignore (Entropy Threshold)
# Setup file in tests/
# Line 1: "simple" (low entropy). Rule: Ignore if <= 3.0
# Line 2: "complex123!@#" (high entropy). Rule: Ignore if <= 3.0 (Should FAIL rule and REPORT)
echo 'secret=AKIAIsimplesimplesim' > "tests/threshold.txt"
echo 'secret=AKIAIcomplex123C0MPl' >> "tests/threshold.txt"

# Update .trilochanaignore in tests/
echo "threshold.txt:1:3.5" > "tests/.trilochanaignore"
echo "threshold.txt:2:3.5" >> "tests/.trilochanaignore"

# Run with global min-entropy 0 to ensure logic is driven by ignore file
output=$(./trilochana --path tests --min-entropy 0)

# Check logic: Should capture complex string, should NOT capture simple string
if [ $(echo "$output" | grep -c 'complex') -ge 1 ]; then
     echo -e "${GREEN}PASS:${NC} Entropy Threshold Ignore Complex"
else
     echo -e "${RED}FAIL:${NC} Entropy Threshold Ignore Complex"
fi
if [ $(echo "$output" | grep -c 'simple') -eq 0 ]; then
     echo -e "${GREEN}PASS:${NC} Entropy Threshold Ignore Simple"
else
     echo -e "${RED}FAIL:${NC} Entropy Threshold Ignore Simple"
fi

# TEST 6: Custom Regex Config
# This uses the global home dir config, which works regardless of scan path
mkdir -p "$CONFIG_DIR"

# 1. Check if config exists and back it up
if [ -f "$REGEX_FILE" ]; then
    cp "$REGEX_FILE" "$BACKUP_FILE"
    
    # 2. Merge existing config with test pattern using a temporary Go script
    # This avoids dependency on 'jq' and ensures safe JSON handling
    cat <<EOF > merge_config.go
package main
import (
	"encoding/json"
	"os"
)
func main() {
	filePath := "$REGEX_FILE"
	content, _ := os.ReadFile(filePath)
	var data map[string]string
	
	// Unmarshal existing data
	if len(content) > 0 {
		json.Unmarshal(content, &data)
	}
	if data == nil {
		data = make(map[string]string)
	}
	
	// Add/Overwrite Test Pattern
	data["TestPattern"] = "TEST-[0-9a-zA-Z]{10}"
	
	// Write back
	output, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(filePath, output, 0644)
}
EOF
    go run merge_config.go
    rm merge_config.go
else
    # File doesn't exist, create it new
    echo '{ "TestPattern": "TEST-[0-9A-Za-z]{10}" }' > "$REGEX_FILE"
fi

# 3. Create test file matching the pattern
echo "TEST-1234567890" > "tests/custom_regex.txt"

# 4. Run the test
if [ $(./trilochana --path tests | grep -c "TestPattern") -eq 1 ]; then
    echo -e "${GREEN}PASS:${NC} Custom Regex Config"
else
    echo -e "${RED}FAIL:${NC} Custom Regex Config"
fi
# ---------------------------------------------------------

# Cleanup
cd "$START_DIR"
# rm -rf "$TEST_ENV"

# Restore original config
if [ -f "$BACKUP_FILE" ]; then
    mv "$BACKUP_FILE" "$REGEX_FILE"
    # echo "Restored original regex.json"
elif [ -f "$REGEX_FILE" ]; then
    # If we created it fresh and no backup exists, remove it to leave system clean
    rm "$REGEX_FILE"
    # echo "Removed test regex.json"
fi

echo "----------------------------------------"
echo "Tests Complete."