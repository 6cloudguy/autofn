#!/bin/bash

echo -e "\033[1;36m[*] Installing all required tools...\033[0m"

# Install APT-based tools
sudo apt update
sudo apt install -y golang ffuf curl nmap exploitdb

# Set Go PATH if not already in shell config
GOBIN="/usr/lib/go/bin"
GOPATH_BIN="$HOME/go/bin"

if ! grep -q "$GOPATH_BIN" ~/.zshrc 2>/dev/null && [ -d "$GOPATH_BIN" ]; then
    echo "export PATH=\"\$PATH:$GOPATH_BIN\"" >> ~/.zshrc
    echo -e "\033[1;33m[+] Added Go bin to PATH in ~/.zshrc\033[0m"
elif ! grep -q "$GOPATH_BIN" ~/.bashrc 2>/dev/null && [ -d "$GOPATH_BIN" ]; then
    echo "export PATH=\"\$PATH:$GOPATH_BIN\"" >> ~/.bashrc
    echo -e "\033[1;33m[+] Added Go bin to PATH in ~/.bashrc\033[0m"
fi

# Install assetfinder if missing
if ! command -v assetfinder &>/dev/null; then
    echo -e "\033[1;33m[+] Installing assetfinder...\033[0m"
    go install github.com/tomnomnom/assetfinder@latest
fi

echo -e "\033[1;32m[✓] All tools installed successfully.\033[0m"
echo -e "\033[1;36m[*] Restart your terminal or run: source ~/.zshrc or ~/.bashrc\033[0m"
