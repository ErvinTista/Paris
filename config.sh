#!/bin/bash

# Ensure script is run with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo privileges."
    exit 1
fi

# Variables
TMP_DIR="/tmp"
TOOLS_DIR="$HOME/Tools/ligolo"
URLS=(
    "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2-alpha/ligolo-ng_agent_0.7.2-alpha_linux_amd64.tar.gz"
    "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2-alpha/ligolo-ng_proxy_0.7.2-alpha_linux_arm64.tar.gz"
    "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2-alpha/ligolo-ng_agent_0.7.2-alpha_windows_amd64.zip"
    "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2-alpha/ligolo-ng_proxy_0.7.2-alpha_windows_amd64.zip"
)

# Download files
echo "Downloading files..."
for url in "${URLS[@]}"; do
    wget -P "$TMP_DIR" "$url"
done

# Unzip and extract files
echo "Unzipping and extracting files..."
for file in "$TMP_DIR"/*; do
    case $file in
        *.tar.gz)
            tar -xzf "$file" -C "$TMP_DIR"
            ;;
        *.zip)
            unzip -o "$file" -d "$TMP_DIR"
            ;;
    esac
done

# Create destination directory
echo "Creating tools directory..."
mkdir -p "$TOOLS_DIR"

# Move extracted files to Tools directory
echo "Moving files to $TOOLS_DIR..."
mv "$TMP_DIR"/* "$TOOLS_DIR" 2>/dev/null

# Cleanup
echo "Cleaning up temporary files..."
rm -rf "$TMP_DIR"/*.tar.gz "$TMP_DIR"/*.zip

echo "Setup complete. All files are in $TOOLS_DIR."
