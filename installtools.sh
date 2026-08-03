#!/usr/bin/env bash

set -e

# echo "Updating package list..."
# sudo apt update

# echo "Installing Semgrep..."
# python3 -m pip install  semgrep

# echo "Installing Gitleaks..."
# GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d '"' -f4)

# wget -q https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz

# tar -xzf gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz

# sudo mv gitleaks /usr/local/bin/

# rm gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz

# echo "Installing Trivy..."

# curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# sudo mv ./bin/trivy /usr/local/bin/

# rm -rf bin

echo "Installing OWASP Dependency-Check..."

DC_VERSION=""

wget -q https://github.com/dependency-check/DependencyCheck/releases/download/v12.1.8/dependency-check-12.1.8-release.zip

unzip -q dependency-check-12.1.8-release.zip

sudo mv dependency-check /opt/

sudo ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

rm dependency-check-12.1.8-release.zip

echo ""
echo "Installed versions:"
echo "-------------------"

semgrep --version
gitleaks version
trivy --version
dependency-check --version

echo ""
echo "Installation complete."