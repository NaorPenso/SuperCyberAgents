# Nuclei Installation Guide

Nuclei is a fast, template-based vulnerability scanner used by the NetworkSecurityAgent for security scanning. This guide covers installation and basic configuration across different operating systems.

## Prerequisites

- Go 1.21 or later (required for the latest Nuclei version)
- Git (to clone templates repository)

## Installation Methods

### Method 1: Using Go (Recommended)

The recommended way to install Nuclei is using Go:

```bash
# Install the latest version of Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Verify installation
nuclei -version

# IMPORTANT: Update templates (REQUIRED after installation)
nuclei -update-templates
```

Ensure your Go bin directory is in your PATH. Typically this is:
- Linux/macOS: `$HOME/go/bin`
- Windows: `%USERPROFILE%\go\bin`

### Method 2: Using GitHub Releases

1. Download the latest release from [Nuclei GitHub Releases](https://github.com/projectdiscovery/nuclei/releases)
2. Extract the archive:
   ```bash
   # For Linux/macOS
   tar -xzvf nuclei_*_linux_amd64.tar.gz  # For Linux
   tar -xzvf nuclei_*_macOS_amd64.tar.gz  # For macOS
   
   # For Windows
   # Extract the ZIP file using Explorer or 7-Zip
   ```
3. Move the binary to a directory in your PATH:
   ```bash
   # Linux/macOS
   sudo mv nuclei /usr/local/bin/
   
   # Windows
   # Move nuclei.exe to a directory in your PATH, or add its location to your PATH
   ```
4. **REQUIRED**: Update templates after installation:
   ```bash
   nuclei -update-templates
   ```

### Method 3: Using Docker

```bash
# Pull the Nuclei Docker image
docker pull projectdiscovery/nuclei

# Run Nuclei using Docker
docker run -it projectdiscovery/nuclei -h

# IMPORTANT: Update templates when using Docker
docker run -it projectdiscovery/nuclei -update-templates
```

## Platform-Specific Instructions

### macOS

If you have Homebrew installed:

```bash
# Install Nuclei using Homebrew
brew install nuclei

# Verify installation
nuclei -version

# REQUIRED: Update templates after installation
nuclei -update-templates
```

### Linux (Ubuntu/Debian)

```bash
# Install Go if not already installed
sudo apt update
sudo apt install -y golang-go

# Set GOPATH
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Verify installation
nuclei -version

# REQUIRED: Update templates after installation
nuclei -update-templates
```

### Windows

1. Install Go for Windows from [golang.org/dl](https://golang.org/dl/)
2. Install Git for Windows from [git-scm.com](https://git-scm.com/)
3. Open Command Prompt or PowerShell and run:
   ```powershell
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   
   # Verify installation (you may need to restart your terminal or computer)
   nuclei -version
   
   # REQUIRED: Update templates after installation
   nuclei -update-templates
   ```

## Version Compatibility Issues

Recent versions of Nuclei (v3.x) introduced changes to the command-line interface that may cause compatibility issues with scripts or tools written for older versions:

### Key Command Changes in Nuclei v3.x

| Old Command (v2.x) | New Command (v3.x) | Description |
|--------------------|-------------------|-------------|
| `-u example.com`   | `-target example.com` | Specifying target URL/domain |
| `-list targets.txt` | `-list targets.txt` (unchanged) | Target list file |
| `-silent` | `-silent` (unchanged) | Silent output mode |

If you encounter errors when using the NetworkSecurityAgent with Nuclei, check your installed version:

```bash
nuclei -version
```

### Version-Specific Notes:

- **Nuclei v2.x**: Uses `-u` for target specification
- **Nuclei v3.x**: Uses `-target` for target specification
- **SuperCyberAgents compatibility**: The tool has been updated to work with Nuclei v3.4.2+

To use NetworkSecurityAgent with older Nuclei versions (v2.x), you'll need to modify the `tools/network_tools.py` file to use `-u` instead of `-target`.

## Installing Nuclei Templates

Nuclei requires templates to scan for vulnerabilities. **This step is mandatory after installation** before you can run any scans:

```bash
# Update/download the templates (REQUIRED after installation)
nuclei -update-templates

# Verify templates were installed
nuclei -tl
```

Without templates, Nuclei will not find any vulnerabilities when scanning targets.

### Template Update Frequency

It's recommended to regularly update templates to detect the latest vulnerabilities:

```bash
# Update templates weekly or before important security assessments
nuclei -update-templates
```

## Troubleshooting

### Common Issues

1. **"nuclei: command not found"**:
   - Ensure Go bin directory is in your PATH
   - For Linux/macOS: `echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc`
   - For Windows: Add `%USERPROFILE%\go\bin` to your PATH environment variable

2. **"Error downloading templates"**:
   - Check your internet connection
   - Try running with sudo (Linux/macOS): `sudo nuclei -update-templates`
   - Manually clone the templates: `git clone https://github.com/projectdiscovery/nuclei-templates.git`

3. **Rate limiting issues during scans**:
   - Use the `-rate-limit` flag: `nuclei -u example.com -rate-limit 100`

4. **Command syntax errors**:
   - Ensure you're using the correct command syntax for your Nuclei version
   - For v3.x: Use `-target example.com` instead of `-u example.com`
   - For v2.x: Use `-u example.com` 

5. **"No vulnerabilities found" when expected**:
   - Verify templates are installed: `nuclei -tl | wc -l` (should show thousands of templates)
   - Try updating templates: `nuclei -update-templates`
   - Try running with verbose flag: `nuclei -target example.com -v`

## Integration with SuperCyberAgents

The NetworkSecurityAgent in SuperCyberAgents uses Nuclei internally. When running scans via the CLI or API, ensure Nuclei is properly installed and accessible from the PATH where you're running the application.

```bash
# Example CLI usage with SuperCyberAgents
poetry run python -m typer cli.main run scan-target example.com --severity medium
```

## Additional Resources

- [Nuclei GitHub Repository](https://github.com/projectdiscovery/nuclei)
- [Nuclei Documentation](https://nuclei.projectdiscovery.io/)
- [Nuclei Templates Repository](https://github.com/projectdiscovery/nuclei-templates) 