#!/usr/bin/env bash

# tool_installer.sh - Installer for external tools & core setup for SuperCyberAgents

# Exit on error, treat unset variables as errors, propagate pipeline errors
set -euo pipefail

# --- Colors for Output (Define early) ---
# Check if tput is available and terminal supports colors
if command -v tput >/dev/null && tput setaf 1 >/dev/null 2>&1; then
    COLOR_RESET=$(tput sgr0)
    COLOR_RED=$(tput setaf 1)
    COLOR_GREEN=$(tput setaf 2)
    COLOR_YELLOW=$(tput setaf 3)
    COLOR_BLUE=$(tput setaf 4)
    COLOR_BOLD=$(tput bold)
    COLOR_DIM=$(tput dim)
else
    # Fallback if tput is not available or colors not supported
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_BLUE=""
    COLOR_BOLD=""
    COLOR_DIM=""
fi

# --- Bash Version Check ---
# Associative arrays (declare -A) require Bash 4.0+. Script refactored to use indexed arrays,
# but warn if using a very old version.
if [[ -n "${BASH_VERSION:-}" && "${BASH_VERSION%%.*}" -lt 4 ]]; then
    # Use echo with printf for better compatibility if colors are disabled
    printf "%s⚠️ Warning: Running Bash v%s. Some advanced features might behave differently. Bash v4.0+ recommended.%s\n" \
        "$COLOR_YELLOW" "${BASH_VERSION}" "$COLOR_RESET"
fi

# --- Configuration ---

# Define required EXTERNAL tools using parallel arrays for Bash v3 compatibility
TOOL_NAMES=(
    "python"
    "git"
    "go"
    "nuclei"
    "nmap"
)
# Command to check existence (used for status)
TOOL_CHECKS_EXIST=(
    "command -v python3 || command -v python"
    "command -v git"
    "command -v go"
    "command -v nuclei"
    "command -v nmap"
)
# Command to get version if tool exists
TOOL_VERSION_CMDS=(
    "(python3 --version || python --version) 2>&1 | sed 's/Python //'" # Prefer python3
    "git --version | sed 's/git version //'"
    "go version | sed -E 's/go version (go[0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/'"
    "nuclei -version 2>&1 | grep 'Nuclei Engine Version:' | sed 's/.*\[INF\] Nuclei Engine Version: //'"
    "nmap --version | head -n 1 | sed 's/Nmap version \(.*\) ( .*/\1/'"
)
# Required version (can be specific or minimum like ">=3.4.0")
TOOL_REQUIRED_VERSIONS=(
    "3.10+"      # Example: Python 3.10 or later (check pyproject.toml)
    "N/A"       
    "go1.21+"   
    "v3.4.2+"
    "7.70+"
)
# Function name to call for installation
TOOL_INSTALL_FUNCS=(
    "install_python" # Will provide guidance
    "install_git"
    "install_go"    
    "install_nuclei"
    "install_nmap"
)

# Core setup requirement
CORE_SETUP_NAME="Project Core Setup"
CORE_POETRY_REQ_VERSION=">=1.2.0"

# --- Emojis for Status ---
ICON_SUCCESS="✅"
ICON_FAILED="❌"
ICON_WARNING="⚠️"
ICON_INFO="ℹ️"

# --- Helper Functions ---
log() { echo "${COLOR_BLUE}${ICON_INFO}${COLOR_BOLD} $1${COLOR_RESET}"; }
log_success() { echo "${COLOR_GREEN}${ICON_SUCCESS}${COLOR_BOLD} $1${COLOR_RESET}"; }
log_warning() { echo "${COLOR_YELLOW}${ICON_WARNING}${COLOR_BOLD} $1${COLOR_RESET}"; }
log_error() { echo "${COLOR_RED}${ICON_FAILED}${COLOR_BOLD} $1${COLOR_RESET}" >&2; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

confirm() {
    local prompt default reply
    prompt="$1"; default="${2:-y}"
    while true; do
        read -rp "$prompt [Y/n]: " reply
        reply=${reply:-$default}
        case "$reply" in
            [Yy]* ) return 0;; [Nn]* ) return 1;; * ) echo "Please answer yes or no.";;
        esac
    done
}

get_tool_index() {
    local tool_name="$1" i
    for i in "${!TOOL_NAMES[@]}"; do
        if [[ "${TOOL_NAMES[$i]}" == "$tool_name" ]]; then echo "$i"; return 0; fi
    done
    echo "-1"; return 1
}

get_os() {
    local os DISTRO
    os=$(uname -s)
    case "$os" in
        Linux*)
            if command_exists lsb_release; then DISTRO=$(lsb_release -si)
            elif [ -f /etc/os-release ]; then # shellcheck disable=SC1091
                 DISTRO=$(source /etc/os-release && echo "$ID")
            else DISTRO="Linux"; fi
            if grep -qi Microsoft /proc/version; then OS_TYPE="WSL"; else OS_TYPE="Linux"; fi
            OS_DISTRO="$DISTRO"
            ;;
        Darwin*) OS_TYPE="macOS"; OS_DISTRO="macOS";; 
        *) OS_TYPE="Unsupported"; OS_DISTRO="Unknown"; log_error "Unsupported OS: $os"; exit 1;;
    esac
    log "Detected OS: $OS_TYPE ($OS_DISTRO)"
}

# --- Status Check Header ---
print_check_header() {
    printf "${COLOR_BOLD}%-25s | %-18s | %-15s | %-15s${COLOR_RESET}\n" "Component" "Status" "Required Ver." "Installed Ver."
    printf "${COLOR_DIM}%-25s | %-18s | %-15s | %-15s${COLOR_RESET}\n" "-------------------------" "------------------" "---------------" "---------------"
}

# --- Tool Check Functions (Print Row Only) ---
check_external_tool_status_row() {
    local tool_name check_cmd_exist version_cmd tool_index installed_version required_version status_text status_color icon notes
    tool_name="$1"
    tool_index=$(get_tool_index "$tool_name")

    if [[ "$tool_index" -eq -1 ]]; then
        icon="${ICON_FAILED}"; status_text="Error"; status_color="$COLOR_RED"
        required_version="N/A"; installed_version="N/A"
        printf "%-25s | ${status_color}%-1s %-16s${COLOR_RESET} | %-15s | %-15s\n" \
            "Ext Tool: $tool_name" "$icon" "$status_text" "$required_version" "$installed_version"
        return 1
    fi

    check_cmd_exist="${TOOL_CHECKS_EXIST[$tool_index]}"
    version_cmd="${TOOL_VERSION_CMDS[$tool_index]}"
    required_version="${TOOL_REQUIRED_VERSIONS[$tool_index]:-N/A}"
    installed_version="N/A"
    local return_code=0

    # Special case for python to check python3 first
    if [[ "$tool_name" == "python" ]]; then
        if command -v python3 >/dev/null 2>&1; then
            check_cmd_exist="command -v python3"
            version_cmd="python3 --version 2>&1 | sed 's/Python //'"
        elif command -v python >/dev/null 2>&1; then
             check_cmd_exist="command -v python"
             version_cmd="python --version 2>&1 | sed 's/Python //'"
        else
            check_cmd_exist="command -v python_not_found" # Force failure
        fi
    fi

    if eval "$check_cmd_exist" >/dev/null 2>&1; then
        icon="${ICON_SUCCESS}"; status_text="Installed"; status_color="$COLOR_GREEN"
        installed_version=$(eval "$version_cmd" 2>/dev/null || echo "Unknown")
        installed_version=${installed_version:-Unknown}
        if [[ "$installed_version" == "Unknown" || -z "$installed_version" ]]; then
           installed_version="ErrorCheck"
        fi
        return_code=0
    else
        icon="${ICON_FAILED}"; status_text="Missing"; status_color="$COLOR_RED"
        return_code=1
    fi

    printf "%-25s | ${status_color}%-1s %-16s${COLOR_RESET} | %-15s | %-15s\n" \
        "Ext Tool: $tool_name" "$icon" "$status_text" "$required_version" "$installed_version"
    return $return_code
}

check_core_setup_rows() {
    local all_ok=true
    local poetry_version="N/A"
    local status_text="" status_color="" icon=""

    # Check pyproject.toml
    if [[ ! -f "pyproject.toml" ]]; then
        icon="${ICON_FAILED}"; status_text="Missing"; status_color="$COLOR_RED"; all_ok=false
        printf "%-25s | ${status_color}%-1s %-16s${COLOR_RESET} | %-15s | %-15s\n" \
            "Core: pyproject.toml" "$icon" "$status_text" "Required" "N/A"
    else
        icon="${ICON_SUCCESS}"; status_text="Found"; status_color="$COLOR_GREEN"
        printf "%-25s | ${status_color}%-1s %-16s${COLOR_RESET} | %-15s | %-15s\n" \
            "Core: pyproject.toml" "$icon" "$status_text" "Required" "Exists"
    fi

    # Check Poetry
    if ! command_exists poetry; then
        icon="${ICON_FAILED}"; status_text="Missing"; status_color="$COLOR_RED"; all_ok=false
        printf "%-25s | ${status_color}%-1s %-16s${COLOR_RESET} | %-15s | %-15s\n" \
            "Core: Poetry CLI" "$icon" "$status_text" "$CORE_POETRY_REQ_VERSION" "N/A"
    else
        poetry_version=$(poetry --version | sed -e 's/Poetry (version \(.*\))/\1/' -e 's/Poetry version \(.*\)/\1/' || echo "Unknown")
        poetry_version=${poetry_version:-Unknown}
        icon="${ICON_SUCCESS}"; status_text="Installed"; status_color="$COLOR_GREEN"
        printf "%-25s | ${status_color}%-1s %-16s${COLOR_RESET} | %-15s | %-15s\n" \
            "Core: Poetry CLI" "$icon" "$status_text" "$CORE_POETRY_REQ_VERSION" "$poetry_version"
    fi

    if $all_ok; then return 0; else return 1; fi
}

# --- Combined Check Function ---
run_all_checks() {
    log "Checking system status..."
    print_check_header
    local tools_ok=true
    local core_ok=true
    local tool_name

    # Check External Tools
    if [ ${#TOOL_NAMES[@]} -eq 0 ]; then
         printf "%-25s | ${COLOR_BLUE}%-1s %-16s${COLOR_RESET} | %-15s | %-15s\n" \
            "(No external tools)" "${ICON_INFO}" "Info" "N/A" "N/A"
    else
        for tool_name in "${TOOL_NAMES[@]}"; do
            if ! check_external_tool_status_row "$tool_name"; then
                tools_ok=false
            fi
        done
    fi

    # Check Core Setup
    if ! check_core_setup_rows; then
        core_ok=false
    fi

    echo # Newline after table

    # Print Summary
    if $tools_ok && $core_ok; then
        log_success "All system components seem OK."
        return 0
    else
        log_warning "Some system components require attention (see table above)."
        if ! $tools_ok; then log_warning "-> External tools need installation/update."; fi
        if ! $core_ok; then log_warning "-> Core setup needs installation/verification."; fi
        return 1
    fi
}

# --- Tool Installation Functions ---

install_via_go(){
    local package_path="$1" binary_name="$2"
    if ! command_exists go; then log_error "Go not found (required)."; log_warning "Install Go >= 1.21 from https://golang.org/doc/install"; return 1; fi
    log "Installing $binary_name via Go..."
    if go install -v "$package_path"; then
        log_success "$binary_name installed via Go."
        local go_bin_path="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
        if [[ ":$PATH:" != *":$go_bin_path:"* ]]; then log_warning "Go bin ($go_bin_path) may not be in PATH."; fi
        return 0
    else log_error "Go install failed for $binary_name."; return 1; fi
}

update_nuclei_templates(){ if command_exists nuclei; then log "Updating Nuclei templates..."; if nuclei -update-templates; then log_success "Nuclei templates updated."; else log_warning "Failed to update Nuclei templates."; fi; else log_warning "Cannot update templates: nuclei not found."; fi; }

install_nuclei(){
    log "Attempting Nuclei install..."
    local installed=false
    if check_external_tool_status_row "nuclei" > /dev/null; then log_success "Nuclei already installed."; update_nuclei_templates; return 0; fi
    case "$OS_TYPE" in
        macOS) if command_exists brew; then log "Using Homebrew..."; if brew install nuclei; then log_success "Installed via Brew."; installed=true; else log_error "Brew failed. Trying Go..."; if install_via_go "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" "nuclei"; then installed=true; fi; fi; else log "Brew not found. Trying Go..."; if install_via_go "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" "nuclei"; then installed=true; fi; fi ;; 
        Linux|WSL) log "Using Go..."; if install_via_go "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" "nuclei"; then installed=true; else log_warning "Go install failed. See https://github.com/projectdiscovery/nuclei#installation"; fi ;; 
        *) log_error "Cannot install on OS: $OS_TYPE"; return 1 ;; 
    esac
    if $installed; then update_nuclei_templates; log_success "Nuclei install complete."; return 0; else log_error "Nuclei install failed."; return 1; fi
}

install_nmap(){
    log "Attempting Nmap install..."
    local installed=false
    if check_external_tool_status_row "nmap" > /dev/null; then log_success "Nmap already installed."; return 0; fi
    log "Using system package manager to install nmap..."
    case "$OS_TYPE" in
        macOS) if command_exists brew; then if brew install nmap; then log_success "Nmap via Brew."; installed=true; else log_error "Brew install failed."; fi; else log_error "Brew not found."; fi ;; 
        Linux|WSL) 
            if command_exists apt-get; then if sudo apt-get update && sudo apt-get install -y nmap; then log_success "Nmap via apt."; installed=true; else log_error "apt install failed."; fi
            elif command_exists yum; then if sudo yum install -y nmap; then log_success "Nmap via yum."; installed=true; else log_error "yum install failed."; fi
            elif command_exists dnf; then if sudo dnf install -y nmap; then log_success "Nmap via dnf."; installed=true; else log_error "dnf install failed."; fi
            elif command_exists pacman; then if sudo pacman -Syu --noconfirm nmap; then log_success "Nmap via pacman."; installed=true; else log_error "pacman install failed."; fi
            else log_error "No common Linux pkg manager found."; fi ;; 
        *) log_error "Cannot install on OS: $OS_TYPE"; return 1 ;; 
    esac
    if $installed; then log_success "Nmap install OK."; check_external_tool_status_row "nmap"; return 0; else log_error "Nmap install failed."; log_warning "Install manually: https://nmap.org/download.html"; return 1; fi
}

install_git(){
    log "Attempting Git install..."
    local installed=false
    if check_external_tool_status_row "git" > /dev/null; then log_success "Git already installed."; return 0; fi
    log "Using system package manager to install git..."
    case "$OS_TYPE" in
        macOS) if command_exists brew; then if brew install git; then log_success "Git via Brew."; installed=true; else log_error "Brew install failed."; fi; else log_error "Brew not found, install Git manually (e.g. Xcode Command Line Tools)."; fi ;; 
        Linux|WSL) 
            if command_exists apt-get; then if sudo apt-get update && sudo apt-get install -y git; then log_success "Git via apt."; installed=true; else log_error "apt install failed."; fi
            elif command_exists yum; then if sudo yum install -y git; then log_success "Git via yum."; installed=true; else log_error "yum install failed."; fi
            elif command_exists dnf; then if sudo dnf install -y git; then log_success "Git via dnf."; installed=true; else log_error "dnf install failed."; fi
            elif command_exists pacman; then if sudo pacman -Syu --noconfirm git; then log_success "Git via pacman."; installed=true; else log_error "pacman install failed."; fi
            else log_error "No common Linux pkg manager found."; fi ;; 
        *) log_error "Cannot install on OS: $OS_TYPE"; return 1 ;; 
    esac
    if $installed; then log_success "Git install OK."; check_external_tool_status_row "git"; return 0; else log_error "Git install failed."; log_warning "Install Git manually from https://git-scm.com/downloads"; return 1; fi
}

install_go(){
    log "Checking Go installation..."
    if check_external_tool_status_row "go" > /dev/null; then
         log_success "Go appears to be installed."
         log_warning "Ensure version is ${TOOL_REQUIRED_VERSIONS[$(get_tool_index go)]} if using 'go install' for other tools."
         return 0
    else
        log_error "Go is not installed."
        log_warning "Go is required ONLY if you plan to install certain tools (like Nuclei) using the 'go install' method."
        log_warning "If needed, install Go manually from: https://golang.org/doc/install"
        log_warning "This script will not automatically install Go."
        return 1 # Indicate failure to install, even though it just gives guidance
    fi
}

install_python(){
    log "Checking Python installation..."
    if check_external_tool_status_row "python" > /dev/null; then
         log_success "Python (python3/python) appears to be installed."
         log_warning "Ensure version is ${TOOL_REQUIRED_VERSIONS[$(get_tool_index python)]} or compatible with pyproject.toml."
         log_warning "Using a Python version manager like pyenv is recommended."
         return 0
    else
        log_error "Python (python3/python) command not found."
        log_warning "Python is required for this project."
        log_warning "Install Python manually for your OS: https://www.python.org/downloads/"
        log_warning "Consider using a version manager like pyenv: https://github.com/pyenv/pyenv"
        log_warning "This script will not automatically install Python."
        return 1 # Indicate failure to install
    fi
}

install_poetry_guidance(){ log_error "Poetry not found."; log_warning "Install from https://python-poetry.org/docs/#installation then re-run."; }

# --- Core Setup Installation ---
install_core_setup() {
    log "Installing core project setup..."
    if [[ ! -f "pyproject.toml" ]]; then log_error "Cannot find pyproject.toml. Run from project root."; return 1; fi
    if ! command_exists poetry; then install_poetry_guidance; return 1; fi
    log "Running 'poetry install --sync'..."
    if poetry install --sync; then log_success "Core dependencies installed."; return 0
    else log_error "'poetry install --sync' failed."; log_warning "Check output for errors."; return 1; fi
}


# --- Main Logic ---
show_help() {
    echo "SuperCyberAgents Tool & Core Setup Installer"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --check          Check status of all components (tools & core) in a single table."
    echo "  --install-all    Install missing tools AND core setup."
    echo "  --install-tools  Install missing external tools only."
    echo "  --install-core   Install core project setup (runs 'poetry install --sync')."
    echo "  --install TOOL   Install a specific external tool (e.g., --install nuclei)."
    echo "  --help, -h       Show this help message."
    echo ""
    echo "If no options are provided, an interactive menu will be shown."
}

# Parse Arguments
ACTION="menu"
TOOL_TO_INSTALL=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --check)
            ACTION="check_all"
            shift
            ;;
        --install-all)
            ACTION="install_all"
            shift
            ;;
         --install-tools)
            ACTION="install_tools"
            shift
            ;;
         --install-core)
            ACTION="install_core"
            shift
            ;;
        --install)
            ACTION="install_specific_tool"
            if [[ -z "${2:-}" || "$2" == --* ]]; then log_error "Error: --install requires tool name."; exit 1; fi
            TOOL_TO_INSTALL="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"; show_help; exit 1
            ;;
    esac
done

# --- Execution ---
get_os

case "$ACTION" in
    check_all)
        run_all_checks
        ;;
    install_all)
        log "Starting installation of ALL components (Tools & Core)..."
        overall_success=true
        log "--- Installing External Tools ---"
        install_failed_tools=false
        tool_name="" tool_index="" install_func=""
        for tool_name in "${TOOL_NAMES[@]}"; do
            if ! check_external_tool_status_row "$tool_name" > /dev/null; then # Check silently
                tool_index=$(get_tool_index "$tool_name")
                install_func="${TOOL_INSTALL_FUNCS[$tool_index]}"
                log "Installing $tool_name..."
                if ! "$install_func"; then log_error "Failed install: $tool_name."; install_failed_tools=true; overall_success=false; fi
            fi
        done
        if ! $install_failed_tools; then log_success "External tools phase done."; else log_warning "External tools phase had errors."; fi
        echo ""
        log "--- Installing Core Setup ---"
        if ! install_core_setup; then log_error "Failed core setup."; overall_success=false; fi
        echo ""
        log "--- Performing Final Verification ---"
        run_all_checks # Run combined check at the end
        if $overall_success; then log_success "Install process completed."; else log_error "Install process completed with errors."; exit 1; fi
        ;;
    install_tools)
        log "Starting installation of EXTERNAL TOOLS only..."
        install_failed_tools=false
        tool_name="" tool_index="" install_func=""
        for tool_name in "${TOOL_NAMES[@]}"; do
             if ! check_external_tool_status_row "$tool_name" > /dev/null; then # Check silently
                tool_index=$(get_tool_index "$tool_name")
                install_func="${TOOL_INSTALL_FUNCS[$tool_index]}"
                log "Installing $tool_name..."
                if ! "$install_func"; then log_error "Failed install: $tool_name."; install_failed_tools=true; fi
            fi
        done
        if $install_failed_tools; then log_error "External tools install had errors."; exit 1
        else log_success "External tools checked/installed."; log "Verifying external tools..."; run_all_checks; fi # Verify afterwards
        ;;
    install_core)
        log "Starting installation of CORE PROJECT SETUP only..."
        if install_core_setup; then log "Verifying core setup..."; run_all_checks; # Verify afterwards
        else log_error "Core setup failed."; exit 1; fi
        ;;
    install_specific_tool)
        local tool_index install_func
        if [[ -z "$TOOL_TO_INSTALL" ]]; then log_error "Internal error: No tool specified."; exit 1; fi
        tool_index=$(get_tool_index "$TOOL_TO_INSTALL")
        if [[ "$tool_index" -eq -1 ]]; then log_error "Unknown external tool: $TOOL_TO_INSTALL"; echo "Available: ${TOOL_NAMES[*]}"; exit 1; fi
        install_func="${TOOL_INSTALL_FUNCS[$tool_index]}"
        log "Installing specific tool: $TOOL_TO_INSTALL..."
        if "$install_func"; then log_success "Install of $TOOL_TO_INSTALL complete."; log "Verifying $TOOL_TO_INSTALL..."; check_external_tool_status_row "$TOOL_TO_INSTALL";
        else log_error "Failed install: $TOOL_TO_INSTALL."; exit 1; fi
        ;;
    menu)
        log "Interactive Setup Management"
        run_all_checks # Initial check
        echo ""
        while true; do
            PS3="${COLOR_YELLOW}Choose an action: ${COLOR_RESET}"
            options=(
                "Install/Verify ALL (Tools & Core)"
                "Install/Verify External Tools ONLY"
                "Install/Verify Core Setup ONLY"
                "Install a SPECIFIC External Tool"
                "Re-check ALL Status"
                "Quit"
            )
            select opt in "${options[@]}"; do
                if ! [[ "$REPLY" =~ ^[0-9]+$ ]] && [[ -n "$REPLY" ]]; then log_error "Invalid input."; break; fi
                case $opt in
                    "Install/Verify ALL (Tools & Core)")
                        log "--- Installing/Verifying External Tools ---"
                        install_failed_tools=false; tool_name=""; tool_index=""; install_func=""
                        for tool_name in "${TOOL_NAMES[@]}"; do
                             if ! check_external_tool_status_row "$tool_name" > /dev/null; then
                                tool_index=$(get_tool_index "$tool_name"); install_func="${TOOL_INSTALL_FUNCS[$tool_index]}"
                                log "Installing $tool_name..."; if ! "$install_func"; then log_error "Failed install: $tool_name."; install_failed_tools=true; fi
                            fi
                        done
                        if $install_failed_tools; then log_warning "Tool install phase had errors."; fi
                        echo ""
                        log "--- Installing/Verifying Core Setup ---"
                        if ! install_core_setup; then log_error "Core setup failed."; fi
                        echo ""
                        log "--- Final Status Check ---"
                        run_all_checks
                        break
                        ;;
                    "Install/Verify External Tools ONLY")
                         log "--- Installing/Verifying External Tools ---"
                        install_failed_tools=false; tool_name=""; tool_index=""; install_func=""
                        for tool_name in "${TOOL_NAMES[@]}"; do
                             if ! check_external_tool_status_row "$tool_name" > /dev/null; then
                                tool_index=$(get_tool_index "$tool_name"); install_func="${TOOL_INSTALL_FUNCS[$tool_index]}"
                                log "Installing $tool_name..."; if ! "$install_func"; then log_error "Failed install: $tool_name."; install_failed_tools=true; fi
                            fi
                        done
                        if $install_failed_tools; then log_warning "Tool install phase had errors."; fi
                        echo ""; log "--- Final Tool Status Check ---"; run_all_checks;
                        break
                        ;;
                    "Install/Verify Core Setup ONLY")
                        log "--- Installing/Verifying Core Setup ---"
                        if ! install_core_setup; then log_error "Core setup failed."; fi
                        echo ""; log "--- Final Core Status Check ---"; run_all_checks;
                        break
                        ;;
                    "Install a SPECIFIC External Tool")
                        PS3_INNER="${COLOR_YELLOW}Select tool: ${COLOR_RESET}"
                        select specific_tool in "${TOOL_NAMES[@]}" "Cancel"; do
                            if ! [[ "$REPLY" =~ ^[0-9]+$ ]] && [[ -n "$REPLY" ]]; then log_error "Invalid input."; continue; fi
                            if [[ "$specific_tool" == "Cancel" ]]; then break; fi
                            if [[ -n "$specific_tool" ]]; then
                                 local tool_index install_func
                                 tool_index=$(get_tool_index "$specific_tool")
                                 if [[ "$tool_index" -eq -1 ]]; then log_error "Invalid selection."; else
                                    install_func="${TOOL_INSTALL_FUNCS[$tool_index]}"; log "Installing $specific_tool..."
                                    if "$install_func"; then log_success "Install ok."; check_external_tool_status_row "$specific_tool";
                                    else log_error "Failed install: $specific_tool."; fi
                                    break
                                 fi
                            else log_error "Invalid choice."; fi
                        done
                        break
                         ;;
                    "Re-check ALL Status")
                        run_all_checks
                        break
                        ;;
                    "Quit") log "Exiting."; exit 0 ;; 
                    *) if [[ -n "$REPLY" ]]; then log_error "Invalid option: $REPLY"; fi; break ;; 
                esac
            done
            echo ""
        done
        ;;
esac

exit 0 