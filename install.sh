#!/bin/bash

# CLIProxyAPIPlus - Installer
# Cross-platform source-to-production deployment

set -euo pipefail

SCRIPT_NAME="cliproxyapi-installer"
REPO_URL="https://github.com/HsnSaboor/CLIProxyAPIPlus.git"

detect_os() {
    case "$(uname -s)" in
        Linux*)
            if [[ -d "$HOME/.local/share" ]]; then
                SOURCE_DIR="$HOME/.local/share/cliproxyapi"
            else
                SOURCE_DIR="$HOME/.cliproxyapi-source"
            fi
            PROD_DIR="$HOME/.cliproxyapi"
            AUTH_DIR="$HOME/.cli-proxy-api"
            ;;
        Darwin*)
            SOURCE_DIR="$HOME/Library/Application Support/cliproxyapi"
            PROD_DIR="$HOME/cliproxyapi"
            AUTH_DIR="$HOME/.cli-proxy-api"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            SOURCE_DIR="$LOCALAPPDATA/cliproxyapi"
            PROD_DIR="$LOCALAPPDATA/cliproxyapi"
            AUTH_DIR="$APPDATA/cli-proxy-api"
            ;;
        *)
            SOURCE_DIR="$HOME/.local/share/cliproxyapi"
            PROD_DIR="$HOME/.cliproxyapi"
            AUTH_DIR="$HOME/.cli-proxy-api"
            ;;
    esac
}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

is_service_running() {
    if [[ "$(uname -s)" == "Linux" ]]; then
        systemctl --user is-active --quiet cliproxyapi.service 2>/dev/null
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        pgrep -f "cli-proxy-api" >/dev/null 2>&1
    else
        pgrep -f "cli-proxy-api" >/dev/null 2>&1
    fi
}

stop_service() {
    if is_service_running; then
        log_info "Stopping service..."
        if [[ "$(uname -s)" == "Linux" ]]; then
            systemctl --user stop cliproxyapi.service 2>/dev/null || true
        fi
        pkill -f "cli-proxy-api" 2>/dev/null || true
        sleep 2
    fi
}

generate_api_key() {
    local prefix="sk-"
    local chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local key=""
    for i in {1..45}; do
        key="${key}${chars:$((RANDOM % ${#chars})):1}"
    done
    echo "${prefix}${key}"
}

check_api_keys() {
    local config_file="${PROD_DIR}/config.yaml"
    [[ ! -f "$config_file" ]] && return 1
    grep -q '"your-api-key-1"' "$config_file" && return 1
    grep -q '"your-api-key-2"' "$config_file" && return 1
    grep -A 10 "^api-keys:" "$config_file" | grep -q '"sk-[^"]*"' && return 0
    return 1
}

git_clone_or_update() {
    local force_update="${1:-false}"

    if [[ -d "$SOURCE_DIR/.git" ]]; then
        if [[ "$force_update" == "true" ]]; then
            log_step "Updating source..."
            cd "$SOURCE_DIR"
            git fetch origin main
            git reset --hard origin/main
            log_success "Source updated"
        else
            log_info "Using existing source at $SOURCE_DIR"
        fi
    else
        log_step "Cloning repository..."
        mkdir -p "$(dirname "$SOURCE_DIR")"
        git clone --depth 1 "$REPO_URL" "$SOURCE_DIR"
        log_success "Repository cloned"
    fi
}

source_build() {
    log_step "Building from source..."

    if ! command -v go >/dev/null 2>&1; then
        log_error "Go is not installed. Install it first: https://go.dev/dl/"
        exit 1
    fi

    cd "$SOURCE_DIR"
    go build -o cli-proxy-api.new ./cmd/server

    log_info "Running pre-flight check..."
    if ! ./cli-proxy-api.new --help >/dev/null 2>&1; then
        log_error "BUILD VERIFICATION FAILED."
        rm -f cli-proxy-api.new
        exit 1
    fi

    log_success "Build verified"
}

safe_deploy() {
    log_step "Atomic Deployment"

    cd "$SOURCE_DIR"

    mkdir -p "$PROD_DIR/config_backup"

    log_info "Backing up config..."
    if [[ -f "$PROD_DIR/config.yaml" ]]; then
        local ts
        ts=$(date +"%Y%m%d_%H%M%S")
        cp "$PROD_DIR/config.yaml" "$PROD_DIR/config_backup/config_${ts}.yaml"
        log_success "Config backed up"
    fi

    log_info "Backing up auth tokens..."
    if [[ -d "$AUTH_DIR" ]]; then
        local token_ts
        token_ts=$(date +"%Y%m%d_%H%M")
        tar -czf "$PROD_DIR/config_backup/tokens_${token_ts}.tar.gz" -C "$AUTH_DIR" . 2>/dev/null || true
        log_success "Tokens backed up"
    fi

    if [[ ! -f "$PROD_DIR/config.yaml" ]]; then
        if [[ -f "$SOURCE_DIR/config.example.yaml" ]]; then
            mkdir -p "$PROD_DIR"
            cp "$SOURCE_DIR/config.example.yaml" "$PROD_DIR/config.yaml"
            local key1 key2
            key1=$(generate_api_key)
            key2=$(generate_api_key)
            sed -i "s/\"your-api-key-1\"/\"$key1\"/g" "$PROD_DIR/config.yaml" 2>/dev/null || true
            sed -i "s/\"your-api-key-2\"/\"$key2\"/g" "$PROD_DIR/config.yaml" 2>/dev/null || true
            log_success "Created config.yaml with generated API keys"
        fi
    fi

    if [[ -f "$PROD_DIR/cli-proxy-api" ]]; then
        mv "$PROD_DIR/cli-proxy-api" "$PROD_DIR/cli-proxy-api.old"
    fi

    mv cli-proxy-api.new "$PROD_DIR/cli-proxy-api"
    chmod +x "$PROD_DIR/cli-proxy-api"
    log_success "Binary deployed"

    create_systemd_service

    log_info "Restarting service..."
    if [[ "$(uname -s)" == "Linux" ]]; then
        systemctl --user restart cliproxyapi.service
    fi
    sleep 3

    if is_service_running; then
        log_success "Service is running"
    else
        log_warning "Service not running, starting manually..."
        nohup "$PROD_DIR/cli-proxy-api" > "$PROD_DIR/nohup.out" 2>&1 &
        sleep 3
    fi
}

create_systemd_service() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        return
    fi

    local systemd_dir="$HOME/.config/systemd/user"
    mkdir -p "$systemd_dir"

    cat > "$systemd_dir/cliproxyapi.service" << EOF
[Unit]
Description=CLIProxyAPI Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$PROD_DIR
ExecStart=$PROD_DIR/cli-proxy-api
Restart=always
RestartSec=10
Environment=HOME=$HOME

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload || true
}

show_status() {
    echo
    echo "CLIProxyAPIPlus - Status"
    echo "========================"
    echo "Source Dir:  $SOURCE_DIR"
    echo "Install Dir: $PROD_DIR"
    echo "Auth Dir:    $AUTH_DIR"

    if [[ -d "$SOURCE_DIR/.git" ]]; then
        cd "$SOURCE_DIR"
        echo "Git Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"
    fi

    [[ -f "$PROD_DIR/cli-proxy-api" ]] && echo "Binary:      Present" || echo "Binary:      Missing"
    [[ -f "$PROD_DIR/config.yaml" ]] && echo "Config:      Present" || echo "Config:      Missing"
    check_api_keys && echo "API Keys:    Configured" || echo "API Keys:    NOT CONFIGURED"

    echo
    if is_service_running; then
        echo -e "Service:     ${GREEN}RUNNING${NC}"
    else
        echo -e "Service:     ${RED}NOT RUNNING${NC}"
    fi
    echo
}

show_quick_start() {
    echo
    echo -e "${GREEN}Quick Start:${NC}"
    echo -e "${BLUE}1. Configure:${NC}  ${CYAN}nano ${PROD_DIR}/config.yaml${NC}"
    echo -e "${BLUE}2. Auth:${NC}       ${CYAN}${PROD_DIR}/cli-proxy-api --login${NC}"
    echo -e "${BLUE}3. Run:${NC}        ${CYAN}systemctl --user start cliproxyapi.service${NC} (Linux)"
    echo
}

install_or_upgrade() {
    local force_update="${1:-false}"

    detect_os
    git_clone_or_update "$force_update"
    source_build
    safe_deploy

    if [[ ! -f "$PROD_DIR/config.yaml" ]] || ! check_api_keys; then
        echo
        echo -e "${YELLOW}API Keys Required${NC}"
        echo -e "${BLUE}Edit: ${CYAN}nano ${PROD_DIR}/config.yaml${NC}"
    fi

    show_quick_start
}

uninstall() {
    if [[ ! -d "$PROD_DIR" ]]; then
        log_warning "Not installed"
        exit 0
    fi

    log_info "Found at: $PROD_DIR"
    read -p "Remove? (y/N): " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0

    stop_service
    rm -rf "$PROD_DIR"
    rm -rf "$SOURCE_DIR"
    log_success "Uninstalled"
}

main() {
    detect_os

    case "${1:-install}" in
        install)
            install_or_upgrade false
            ;;
        upgrade)
            install_or_upgrade true
            ;;
        status)
            show_status
            ;;
        uninstall)
            uninstall
            ;;
        -h|--help)
            cat << EOF
CLIProxyAPIPlus - Installer

Usage: $SCRIPT_NAME [command]

Commands:
  install         Clone (if needed) and install
  upgrade         Pull latest and reinstall
  status          Show installation status
  uninstall       Remove installation
  -h, --help     This help

Paths:
  Source:  $SOURCE_DIR
  Binary:  $PROD_DIR
  Auth:    $AUTH_DIR

EOF
            ;;
        *)
            log_error "Unknown: $1"
            exit 1
            ;;
    esac
}

main "$@"
