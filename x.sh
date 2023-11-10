#!/bin/bash
clear
# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
PUBLIC_IP=$(curl -s http://ipinfo.io/ip)
# Function to check if a tool is installed and install it if not
check_and_install() {
    for tool in "$@"; do
        if tool_is_installed "$tool"; then
            echo -e "${GREEN}$tool is already installed.${NC}"
        else
            echo -e "${YELLOW}$tool is not installed. Installing...${NC}"
            install_tool "$tool"
        fi
    done
}

tool_is_installed() {
    local tool=$1

    if command -v "$tool" &> /dev/null; then
        return 0
    fi

    if dpkg-query -W -f='${Status}' "$tool" 2>/dev/null | grep -q "ok installed"; then
        return 0
    fi

    # Special check for acme.sh
    if [[ "$tool" == "acme.sh" ]] && [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        return 0
    fi

    return 1
}

install_tool() {
    local tool=$1

    case "$tool" in
        docker)
            curl -sSL https://get.docker.com/ | sh
            ;;
        acme.sh)
            curl -sSL https://get.acme.sh/ | sh
            ;;
        *)
            sudo apt update
            sudo apt install -y "$tool"
            ;;
    esac
}

# Function to ask yes/no questions
ask_yes_no() {
    local prompt="$1"
    local answer

    while true; do
        read -rp "$prompt [y/n]: " answer
        case "$answer" in
            [yY][eE][sS]|[yY])
                echo "yes"
                break
                ;;
            [nN][oO]|[nN])
                echo "no"
                break
                ;;
            *)
                echo -e "${YELLOW}Please answer ${GREEN}yes${YELLOW} or ${RED}no${YELLOW}.${NC}"
                ;;
        esac
    done
}

# Function to generate a private key
generate_private_key() {
    # Call the xray executable and extract the private key
    key_output=$(./marzban/xray-core/xray x25519)
    echo "$key_output" | grep "Private key:" | cut -d ' ' -f 3
}

# Function to generate shortid
generate_short_id() {
    openssl rand -hex 8
}

# Function to validate domain format
validate_domain() {
    local domain=$1
    if ! [[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
        echo -e "${RED}Invalid domain format. Please use alphanumeric characters, dots, and dashes only.${NC}"
        return 1
    fi
    return 0
}

# Function to check if a domain is pointing to the server's public IP
check_domain_ip() {
    local domain=$1
    local domain_ip
    domain_ip=$(dig +short "$domain" | grep '^[.0-9]*$' | tail -n1) # Taking the last IP if multiple are returned

    if [ "$domain_ip" != "$PUBLIC_IP" ]; then
        echo -e "${RED}Domain is not pointing to the server's public IP (${PUBLIC_IP}). Please update your DNS settings.${NC}"
        return 1
    fi
    return 0
}

# Function to initialize default key-values in the .env file
initialize_default_values() {
    {
        echo "DOCS=true"
        echo "XRAY_JSON=\"/var/lib/marzban/xray_config.json\""
        echo "XRAY_EXECUTABLE_PATH=\"/var/lib/marzban/xray-core/xray\""
        echo "XRAY_ASSETS_PATH=\"/var/lib/marzban/xray-core/assets\""
    } >> .env
}

# Function to load existing .env or create a new one
load_or_initialize_env() {
    if [ -f ".env" ]; then
        echo -e "${GREEN}An existing .env file has been found. Would you like to reset Marzban?${NC}"
        if [[ $(ask_yes_no "Reset and start from scratch?") == "yes" ]]; then
            # bringing down any containers
            echo -e "${YELLOW}Bringing down any containers...${NC}"
            docker compose down
            echo -e "${GREEN}All containers have been brought down.${NC}"
            echo -e "${YELLOW}Resetting .env file...${NC}"
            >.env # Empty the .env file
            echo -e "${GREEN}.env file has been reset.${NC}"
            # deleting the marzban folder and databases
            echo -e "${YELLOW}Deleting the marzban folder and databases...${NC}"
            rm -rf marzban
            echo -e "${GREEN}The marzban folder and databases have been deleted.${NC}"
            # deleting nginx settings and certificates
            echo -e "${YELLOW}Deleting nginx settings ${NC}"
            rm -rf nginx
            echo -e "${GREEN}Nginx settings and certificates have been deleted.${NC}"
            echo -e "${YELLOW}Deleting the docker-compose.yml file...${NC}"
            rm -rf docker-compose.yml
            echo -e "${GREEN}The docker-compose.yml file has been deleted.${NC}"
            initialize_default_values
        fi
    else
        touch .env
        echo -e "${GREEN}Starting with a new configuration.${NC}"
        initialize_default_values
    fi
}

# Function to prompt for admin credentials
prompt_for_admin_credentials() {
    local marzban_admin marzban_password
    echo -e "${BLUE}Admin access is a privilege. Use it wisely and securely.${NC}"

    read -rp "Enter your Marzban admin username: " marzban_admin
    read -rp "Enter your Marzban admin password: " marzban_password
    echo
    update_env_file "SUDO_USERNAME" "$marzban_admin"
    update_env_file "SUDO_PASSWORD" "$marzban_password"
}

# Function to update or add a key-value pair in the .env file
update_env_file() {
    local key=$1
    local value=$2
    if grep -q "^$key=" .env; then
        # If the key already exists, replace it
        sed -i "s/^$key=.*/$key=\"$value\"/" .env
    else
        # If the key does not exist, append it
        echo "$key=\"$value\"" >> .env
    fi
}

# Function to prompt for a domain and validate it, with an option to skip IP check
prompt_for_domain() {
    local domain_type=$1
    local domain_var_name=$2
    local skip_ip_check=$3
    local domain

    while true; do
        read -rp "Enter the $domain_type domain/subdomain: " domain
        if validate_domain "$domain"; then
            if [[ "$skip_ip_check" != "yes" ]]; then
                if check_domain_ip "$domain"; then
                    update_env_file "$domain_var_name" "$domain"
                    break
                fi
            else
                update_env_file "$domain_var_name" "$domain"
                break
            fi
        fi
    done
}

# Function to ask for the Marzban version if not already set
ask_for_marzban_version() {
    if ! grep -q "^MARZBAN_VERSION=" .env; then
        local marzban_version
        marzban_version=$(ask_yes_no "Use 'dev' version? (y for 'dev', n for 'latest')")
        if [[ "$marzban_version" == "yes" ]]; then
            marzban_version="dev"
        else
            marzban_version="latest"
        fi
        update_env_file "MARZBAN_VERSION" "$marzban_version"
    fi
}

# Function to ask for the database choice and configure accordingly
ask_for_db_choice() {
    local db_choice
    echo -e "${YELLOW}Select your database for Marzban: 'mysql' for robustness, 'sqlite' for simplicity.${NC}"
    select db_choice in "mysql" "sqlite"; do
        case $db_choice in
            "mysql")
                update_env_file "DB_CHOICE" "mysql"
                ask_for_mysql_details
                break
                ;;
            "sqlite")
                update_env_file "DB_CHOICE" "sqlite"
                update_env_file "SQLALCHEMY_DATABASE_URL" "sqlite:////var/lib/marzban/db.sqlite3"
                break
                ;;
            *)
                echo -e "${RED}Error: Invalid choice. Select '1' for MySQL or '2' for SQLite.${NC}"
                ;;
        esac
    done
}

# Function to ask for MySQL details if MySQL is chosen
ask_for_mysql_details() {
    local mysql_root_password
    read -rp "Enter MySQL root password: " mysql_root_password
    update_env_file "MYSQL_ROOT_PASSWORD" "$mysql_root_password"
    update_env_file "MYSQL_DATABASE" "marzban"  # Add the MySQL database name to the .env file
    update_env_file "SQLALCHEMY_DATABASE_URL" "mysql+pymysql://root:$mysql_root_password@mysql/marzban"
    local phpmyadmin_choice
    phpmyadmin_choice=$(ask_yes_no "Do you want to install phpMyAdmin?")
    update_env_file "PHPMYADMIN_CHOICE" "$phpmyadmin_choice"

    if [[ "$phpmyadmin_choice" == "yes" ]]; then
        local PMA_ADDRESS
        while true; do
            read -rp "Enter the address for phpMyAdmin: " PMA_ADDRESS
            if validate_domain "$PMA_ADDRESS"; then
                update_env_file "PMA_ADDRESS" "$PMA_ADDRESS"
                update_env_file "PMA_ARBITRARY" "1"
                update_env_file "APACHE_PORT" "8010"
                break
            fi
        done
    fi
}

# Function to configure WARP outbound settings with the latest release URL
configure_warp_outbound() {
    local warp_outbound_choice warp_release_url warp_license_choice warp_license
    warp_outbound_choice=$(ask_yes_no "Do you want to use WARP as your default outbound?")
    update_env_file "WARP_OUTBOUND_CHOICE" "$warp_outbound_choice"

    if [[ "$warp_outbound_choice" == "yes" ]]; then
        warp_release_url=$(get_latest_release_url_warp)
        update_env_file "WARP_RELEASE_URL" "$warp_release_url"

        warp_license_choice=$(ask_yes_no "Do you have a WARP+ license?")
        update_env_file "WARP_LICENSE_CHOICE" "$warp_license_choice"

        if [[ "$warp_license_choice" == "yes" ]]; then
            read -rp "Enter your WARP+ license key: " warp_license
            update_env_file "WARP_LICENSE" "$warp_license"
        fi
    fi
}


# Function to configure Telegram backup
configure_telegram_backup() {
    local telegram_backup_choice telegram_bot_token telegram_chat_id telegram_backup_cron
    telegram_backup_choice=$(ask_yes_no "Do you want to enable backups to Telegram?")
    update_env_file "TELEGRAM_BACKUP_CHOICE" "$telegram_backup_choice"

    if [[ "$telegram_backup_choice" == "yes" ]]; then
        if [[ "$DB_CHOICE" = "mysql" ]]; then
            check_and_install mysql-client
        fi
        # Prompt user for API token and chat ID
        read -rp "Enter your Telegram bot token: " telegram_bot_token
        read -rp "Enter your Telegram chat ID: " telegram_chat_id

        # Validate API token and chat ID using Telegram API
        

        telegram_api_url="https://api.telegram.org/bot$telegram_bot_token/getChat?chat_id=$telegram_chat_id"
        response=$(curl -s -X GET "$telegram_api_url")
        if [[ $(echo "$response" | jq '.ok') != true ]]; then
            echo -e "${RED}Error: Invalid API token or chat ID. Please try again.${NC}"
            return 1
        fi

        # Send verification code to chat ID
        verification_code=$(openssl rand -hex 6)
        telegram_send_message_url="https://api.telegram.org/bot$telegram_bot_token/sendMessage"
        curl -s -X POST "$telegram_send_message_url" \
            -H 'Content-Type: application/json' \
            -d "{\"chat_id\": \"$telegram_chat_id\", \"text\": \"Verification code: $verification_code\"}" > /dev/null

        # Prompt user to enter verification code
        read -rp "Enter the verification code sent to your Telegram chat: " entered_verification_code

        # Verify verification code
        if [[ "$entered_verification_code" != "$verification_code" ]]; then
            echo -e "${RED}Error: Invalid verification code. Please try again.${NC}"
            return 1
        fi

        # Save API token and chat ID to environment file
        update_env_file "TELEGRAM_API_TOKEN" "$telegram_bot_token"
        update_env_file "TELEGRAM_ADMIN_ID" "$telegram_chat_id"

        echo -e "${YELLOW}Select the schedule for backups to be sent:${NC}"
        select telegram_backup_cron in "hourly" "every 2 hours" "every 3 hours" "every 4 hours" "every 5 hours" "every 6 hours" "every 7 hours" "every 8 hours" "every 9 hours"; do
            case $telegram_backup_cron in
                "hourly"|"every 2 hours"|"every 3 hours"|"every 4 hours"|"every 5 hours"|"every 6 hours"|"every 7 hours"|"every 8 hours"|"every 9 hours")
                    update_env_file "TELEGRAM_BACKUP_CRON" "$telegram_backup_cron"
                    break
                    ;;
                *)
                    echo -e "${RED}Invalid schedule option. Please select a valid interval: (1-9)${NC}"
                    ;;
            esac
        done
    fi
}

# Generic function to retrieve the latest release URL from a GitHub repository
get_latest_release_url_from_repo() {
    local owner="$1"
    local repo="$2"
    local os_type="$3"
    local asset_arch="$4"

    local latest_release_url=$(curl -s "https://api.github.com/repos/${owner}/${repo}/releases/latest" | \
        jq -r --arg asset_arch "$asset_arch" --arg os_type "$os_type" \
        '.assets[] | select(.name | contains($asset_arch) and contains($os_type)) | .browser_download_url' | head -1)

    if [[ -z "$latest_release_url" ]]; then
        echo "Error: Could not find a download URL for ${os_type}-${asset_arch}."
        return 1
    fi

    echo "$latest_release_url"
}

# Function to map architecture to the specific format for Xray Core and WARP
map_architecture() {
    local arch="$1"
    local repo="$2"

    case "$repo" in
        "Xray-core")
            case "$arch" in
                x86_64) echo "64" ;;
                armv7l) echo "arm32-v7a" ;;
                aarch64) echo "arm64-v8a" ;;
                *) echo "Unsupported architecture for Xray-core: $arch" && return 1 ;;
            esac
            ;;
        "wgcf")
            case "$arch" in
                x86_64) echo "amd64" ;;
                armv7l) echo "armv7" ;;
                aarch64) echo "arm64" ;;
                *) echo "Unsupported architecture for WARP: $arch" && return 1 ;;
            esac
            ;;
        *)
            echo "Unsupported repository: $repo"
            return 1
            ;;
    esac
}

# Function to get the latest release URL for Xray Core based on the current system's architecture
get_latest_release_url_xray() {
    local arch=$(uname -m)
    local os_type=$(uname -s | tr '[:upper:]' '[:lower:]')
    local mapped_arch=$(map_architecture "$arch" "Xray-core")
    if [[ $? -eq 0 ]]; then
        get_latest_release_url_from_repo "XTLS" "Xray-core" "$os_type" "$mapped_arch"
    fi
}

# Function to get the latest release URL for WARP based on the current system's architecture
get_latest_release_url_warp() {
    local arch=$(uname -m)
    local os_type=$(uname -s | tr '[:upper:]' '[:lower:]')
    local mapped_arch=$(map_architecture "$arch" "wgcf")
    if [[ $? -eq 0 ]]; then
        get_latest_release_url_from_repo "ViRb3" "wgcf" "$os_type" "$mapped_arch"
    fi
}

echo -e "${YELLOW}Initializing configuration: Loading or creating the .env file...${NC}"
load_or_initialize_env

echo -e "${YELLOW}Preparing system: Checking and installing necessary tools...${NC}"
check_and_install jq docker curl dig socat zip openssl acme.sh

echo -e "${YELLOW}Do you want to use the 'dev' version or the 'latest' version of Marzban?${NC}"
ask_for_marzban_version

echo -e "${YELLOW}Configuring domain: Specify the domain/subdomain for Marzban Panel...${NC}"
prompt_for_domain "Marzban" "MARZBAN_ADDRESS"

echo -e "${YELLOW}Setting XRAY subscription: Enter the address for XRAY subscription URL...${NC}"
prompt_for_domain "XRAY subscription" "XRAY_SUBSCRIPTION_URL"

echo -e "${YELLOW}Admin setup: Enter Marzban admin credentials...${NC}"
prompt_for_admin_credentials

echo -e "${YELLOW}Database selection: Choose your preferred database for Marzban...${NC}"
ask_for_db_choice

echo -e "${YELLOW}Configuring WARP: Setting up outbound settings...${NC}"
configure_warp_outbound

echo -e "${YELLOW}Backup configuration: Setting up Telegram backups and Marzban Telegram bot...${NC}"
configure_telegram_backup

# Read the .env file and export the variables
set -a
source .env
set +a

# Add the prefix to XRAY_SUBSCRIPTION_URL
xray_subscription_url_prefix="https://$XRAY_SUBSCRIPTION_URL"
update_env_file "XRAY_SUBSCRIPTION_URL_PREFIX" "$xray_subscription_url_prefix"

# Invoke the function to add the XRAY_SUBSCRIPTION_URL_PREFIX to the .env file
# Function to append text to a file
append_to_file() {
        local file=$1
        local text=$2
        echo -e "$text" >> "$file"
}

# Function to handle MySQL related tasks
handle_mysql() {
  # Add MySQL service to docker-compose.yml
  local mysql_service="
  mysql:
    image: mysql:latest
    container_name: mysql
    restart: always
    env_file: .env
    networks:
      - mynetwork
    volumes:
      - ./marzban/mysql:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      timeout: 20s
      retries: 10
      interval: 15s
      start_period: 30s
"

  # Check if phpMyAdmin is desired and add to the service if so
  if [[ "$PHPMYADMIN_CHOICE" == "yes" ]]; then
    local phpmyadmin_service="
  phpmyadmin:
    image: phpmyadmin/phpmyadmin:latest
    container_name: phpmyadmin
    restart: always
    env_file: .env
    networks:
      - mynetwork
    depends_on:
      mysql:
        condition: service_healthy
"
    mysql_service+="$phpmyadmin_service"
  fi

  # Append MySQL (and phpMyAdmin if applicable) to the docker-compose.yml
  append_to_file "docker-compose.yml" "$mysql_service"
}
# Start creating the docker-compose.yml file
cat <<EOF > docker-compose.yml
services:
  marzban:
    image: gozargah/marzban:$MARZBAN_VERSION
    container_name: marzban
    restart: always
    env_file: .env
    ports:
      - "8443:8443"
      - "8081:8081"
      - "2053:2053"
      - "2083:2083"
      - "1080:1080"
      - "8080:8080"
    networks:
      - mynetwork
    volumes:
      - ./marzban:/var/lib/marzban
      - ./certs:/usr/local/etc/certs:ro
    healthcheck:
      test: ["CMD-SHELL", "marzban-cli --help"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 30s

EOF
# Handle database choice
if [[ "$DB_CHOICE" == "mysql" ]]; then
    { echo "    depends_on:";
        echo "      mysql:";
        echo "        condition: service_healthy";
    } >> docker-compose.yml
    handle_mysql
fi

mkdir -p nginx
# Append nginx service to docker-compose.yml
cat << EOF >> docker-compose.yml
  nginx:
    image: nginx:latest
    container_name: nginx
    restart: always
    env_file: .env
    ports:
      - "443:443"
    volumes:
      - ./nginx:/etc/nginx
      - ./certs:/etc/ssl/certs:ro
    depends_on:
      marzban:
        condition: service_healthy
    networks:
      - mynetwork
networks:
  mynetwork:
    driver: bridge
EOF


echo -e "${GREEN}docker-compose.yml has been created.${NC}\n"


# Variables for acme.sh
ACME_HOME="/root/.acme.sh"
CERT_HOME="./certs"

NGINX_CONF="./nginx/nginx.conf"
NGINX_CONF_D="./nginx/conf.d"
NGINX_CERTS="/etc/ssl/certs"


# Function to create directories if they don't exist
ensure_directories() {
    mkdir -p "$CERT_HOME"
    mkdir -p "$NGINX_CONF_D"
}

# Generate nginx.conf
cat > "$NGINX_CONF" <<EOF
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    default_type application/octet-stream;

    access_log off; # Consider turning on if needed
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # SSL optimizations (if SSL is used)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "no-referrer-when-downgrade";

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Function to issue a certificate
issue_certificate() {
    local domain=$1
    $ACME_HOME/acme.sh --issue --standalone -d "$domain" \
        --cert-file "$CERT_HOME/$domain.cer" \
        --key-file "$CERT_HOME/$domain.key" \
        --fullchain-file "$CERT_HOME/$domain.fullchain.cer" \
        --server letsencrypt \
    # Check if the certificate was issued successfully
    if [ ! -f "$CERT_HOME/$domain.key" ]; then
        echo "Failed to obtain the certificate for $domain"
        return 1
    fi
    return 0
}

# Function to generate nginx configuration for a domain
generate_nginx_conf() {
    local domain=$1
    local service_name=$2
    local service_port=$3
    local conf_file="$NGINX_CONF_D/$domain.conf"

    cat > "$conf_file" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    location / {
        proxy_pass http://$service_name:$service_port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $domain;

    ssl_certificate $NGINX_CERTS/$domain.fullchain.cer;
    ssl_certificate_key $NGINX_CERTS/$domain.key;

    location / {
        proxy_pass http://$service_name:$service_port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header X-Forwarded-Proto 'https';
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
}

# Function for extract variables from the ./wgcf/wgcf-profile.conf file
extract_wgcf_variables() {
    WGCF_PRIVATE_KEY=$(sed -n 's/PrivateKey = \(.*\)/\1/p' ./wgcf/wgcf-profile.conf)
    WGCF_IPV4_ADDRESS=$(grep -E "Address = .*[.].*" ./wgcf/wgcf-profile.conf | head -n 1 | cut -d '=' -f 2 | tr -d '[:space:]' | cut -d '/' -f 1)
    WGCF_IPV6_ADDRESS=$(grep -E "Address = .*[:].*" ./wgcf/wgcf-profile.conf | tail -n 1 | cut -d '=' -f 2 | tr -d '[:space:]' | cut -d '/' -f 1)
    WGCF_DNS=$(sed -n 's/DNS = \(.*\)/\1/p' ./wgcf/wgcf-profile.conf)
    WGCF_PUBLIC_KEY=$(sed -n 's/PublicKey = \(.*\)/\1/p' ./wgcf/wgcf-profile.conf)
    WGCF_ENDPOINT=$(sed -n 's/Endpoint = \(.*\)/\1/p' ./wgcf/wgcf-profile.conf)
}

# Function to ask for the INBOUNDS domain and validate it
ask_for_domain() {
    local domain
    while true; do
        read -rp "Enter your domain name: " domain
        if validate_domain "$domain" && check_domain_ip "$domain"; then
            update_hosts_with_address "$domain"
            break
        fi
    done
}

# Function to ask for inbound address choice and configure accordingly
ask_for_inbound_address() {
    local inbound_address_choice
    echo -e "${YELLOW}How do you want to address the inbound?${NC}"
    select inbound_address_choice in "domain" "real_public_ip" "default_server_ip"; do
        case $inbound_address_choice in
            "domain")
                ask_for_domain
                break
                ;;
            "real_public_ip")
                update_hosts_with_address "$PUBLIC_IP"
                break
                ;;
            "default_server_ip")
                break
                ;;
            *)
                echo -e "${RED}Invalid option selected. Please choose a valid option.${NC}"
                ;;
        esac
    done
}

# Function to get the Docker internal IP of marzban container
get_marzban_ip() {
    echo $(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' marzban)
}

# Function to retrieve access token
get_access_token() {
    local marzban_ip=$(get_marzban_ip)
    local access_token_response=$(curl -s -X 'POST' \
        "http://${marzban_ip}:8000/api/admin/token" \
        -H 'accept: application/json' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "grant_type=password&username=${SUDO_USERNAME}&password=${SUDO_PASSWORD}&scope=&client_id=&client_secret=")
    
    local access_token=$(echo "$access_token_response" | jq -r '.access_token')
    
    if [[ -z "$access_token" || "$access_token" == "null" ]]; then
        echo "Error: Failed to retrieve access token."
        exit 1
    fi

    echo "$access_token"
}

update_hosts() {
    local access_token=$1
    local response=$2
    local server_ip=$3
    local marzban_ip=$(get_marzban_ip)
    local updated_response=$(echo "$response" | jq --arg ip "$server_ip" 'walk(if type == "object" and has("address") and .address == "{SERVER_IP}" then .address = $ip else . end)')
    local update_response=$(curl -s --request PUT \
        --url "http://${marzban_ip}:8000/api/hosts" \
        --header "Authorization: Bearer ${access_token}" \
        --header 'Content-Type: application/json' \
        --data "$updated_response")

    echo "$update_response"
}

# Function to update hosts with the specified address (domain name or IP)
update_hosts_with_address() {
    local address=$1
    local marzban_ip=$(get_marzban_ip)
    access_token=$(get_access_token)
    hosts=$(curl -s --request GET \
        --url "http://${marzban_ip}:8000/api/hosts" \
        --header "Authorization: Bearer ${access_token}" \
        --header 'Content-Type: application/json')
    updated_hosts=$(update_hosts "$access_token" "$hosts" "$address")
    update_hosts_ip=$(curl -s --request PUT \
        --url "http://${marzban_ip}:8000/api/hosts" \
        --header "Authorization: Bearer ${access_token}" \
        --header 'Content-Type: application/json' \
        --data "$updated_hosts")
}

# Function to add an inbound to the JSON configuration
add_inbound_to_config() {
  local inbound="$1"
  config=$(jq ".inbounds += [$inbound]" <<< "$config")
}
# Function to reorder language options in the HTML file
reorder_language_options() {
    local preferred_language=$1
    local options=""
    case $preferred_language in
        "Persian")
            options="<option value=\"fa\">فارسی<\/option>\n<option value=\"en\">English<\/option>\n<option value=\"ru\">Русский<\/option>"
            ;;
        "English")
            options="<option value=\"en\">English<\/option>\n<option value=\"fa\">فارسی<\/option>\n<option value=\"ru\">Русский<\/option>"
            ;;
        "Russian")
            options="<option value=\"ru\">Русский<\/option>\n<option value=\"en\">English<\/option>\n<option value=\"fa\">فارسی<\/option>"
            ;;
    esac

    sed -i "s|<option value=\"ru\">Русский</option>||" ./marzban/templates/subscription/index.html
    sed -i "s|<option value=\"fa\">فارسی</option>||" ./marzban/templates/subscription/index.html
    sed -i "s|<option value=\"en\">English</option>|$options|" ./marzban/templates/subscription/index.html
}


# Function to install the Marzban subscription template
install_marzban_subscription_template_x0sina() {
    mkdir -p ./marzban/templates/subscription
    wget -N -P ./marzban/templates/subscription https://raw.githubusercontent.com/x0sina/marzban-sub/main/index.html
    update_env_file "CUSTOM_TEMPLATES_DIRECTORY" "/var/lib/marzban/templates/"
    update_env_file "SUBSCRIPTION_PAGE_TEMPLATE" "subscription/index.html"
    select_default_language
}

# Function to install the Marzban dashboard template
install_marzban_subscription_template_oXIIIo() {
    mkdir -p ./marzban/templates/subscription
    mkdir -p ./marzban/templates/clash
    mkdir -p ./marzban/templates/singbox
    mkdir -p ./marzban/templates/home
    wget -N -P ./marzban/templates/clash/ https://raw.githubusercontent.com/oXIIIo/marzban-template/master/clash/default.yml
    wget -N -P ./marzban/templates/singbox/ https://raw.githubusercontent.com/oXIIIo/marzban-template/master/singbox/default.json
    wget -N -P ./marzban/templates/subscription/ https://raw.githubusercontent.com/oXIIIo/marzban-template/master/subscription/index.html
    wget -N -P ./marzban/templates/home/ https://raw.githubusercontent.com/oXIIIo/marzban-template/master/home/index.html
    update_env_file "CUSTOM_TEMPLATES_DIRECTORY" "/var/lib/marzban/templates/"
    update_env_file "SUBSCRIPTION_PAGE_TEMPLATE" "subscription/index.html"
    update_env_file "CLASH_CONFIG_TEMPLATE" "clash/default.yml"
    update_env_file "SINGBOX_CONFIG_TEMPLATE" "singbox/default.json"
    update_env_file "HOME_PAGE_TEMPLATE" "home/index.html"
}

# Function to select the default language
select_default_language() {
    echo "Select the default language for this dashboard:"
    select language_choice in "Persian" "English" "Russian"; do
        case $language_choice in
            "Persian"|"English"|"Russian")
                reorder_language_options "$language_choice"
                break
                ;;
            *)
                echo "Invalid selection. Please choose a valid language."
                ;;
        esac
    done
}

# Function to ask user which dashboard to install
ask_dashboard_choice() {
    local install_choice
    install_choice=$(ask_yes_no "Do you want to install a custom dashboard for your Marzban panel?")
    
    if [[ "$install_choice" == "yes" ]]; then
        echo "Choose which dashboard to install:"
        select dashboard in "Template by x0sina" "Template by oXIIIo"; do
            case $dashboard in
                "Template by x0sina")
                    install_marzban_subscription_template_x0sina
                    break
                    ;;
                "Template by oXIIIo")
                    install_marzban_subscription_template_oXIIIo
                    break
                    ;;
                *)
                    echo "Invalid selection. Please choose a valid dashboard."
                    ;;
            esac
        done
    fi
}


# Function to create the backup script
create_backup_script() {
    # Determine CRON interval from the chosen schedule
    case $TELEGRAM_BACKUP_CRON in
        "hourly") CRON_INTERVAL="0 * * * *";;
        "every 2 hours") CRON_INTERVAL="0 */2 * * *";;
        "every 3 hours") CRON_INTERVAL="0 */3 * * *";;
        "every 4 hours") CRON_INTERVAL="0 */4 * * *";;
        "every 5 hours") CRON_INTERVAL="0 */5 * * *";;
        "every 6 hours") CRON_INTERVAL="0 */6 * * *";;
        "every 7 hours") CRON_INTERVAL="0 */7 * * *";;
        "every 8 hours") CRON_INTERVAL="0 */8 * * *";;
        "every 9 hours") CRON_INTERVAL="0 */9 * * *";;
        *) 
            echo "Invalid backup interval. Please set a valid interval in the .env file."
            return 1
            ;;
    esac

# Create the backup.sh script with the updated content
cat << 'EOF' > backup.sh
#!/bin/bash

# Colors for output
RED='\033[1;31m'
GREEN='\033[0;32m'  
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

cd "$SCRIPT_DIR"

BACKUP_DIR="backups"
mkdir -p "$BACKUP_DIR"

set -a
source .env
set +a

DATE=$(date +%Y-%m-%d)
TIME=$(date +%H-%M-%S)

PUBLIC_IP=$(curl -s http://ipinfo.io/ip)

# Backup filename
BACKUP_FILE="$BACKUP_DIR/${MARZBAN_ADDRESS}-${DATE}-${TIME}.zip"

# MySQL Database backup
if [ "$DB_CHOICE" = "mysql" ]; then

  MYSQL_CONTAINER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mysql)

  if [ -z "$MYSQL_CONTAINER_IP" ]; then
    echo "${RED}Failed to get MySQL container IP address${NC}"
    exit 1
  fi

  mysqldump -h $MYSQL_CONTAINER_IP -u root -p$MYSQL_ROOT_PASSWORD $MYSQL_DATABASE > "./db.sql"

fi

# Create zip archive excluding backups directory and 'mysql' directories
zip -r "$BACKUP_FILE" . -x "$BACKUP_DIR/*" -x "*/mysql/*" -x "wgcf/*"

# Send backup to Telegram
curl -F document=@"$BACKUP_FILE" "https://api.telegram.org/bot$TELEGRAM_API_TOKEN/sendDocument" \
  -F chat_id="$TELEGRAM_ADMIN_ID" \
  -F caption="Backup sent from $PUBLIC_IP, Date: $DATE, Time: $TIME" > /dev/null 2>&1

# Remove old backups after 30 days 
find "$BACKUP_DIR" -type f -name '*.zip' -mtime +30 -delete
EOF
    chmod +x backup.sh

    # Add the backup script to crontab if it's not already present
    local backup_script_path=$(realpath backup.sh)
    if ! crontab -l | grep -q "$backup_script_path"; then
        (crontab -l 2>/dev/null; echo "$CRON_INTERVAL $backup_script_path") | crontab -
        echo "Backup script added to crontab."
    else
        echo "Backup script is already scheduled in crontab."
    fi
}

# Ensure the necessary directories exist
ensure_directories
# Issue and configure certificates and nginx configs
declare -A domains_services_ports=(
    ["$MARZBAN_ADDRESS"]="marzban:8000"
    ["$XRAY_SUBSCRIPTION_URL"]="marzban:8000"
)

# Add PMA_ADDRESS if it is set in the .env file
if [[ -n "$PMA_ADDRESS" ]]; then
    domains_services_ports["$PMA_ADDRESS"]="phpmyadmin:$APACHE_PORT"
fi

# Getting cetificates for domains
echo -e "${YELLOW}Getting certificates for domains...${NC}"
for domain in "${!domains_services_ports[@]}"; do
    service_info=(${domains_services_ports[$domain]//:/ })
    service_name=${service_info[0]}
    service_port=${service_info[1]}

    if issue_certificate "$domain"; then
        generate_nginx_conf "$domain" "$service_name" "$service_port"
    fi
    $ACME_HOME/acme.sh --upgrade --auto-upgrade
    $ACME_HOME/acme.sh --cron --home $ACME_HOME
done


# Handle the WARP_OUTBOUND_CHOICE
if [[ "$WARP_OUTBOUND_CHOICE" == "yes" ]]; then
    if [[ ! -f "./wgcf/wgcf" ]]; then
        mkdir -p wgcf
        wget $WARP_RELEASE_URL -O ./wgcf/wgcf
        chmod +x ./wgcf/wgcf

        pushd wgcf
        ./wgcf register
        popd
    fi
    if [[ "$WARP_LICENSE_CHOICE" == "yes" ]]; then
        pushd wgcf
        # replace the license key in the wgcf-account.toml file
        sed -i "s/license_key = '.\+'/license_key = '$WARP_LICENSE'/" wgcf-account.toml
        ./wgcf update
        popd
    fi

pushd wgcf
./wgcf generate
popd

fi


# Default outbounds
OUTBOUNDS=""
blackhole_outbound='{
    "tag": "block",
    "protocol": "blackhole",
    "settings": {}
}'
direct_outbound='{
    "tag": "direct",
    "protocol": "freedom",
    "settings": {}
}'

# Add WARP outbound if selected
if [[ "$WARP_OUTBOUND_CHOICE" == "yes" ]]; then
    # extract the variables from the ./wgcf/wgcf-profile.conf file
    extract_wgcf_variables
    # Save the WARP outbound in a variable
    WARP_OUTBOUND='{
        "tag": "warp",
        "protocol": "wireguard",
        "settings": {
            "secretKey": "'"$WGCF_PRIVATE_KEY"'",
            "DNS": "'"$WGCF_DNS"'",
            "address": ["'"$WGCF_IPV4_ADDRESS"'", "'"$WGCF_IPV6_ADDRESS"'"],
            "peers": [
                {
                    "publicKey": "'"$WGCF_PUBLIC_KEY"'",
                    "endpoint": "'"$WGCF_ENDPOINT"'"
                }
            ]
        }
    }'

    # Add WARP outbound to the list of outbounds
    OUTBOUNDS="[$WARP_OUTBOUND,$direct_outbound,$blackhole_outbound]"
else
    # Add default outbounds to the list of outbounds
    OUTBOUNDS="[$direct_outbound,$blackhole_outbound]"
fi


# Downloading latest version of XRAY
echo -e "${YELLOW}Downloading latest version of XRAY...${NC}"
mkdir -p ./marzban/xray-core
XRAY_RELEASE_URL=$(get_latest_release_url_xray)
wget -O ./marzban/xray-core/xray.zip $XRAY_RELEASE_URL
unzip -o ./marzban/xray-core/xray.zip -d ./marzban/xray-core
rm ./marzban/xray-core/xray.zip ./marzban/xray-core/README.md ./marzban/xray-core/LICENSE ./marzban/xray-core/geo*

# Downloading xray assets
echo -e "${YELLOW}Downloading XRAY assets...${NC}"
mkdir -p ./marzban/xray-core/assets
v2ray_assets=$(curl -s https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest)
v2ray_assets_download_url=$(echo "$v2ray_assets" | jq -r '.assets[] | select(.name | endswith(".zip")).browser_download_url')
curl -L -o latest_release.zip "$v2ray_assets_download_url"
unzip -o latest_release.zip -d ./marzban/xray-core/assets
rm latest_release.zip

# Configuring Inbounds
echo -e "${YELLOW}Configuring Inbounds...${NC}"

vmess_tcp_inbound="{\"tag\": \"VMess TCP\",\"listen\": \"::\",\"port\": 8081,\"protocol\": \"vmess\",\"settings\": {\"clients\": []},\"streamSettings\": {\"network\": \"tcp\",\"tcpSettings\": {\"header\": {\"type\": \"http\",\"request\": {\"method\": \"GET\",\"path\": [\"/\"],\"headers\": {\"Host\": [\"google.com\"]}},\"response\": {}}},\"security\": \"none\"},\"sniffing\": {\"enabled\": true,\"destOverride\": [\"http\",\"tls\"]}}"
trojan_ws_tls_inbound="{\"tag\": \"Trojan Websocket TLS\",\"listen\": \"::\",\"port\": 2083,\"protocol\": \"trojan\",\"settings\": {\"clients\": []},\"streamSettings\": {\"network\": \"ws\",\"security\": \"tls\",\"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"/usr/local/etc/certs/${XRAY_SUBSCRIPTION_URL}.cer\",\"keyFile\": \"/usr/local/etc/certs/${XRAY_SUBSCRIPTION_URL}.key\"}],\"minVersion\": \"1.2\",\"cipherSuites\": \"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"}},\"sniffing\": {\"enabled\": true,\"destOverride\": [\"http\",\"tls\"]}}"
vmess_ws_inbound="{\"tag\": \"VMess Websocket\",\"listen\": \"::\",\"port\": 8080,\"protocol\": \"vmess\",\"settings\": {\"clients\": []},\"streamSettings\": {\"network\": \"ws\",\"wsSettings\": {\"path\": \"/\",\"headers\": {\"Host\": \"google.com\"}},\"security\": \"none\"},\"sniffing\": {\"enabled\": true,\"destOverride\": [\"http\",\"tls\"]}}"
shadowsocks_tcp_inbound="{\"tag\": \"Shadowsocks TCP\",\"listen\": \"::\",\"port\": 1080,\"protocol\": \"shadowsocks\",\"settings\": {\"clients\": [],\"network\": \"tcp,udp\"}}"


# Generate shortids & private keys
private_key_vless_tcp_reality=$(generate_private_key)
private_key_vless_grpc_reality=$(generate_private_key)
short_id_vless_tcp_reality=$(generate_short_id)
short_id_vless_grpc_reality=$(generate_short_id)

vless_tcp_reality_inbound="{\"tag\": \"VLESS TCP REALITY\",\"listen\": \"::\",\"port\": 8443,\"protocol\": \"vless\",\"settings\": {\"clients\": [],\"decryption\": \"none\"},\"streamSettings\": {\"network\": \"tcp\",\"tcpSettings\": {},\"security\": \"reality\",\"realitySettings\": {\"show\": false,\"dest\": \"discordapp.com:443\",\"xver\": 0,\"serverNames\": [\"cdn.discordapp.com\",\"discordapp.com\"],\"privateKey\": \"${private_key_vless_tcp_reality}\",\"shortIds\": [\"${short_id_vless_tcp_reality}\"]}},\"sniffing\": {\"enabled\": true,\"destOverride\": [\"http\",\"tls\"]}}"
vless_grpc_reality_inbound="{\"tag\": \"VLESS GRPC REALITY\",\"listen\": \"::\",\"port\": 2053,\"protocol\": \"vless\",\"settings\": {\"clients\": [],\"decryption\": \"none\"},\"streamSettings\": {\"network\": \"grpc\",\"grpcSettings\": {\"serviceName\": \"xyz\"},\"security\": \"reality\",\"realitySettings\": {\"show\": false,\"dest\": \"discordapp.com:443\",\"xver\": 0,\"serverNames\": [\"cdn.discordapp.com\",\"discordapp.com\"],\"privateKey\": \"${private_key_vless_grpc_reality}\",\"shortIds\": [\"${short_id_vless_grpc_reality}\"]}},\"sniffing\": {\"enabled\": true,\"destOverride\": [\"http\",\"tls\"]}}"

declare -a inbounds=(
  "$vmess_tcp_inbound"
  "$vmess_ws_inbound"
  "$vless_tcp_reality_inbound"
  "$vless_grpc_reality_inbound"
  "$trojan_ws_tls_inbound"
  "$shadowsocks_tcp_inbound"
  )

# Tags for the inbounds to prompt the user
declare -a tags=(
  "VMess TCP"
  "VMess Websocket"
  "VLESS TCP REALITY"
  "VLESS GRPC REALITY"
  "Trojan Websocket TLS"
  "Shadowsocks TCP"
)


config='{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [],
  "outbounds": [],
  "routing": {
    "rules": [
      {
        "ip": [
          "geoip:private"
        ],
        "domain": [
          "geosite:private"
        ],
        "outboundTag": "BLOCK",
        "type": "field"
      }    ]
  }
}'

for i in "${!inbounds[@]}"; do
  user_response=$(ask_yes_no "Include \"${tags[$i]}\" inbound?")
  if [[ "$user_response" == "yes" ]]; then
    add_inbound_to_config "${inbounds[$i]}"
  fi
done

config=$(jq --argjson outbounds "$OUTBOUNDS" '.outbounds = $outbounds' <<< "$config")

mkdir -p marzban
if cat > ./marzban/xray_config.json <<EOL
$config
EOL
then
    echo -e "${GREEN}Configuration has been written to xray_config.json${NC}"

else
    echo "${RED}Failed to write configuration to xray_config.json${NC}"
    exit 1
fi

echo -e "${YELLOW}Custom Dashboards ...${NC}"
ask_dashboard_choice

docker compose up -d && docker compose logs

while [[ "$(docker inspect -f '{{.State.Health.Status}}' marzban)" != "healthy" ]]; do
    sleep 5
done

echo -e "${YELLOW}Configuring Marzban inbounds address. This is the address that appears in the clients' connections in the Xray client. You can choose the:${NC}"
echo -e "${YELLOW}1. domain: This is a domain or subdomain pointed to the server${NC}"
echo -e "${YELLOW}2. real_public_ip: This is the real public IP of the server${NC}"
echo -e "${YELLOW}3. default_server_ip: This is the default {SERVER_IP} set by Marzban${NC}"
ask_for_inbound_address

if [[ "$TELEGRAM_BACKUP_CHOICE" == "yes" ]]; then
    # Function call to create the backup script
    create_backup_script
    # Send a message over Telegram to the user to notify them backup is going to get started and donot exit 
    # script as it may take some time for execution to complete and also tell them they can use /start to use marzban bot
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_API_TOKEN/sendMessage" \
        -H 'Content-Type: application/json' \
        -d "{\"chat_id\": \"$TELEGRAM_ADMIN_ID\", \"text\": \"Backup is going to get started. You can use /start to use marzban bot. Please do not exit the script.\"}" > /dev/null
    ./backup.sh "$PWD"
fi


echo -e "${GREEN}Marzban is now running.${NC}"
echo -e "${YELLOW}You can access Marzban at ${GREEN}https://$MARZBAN_ADDRESS/dashboard/login${NC}"

if [[ "$PHPMYADMIN_CHOICE" == "yes" ]]; then
    echo -e "${YELLOW}phpMyAdmin is available at ${GREEN} https://$PMA_ADDRESS${NC}"
    echo -e "${YELLOW}Server is: ${GREEN}mysql${NC}"
    echo -e "${YELLOW}Username is: ${GREEN}root${NC}"
fi