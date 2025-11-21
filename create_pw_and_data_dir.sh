# Main data directory
DATA_ROOT_DIR="./data"
echo "DATA_ROOT_DIR=$DATA_ROOT_DIR" > ./.env

# Clear and create directories
rm -rf "$DATA_ROOT_DIR" 2>/dev/null
mkdir "$DATA_ROOT_DIR" 2>/dev/null

# Password generatror
generate_password() {
    tr -dc A-Za-z0-9 </dev/urandom | head -c 24
}

# Generate and store admin password
PASSWORD=$(generate_password)
echo "PASSWORD=$PASSWORD" >> ./.env
