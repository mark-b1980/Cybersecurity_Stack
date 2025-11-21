#!/bin/bash
# Determine script path and cd to the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create data directories and generate admin password
bash ../create_pw_and_data_dir.sh

# Ask for SERVER_IP if not set
read -p "Enter the SERVER_IP or FQDN for Velociraptor server: " SERVER_IP
echo "SERVER_IP=$SERVER_IP" >> ./.env

# Read data from .env file
source ./.env

# Start Velociraptor service
echo "Starting Velociraptor Docker Setup..."
docker-compose up -d
sleep 20

# Display access information
echo "--------------------------------------------------------"
echo "Your admin password is:"
echo "$PASSWORD"
echo "--------------------------------------------------------"

echo ""
echo "You can access Velociraptor at: https://${SERVER_IP}:8889/"
echo ""

echo "Don't forget to install the server certificate on your clients!"
echo "You can find it in the 'data' directory as 'server.crt'."