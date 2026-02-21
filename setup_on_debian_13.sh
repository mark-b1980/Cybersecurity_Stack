#!/bin/bash

################################################################################################
# Check if running as root
################################################################################################
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

################################################################################################
# Change directory to script location & get absolute path
################################################################################################
script_dir=$(dirname "$0")
cd "$script_dir"

script_dir=$(pwd)

################################################################################################
# Install needed tools
################################################################################################
apt update
apt install -y openssh-server docker.io docker-compose ufw htop cron python3-venv
systemctl enable sshd
systemctl start sshd

################################################################################################
# Configure firewall
################################################################################################
# SSH for management purposes
ufw allow 22/tcp   # SSH access for management purposes

# Velociraptor
ufw allow 8000/tcp # Velociraptor client-server communication
ufw allow 8001/tcp # Velociraptor client-server communication
ufw allow 8889/tcp # Velociraptor web interface

# GVM
ufw allow 2222/tcp # GVM SSH
ufw allow 9392/tcp # GVM web interface

# ELK Stack
ufw allow 5601/tcp # Kibana
ufw allow 9200/tcp # Elasticsearch
ufw allow 9000/tcp # Logstash
ufw allow 5141/udp # Syslog input for pfSense

ufw enable
ufw status

################################################################################################
# Add user to docker group
################################################################################################
getent group docker || groupadd docker
read -p "Enter the username to add to the docker group: " USER_NAME
usermod -aG docker $USER_NAME

################################################################################################
# Setup venv
################################################################################################
python3 -m venv stack_venv

################################################################################################
# Run the setup script of each component
################################################################################################

