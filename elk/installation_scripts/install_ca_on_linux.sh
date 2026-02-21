#!/bin/bash

################################################################################################
# Check if running as root
################################################################################################
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Setup ca.crt as trusted
mkdir -p /usr/local/share/ca-certificates/elastic
cp ca.crt /usr/local/share/ca-certificates/elastic/elastic-stack-ca.crt
update-ca-certificates
