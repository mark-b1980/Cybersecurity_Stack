#!/bin/bash
docker compose down -v --remove-orphans
docker volume prune -f
bash initial_setup.sh