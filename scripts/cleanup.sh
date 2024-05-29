#!/bin/bash

# Ensure the script is run as root or with sudo
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root or with sudo" >&2
  exit 1
fi

DOCKER_COMPOSE="docker-compose"

if ! command -v docker-compose
then
        DOCKER_COMPOSE="docker compose"
        echo "Docker compose command set to new style $DOCKER_COMPOSE"
fi

$DOCKER_COMPOSE down
docker volume rm --force civtak-server_db_data
rm -rf tak
rm -rf /tmp/takserver
rm -f .env

# Comment me out to avoid deleting lets_encrypt certificates
rm -f lets_encrypt/*

# Comment me out to save yourself rebuilding........
docker image rm tak-server-db --force
docker image rm tak-server-tak --force
