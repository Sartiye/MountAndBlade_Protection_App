#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_DIR="$REPO_DIR/services"
SYSTEMD_DIR="/etc/systemd/system"
USER=${SUDO_USER:-$USER}

if [ ! -d "$SERVICE_DIR" ]; then
  echo "Service directory not found: $SERVICE_DIR"
  exit 1
fi

echo "Updating systemd services from: $SERVICE_DIR"
for service_file in "$SERVICE_DIR"/*.service; do
  if [ -f "$service_file" ]; then
    service_name=$(basename "$service_file")
    echo "Installing $service_name..."
    sudo cp "$service_file" "$SYSTEMD_DIR/"
    sudo sed -i "s|__USER__|$USER|g" "$SYSTEMD_DIR/$service_name"
    sudo sed -i "s|__REPO_DIR__|$REPO_DIR|g" "$SYSTEMD_DIR/$service_name"
  fi
done

echo "Reloading systemd daemon and restarting services..."
sudo systemctl daemon-reload

for service_file in "$SERVICE_DIR"/*.service; do
  if [ -f "$service_file" ]; then
    service_name=$(basename "$service_file")
    sudo systemctl restart "$service_name"
    sudo systemctl enable "$service_name"
    echo "Restarted and enabled $service_name"
  fi
done

echo "✅ All services updated, restarted, and enabled on boot."
