#!/bin/bash

# Config
REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
SERVICE_DIR="$REPO_DIR/services"
SYSTEMD_DIR="/etc/systemd/system"
USER=$(whoami)

# Step 1: Check for service files
if [ ! -d "$SERVICE_DIR" ]; then
  echo "Service directory not found: $SERVICE_DIR"
  exit 1
fi

# Step 2: Copy each .service file and update user placeholder
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

# Step 3: Reload systemd and restart all updated services
echo "Reloading systemd daemon and restarting services..."
sudo systemctl daemon-reexec
for service_file in "$SERVICE_DIR"/*.service; do
  if [ -f "$service_file" ]; then
    service_name=$(basename "$service_file")
    service_unit="${service_name}"
    sudo systemctl restart "$service_unit"
    echo "Restarted $service_unit"
  fi
done

echo "✅ All services updated and restarted."
