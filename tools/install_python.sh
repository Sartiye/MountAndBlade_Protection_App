#!/bin/bash

set -e  # Exit on error

cd "$(dirname "$0")/.."

echo "🧪 Setting up Python virtual environment..."

# Ensure pip and venv are installed
echo "🔧 Installing system dependencies..."
sudo apt install python3-pip python3-venv -y

# Create the virtual environment only if it doesn't exist
if [ ! -d "source/env" ]; then
  echo "📦 Creating new virtual environment..."
  python3 -m venv source/env
else
  echo "✅ Virtual environment already exists."
fi

# Activate it and install requirements
echo "📥 Installing Python packages from requirements.txt..."
source source/env/bin/activate
pip install --upgrade pip
pip install -r source/requirements_linux.txt
deactivate

echo "✅ Python environment setup complete!"
