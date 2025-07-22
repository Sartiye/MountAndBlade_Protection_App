#!/bin/bash
cd ..

export GOOGLE_APPLICATION_CREDENTIALS="data/credentials/firewall-manager.json"
source source/env/bin/activate
gnome-terminal -- bash -c "python source/main.py"
