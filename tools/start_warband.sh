#!/bin/bash
cd ..
source source/env/bin/activate
gnome-terminal -- bash -c "python source/main.py"
gnome-terminal -- bash -c "python scripts/WarbandIpListTransmitter.py"
