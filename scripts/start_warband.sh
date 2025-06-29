#!/bin/bash
cd ..
source source/env/bin/activate
gnome-terminal -- bash -c "python addons/WarbandIpListTransmitter.py"
