#!/bin/bash
cd ..
gnome-terminal -- bash -c ".\source\env\bin\python .\source\main.py"
gnome-terminal -- bash -c "python .\scripts\WarbandIpListTransmitter.py"
