#!/bin/bash
# Dependency installation script for Ubuntu 24.04

set -e

echo "---- Ubuntu 24.04: Installing system dependencies ----"
sudo apt-get update -y
sudo apt-get install -y cmake gdb python3 python3-venv python3-pip libopencv-dev unzip

echo "---- Creating Python virtual environment and installing Python packages ----"
cd "$(dirname "$0")"
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install numpy opencv-python cma spicy

echo "---- Installation complete! ----"
echo "To activate the virtual environment, run: source .venv/bin/activate"
echo "You can now build the C++ executables and run the attack scripts." 