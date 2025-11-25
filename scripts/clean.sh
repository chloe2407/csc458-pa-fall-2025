#!/bin/bash
# filepath: /home/mininet/pa2/clean.sh
# Script to clean up experiment files and Mininet resources

echo "Cleaning up experiment files..."

# Clean up Mininet resources
mn -c

# Remove all output directories
# rm -rf bb-q*
rm -rf bb-aqm-q*

# Remove Python cache files
rm -rf __pycache__/

pgrep -f webserver.py | xargs kill -9 2>/dev/null || true
pgrep -f iperf | xargs kill -9 2>/dev/null || true
pgrep -f 'cat /sys/kernel/debug/tracing/trace_pipe' | xargs kill -9 2>/dev/null || true
echo 0 > /sys/kernel/debug/tracing/events/tcp/tcp_probe/enable
