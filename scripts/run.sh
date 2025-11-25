#!/bin/bash
set -e

cd "$(dirname "$0")/.."

# Note: Mininet must be run as root.  So invoke this shell script
# using sudo.

TIME=100
BW_NET=10

# TODO: If you want the RTT to be 4ms what should the delay on each
# link be?  Set this value correctly.
DELAY=1
IPERF_PORT=5001

# Queue sizes to test
QSIZES=(100)
# QSIZES=(10 60)
# note: run QSIZES=(20) and QSIZES=(100) separately when running with AQM
# make sure we don't use a cached cwnd
sysctl -w net.ipv4.tcp_no_metrics_save=1

echo "Starting bufferbloat experiments..."
echo "Network parameters: BW=${BW_NET}Mbps, Delay=${DELAY}ms (RTT=4ms)"

for qsize in "${QSIZES[@]}"; do
    echo "----------------------------------------"
    echo "Running experiment with queue size: $qsize packets"
    # dir="bb-q$qsize"
    # Uncomment when running with AQM
    dir="bb-aqm-q$qsize"

    python3 bufferbloat.py --dir=$dir --time=$TIME --bw-net=$BW_NET --delay=$DELAY --maxq=$qsize

    # TODO: Ensure the input file names match the ones you use in
    # bufferbloat.py script.  Also ensure the plot file names match
    # the required naming convsention when submitting your tarball.
    python3 plot_tcpprobe.py -f $dir/cwnd.txt -o $dir/cwnd-iperf.png -p $IPERF_PORT
    python3 plot_queue.py -f $dir/q.txt -o $dir/q.png
    python3 plot_ping.py -f $dir/ping.txt -o $dir/rtt.png
done
