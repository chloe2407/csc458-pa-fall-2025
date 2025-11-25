#!/usr/bin/python3
"CSC458 Fall 2025 Programming Assignment 2: Bufferbloat"

from typing import List, Tuple

from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.clean import cleanup

import subprocess
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

from monitor import monitor_qlen
import termcolor as T

import sys
import os
import math

import statistics as stats

# TODO: Don't just read the TODO sections in this code.  Remember that
# one of the goals of this assignment is for you to learn how to use
# Mininet.

parser = ArgumentParser(description="Bufferbloat tests")
parser.add_argument(
    "--bw-host", "-B", type=float, help="Bandwidth of host links (Mb/s)", default=1000
)

parser.add_argument(
    "--bw-net",
    "-b",
    type=float,
    help="Bandwidth of bottleneck (network) link (Mb/s)",
    required=True,
)

parser.add_argument(
    "--delay", type=float, help="Link propagation delay (ms)", required=True
)

parser.add_argument("--dir", "-d", help="Directory to store outputs", required=True)

parser.add_argument(
    "--time", "-t", help="Duration (sec) to run the experiment", type=int, default=10
)

parser.add_argument(
    "--maxq",
    type=int,
    help="Max buffer size of network interface in packets",
    default=100,
)

# Linux uses CUBIC-TCP by default that doesn't have the usual sawtooth
# behaviour.  For those who are curious, invoke this script with
# --cong cubic and see what happens...
# sysctl -a | grep cong should list some interesting parameters.
parser.add_argument(
    "--cong", help="Congestion control algorithm to use", default="reno"
)

# Expt parameters
args = parser.parse_args()


class BBTopo(Topo):
    "Simple topology for bufferbloat experiment."

    def build(self, n=2) -> None:
        # Here are two hosts
        hosts = [self.addHost(f"h{i}") for i in range(1, n + 1)]

        # Here I have created a switch.  If you change its name, its
        # interface names will change from s0-eth1 to newname-eth1.
        switch = self.addSwitch("s0")

        # TODO: Add links with appropriate characteristics
        # High-speed access link h1 <-> s0 (non-bottleneck)
        self.addLink(
            hosts[0],
            switch,
            cls=TCLink,
            bw=args.bw_host,
            delay=f"{args.delay}ms",
            max_queue_size=1000,  # large so it won't be the bottleneck
            use_htb=True,
        )

        # Bottleneck link s0 <-> h2 (this is where we place maxq)
        # We attach the s0 side after the h1 link so s0-eth2 is the bottleneck egress.
        self.addLink(
            switch,
            hosts[1],
            cls=TCLink,
            bw=args.bw_net,
            delay=f"{args.delay}ms",
            max_queue_size=args.maxq,
            use_htb=True,
        )


# Simple wrappers around monitoring utilities.  You are welcome to
# contribute neatly written (using classes) monitoring scripts for
# Mininet!


# tcp_probe kernel module was removed since it used jprobe which was deprecated.
# In Linux >= 4.16, it has been replaced by the tcp:tcp_probe kernel tracepoint.
def start_tcpprobe(outfile: str = "cwnd.txt") -> subprocess.Popen:
    """Enable tcp_probe tracepoint and log to a file."""
    subprocess.run(
        "mount -t debugfs none /sys/kernel/debug 2>/dev/null || true", shell=True
    )
    subprocess.run(
        "echo 1 > /sys/kernel/debug/tracing/events/tcp/tcp_probe/enable", shell=True
    )

    trace_file = os.path.join(args.dir, outfile)
    return subprocess.Popen(
        f"cat /sys/kernel/debug/tracing/trace_pipe > {trace_file}", shell=True
    )


def stop_tcpprobe() -> None:
    """Disable tcp_probe and stop reader."""
    subprocess.run(
        "echo 0 > /sys/kernel/debug/tracing/events/tcp/tcp_probe/enable", shell=True
    )
    subprocess.run(
        "pgrep -f 'cat /sys/kernel/debug/tracing/trace_pipe' | xargs kill -9 2>/dev/null || true",
        shell=True,
    )


def start_qmon(iface: str, interval_sec=0.1, outfile="q.txt") -> Process:
    monitor = Process(target=monitor_qlen, args=(iface, interval_sec, outfile))
    monitor.start()
    return monitor


def start_iperf(net: Mininet) -> Tuple[subprocess.Popen, subprocess.Popen]:
    """Start iperf server and (TODO) client."""
    h2 = net.get("h2")
    print("Starting iperf server...")
    # For those who are curious about the -w 16m parameter, it ensures
    # that the TCP flow is not receiver window limited.  If it is,
    # there is a chance that the router buffer may not get filled up.
    server = h2.popen("iperf -s -w 16m")
    # TODO: Start the iperf client on h1.  Ensure that you create a
    # long lived TCP flow. You may need to redirect iperf's stdout to avoid blocking.
    h1= net.get("h1")
    iperf_out = os.path.join(args.dir, "iperf_client.txt")
    # Run for the whole experiment duration (slightly longer to be safe)
    duration = max(args.time, 10)
    client = h1.popen(
        f"iperf -c {h2.IP()} -t {duration} -i 1 -w 16m > {iperf_out} 2>&1",
        shell=True,
    )
    return server, client


def start_webserver(net: Mininet) -> List[subprocess.Popen]:
    """Start HTTP webserver on h1."""
    h1 = net.get("h1")
    proc = h1.popen("python3 http/webserver.py", shell=True)
    sleep(1)
    return [proc]


def start_ping(net: Mininet) -> subprocess.Popen:
    # TODO: Start a ping train from h1 to h2 (or h2 to h1, does it
    # matter?)  Measure RTTs every 0.1 second.  Read the ping man page
    # to see how to do this.

    # Hint: Use host.popen(cmd, shell=True).  If you pass shell=True
    # to popen, you can redirect cmd's output using shell syntax.
    # i.e. ping ... > /path/to/ping.txt
    # Note that if the command prints out a lot of text to stdout, it will block
    # until stdout is read. You can avoid this by runnning popen.communicate() or
    # redirecting stdout
    h1 = net.get("h1")
    h1.popen(f"echo '' > {os.path.join(args.dir, 'ping.txt')}", shell=True)

    h2 = net.get("h2")
    ping_out = os.path.join(args.dir, "ping.txt")
    # -i 0.1: interval; -D: print timestamp; -W 1: 1s timeout; -n: numeric
    count = int(args.time * 10) + 20
    cmd = f"ping -n -D -i 0.1 -W 1 -c {count} {h2.IP()} > {ping_out} 2>&1"
    info(T.colored(f"Starting ping train h1 -> h2 @0.1s, writing {ping_out}\n", "green"))
    return h1.popen(cmd, shell=True)

def cleanup_processes() -> None:
    """Ensure all spawned processes are terminated."""
    stop_tcpprobe()
    subprocess.run(
        "pgrep -f webserver.py | xargs kill -9 2>/dev/null || true", shell=True
    )
    subprocess.run("pgrep -f iperf | xargs kill -9 2>/dev/null || true", shell=True)

def measure_http_fetch_times(net: Mininet, trials: int = 3) -> List[float]:
    """
    From h2, curl the webpage from the webserver on h1.
    We follow the assignment spec: fetch http://<h1_ip>/http/index.html
    and record total fetch time reported by curl.
    """
    h1, h2 = net.get("h1", "h2")

    # fetch <webserver ip>/http/index.html
    url = f"http://{h1.IP()}/http/index.html"

    times: List[float] = []
    http_log = os.path.join(args.dir, "http_times.txt")

    info(f"Measuring HTTP fetch times from h2: {url}\n")

    for i in range(trials):
        # -o /dev/null: discard body
        # -s: silent
        # -w "%{time_total}\n": print only total time in seconds
        cmd = f'curl -o /dev/null -s -w "%{{time_total}}\\n" "{url}"'
        output = h2.cmd(cmd)

        try:
            val = float(output.strip())
            times.append(val)

            # append to file
            with open(http_log, "a") as f:
                f.write(f"{val:.6f}\n")

            info(f"  trial {i+1}: {val:.3f} s\n")
        except ValueError:
            info(f"  trial {i+1}: failed to parse curl output: {output}\n")

        sleep(1)

    return times


def bufferbloat() -> None:
    """Main: set up topology, start monitoring, run experiment."""
    os.makedirs(args.dir, exist_ok=True)
    subprocess.run(["sysctl", "-w", f"net.ipv4.tcp_congestion_control={args.cong}"])

    # Cleanup any leftovers from previous mininet runs
    cleanup()
    cleanup_processes()

    topo = BBTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    # This performs a basic all pairs ping test.
    net.pingAll()

    # Uncomment when running with AQM
    cmd = f"tc qdisc replace dev s0-eth2 root fq_codel limit {args.maxq}"
    print("Installing fq_codel on s0-eth2 with:", cmd)
    subprocess.run(cmd, shell=True, check=True)

    # Start all the monitoring processes
    start_tcpprobe("cwnd.txt")
    start_ping(net)

    # TODO: Start monitoring the queue sizes.  Since the switch I
    # created is "s0", I monitor one of the interfaces.  Which
    # interface?  The interface numbering starts with 1 and increases.
    # Depending on the order you add links to your network, this
    # number may be 1 or 2.  Ensure you use the correct number.
    #
    qmon = start_qmon(iface='s0-eth2',
                     outfile='%s/q.txt' % (args.dir))
    # qmon = None

    # TODO: Start iperf, webservers, etc.
    # start_iperf(net)
    iperf_server, iperf_client = start_iperf(net)
    web_procs = start_webserver(net)

    # Hint: The command below invokes a CLI which you can use to
    # debug.  It allows you to run arbitrary commands inside your
    # emulated hosts h1 and h2.
    #
    # CLI(net)

    # TODO: measure the time it takes to complete webpage transfer
    # from h1 to h2 (say) 3 times.  Hint: check what the following
    # command does: curl -o /dev/null -s -w %{time_total} google.com
    # Now use the curl command to fetch webpage from the webserver you
    # spawned on host h1 (not from google!)
    # Hint: have a separate function to do this and you may find the
    # loop below useful.
    start_time = time()
    _ = measure_http_fetch_times(net, trials=3)
    while True:
        # do the measurement (say) 3 times.
        sleep(1)
        now = time()
        delta = now - start_time
        if delta > args.time:
            break
        print("%.1fs left..." % (args.time - delta))

    # TODO: compute average (and standard deviation) of the fetch
    # times.  You don't need to plot them.  Just note it in your
    # README and explain.

    http_times_path = os.path.join(args.dir, "http_times.txt")
    if os.path.exists(http_times_path):
        with open(http_times_path) as f:
            vals = [float(x.strip()) for x in f if x.strip()]
        if vals:
            mean_v = stats.mean(vals)
            std_v = stats.pstdev(vals) if len(vals) > 1 else 0.0
            summary_path = os.path.join(args.dir, "http_summary.txt")
            with open(summary_path, "w") as f:
                f.write(f"trials={len(vals)}\nmean={mean_v:.6f}\nstd={std_v:.6f}\n")
            info(T.colored(f"HTTP fetch mean={mean_v:.3f}s std={std_v:.3f}s\n", "yellow"))

    stop_tcpprobe()
    if qmon is not None:
        qmon.terminate()

    try:
        iperf_server.terminate()
        iperf_client.terminate()
    except Exception:
        pass
    for p in web_procs:
        try:
            p.terminate()
        except Exception:
            pass

    net.stop()

    # Ensure that all processes you create within Mininet are killed.
    # Sometimes they require manual killing.
    cleanup_processes()


if __name__ == "__main__":
    bufferbloat()
