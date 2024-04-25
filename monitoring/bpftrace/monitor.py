#!/usr/bin/env python3

import os
from argparse import ArgumentParser
import subprocess

def get_args():
    parser = ArgumentParser(description="Run a command and monitor its system calls")
    parser.add_argument("-p", "--process", required=True, help="Process to monitor/trace")
    parser.add_argument("-o", "--csv-output", required=False, help="CSV file to write to")
    parser.add_argument("-c", "--command", required=False, help="Command to trace")
    return parser.parse_args()

def run_command(command):
    # Run the command in the background using subprocess
    subprocess.Popen(command, shell=True)
    return command.split()[0] # Return the process name

def run_trace(process, output):
    pid = subprocess.Popen(["pgrep", process], stdout=subprocess.PIPE).stdout.read().decode("utf-8").strip()
    bpf_command = f"bpftrace monitoring.bt {pid} > {output}"
    bpf_trace = subprocess.Popen(bpf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = bpf_trace.communicate()

    return bpf_trace

def main():
    args = get_args()
    if args.command is not None: 
        process = run_command(args.command)
    else:
        process = args.process
    bpf_trace = run_trace(args.process, args.csv_output)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        # Kill the process and the bpftrace script
        pid = subprocess.Popen(["pgrep", process], stdout=subprocess.PIPE).stdout.read().decode("utf-8").strip()
        os.system(f"kill {pid}")
        bpf_trace.kill()
        print("Exiting...")
        exit()
