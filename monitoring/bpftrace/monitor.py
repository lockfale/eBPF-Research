#!/usr/bin/env python3

import os
from argparse import ArgumentParser
import subprocess

def get_args():
    parser = ArgumentParser(description="Run a command and monitor its system calls")
    mex_group = parser.add_argument_group('Process or Command','You can run a command or give it a process name to monitor')
    mexclusive_group = mex_group.add_mutually_exclusive_group(required=True)
    mexclusive_group.add_argument("-p", "--process", help="Process to monitor/trace")
    mexclusive_group.add_argument("-c", "--command", help="Command to trace")
    parser.add_argument("-o", "--csv-output", required=False, help="CSV file to write to")
    return parser.parse_args()

def run_command(command):
    # Run the command in the background using subprocess
    subprocess.Popen(command, shell=True)
    return command.split()[0] # Return the process name

def run_trace(process, output):
    print(f"Monitoring process: {process}")
    exe_path = os.readlink(f"/proc/{pid}/exe")
    print(f"Executable path: {exe_path}")
    pid = subprocess.Popen(["pgrep", process], stdout=subprocess.PIPE).stdout.read().decode("utf-8").strip()
    bpf_command = f"bpftrace -q procmon.bt -o {output} {pid} {exe_path}"
    bpf_trace = subprocess.Popen(bpf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = bpf_trace.communicate()
    print(stdout.decode("utf-8"))
    print(stderr.decode("utf-8"))

    return bpf_trace

def main():
    args = get_args()
    if args.command is not None: 
        process = run_command(args.command).strip()
    else:
        process = args.process
    bpf_trace = run_trace(process, args.csv_output)

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


if __name__ == "__main__":
    main()