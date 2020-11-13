# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""
import logging
import json
import os
import pytest
import subprocess

import host_tools.drive as drive_tools
import host_tools.logging as log_tools
import host_tools.network as net_tools  # pylint: disable=import-error

# Block device size in MB.
BLOCK_DEVICE_SIZE = 2048
# Iteration duration in seconds.
ITERATION_DURATION = 60 * 5

FIO_BLOCK_SIZES = [65536, 4096, 1024, 512]
FIO_TEST_MODES = ["randrw", "readwrite"]

log = logging.getLogger("blk")

cpu_usage = r"""
BEGIN {
  prev_total = 0
  prev_idle = 0
  while (getline < \"/proc/stat\") {
    close(\"/proc/stat\")
    idle = \$5
    total = 0
    for (i=2; i<=NF; i++)
      total += \$i
    print (1.0-(idle-prev_idle)/(total-prev_total))*100
    prev_idle = idle
    prev_total = total
    system(\"sleep 1\")
  }
}
"""

CRT_PIN = 0x10


def set_pinning(pid):
    """
    PIN a given PID
    """
    global CRT_PIN

    cmd = "taskset -p %s %s" % (hex(CRT_PIN), pid)

    # Run taskset on the given PID
    subprocess.run(cmd, shell=True, check=True,
                   stdout=subprocess.PIPE).stdout.decode("utf-8")

    # Bitshift the mask to get ready for the next pinning command
    CRT_PIN = CRT_PIN << 1


def run_fio(ssh_connection, mode, bs):
    """Run a fio test in the specified mode with block size bs."""
    # Clear host page cache first.
    os.system("sync; echo 1 > /proc/sys/vm/drop_caches")

    # Use noop scheduler
    os.system("echo 'noop' > /sys/block/nvme0n1/queue/scheduler")

    # Compute the fio command
    cmd = ("fio --name={mode}-{bs} --rw={mode} --bs={bs} --filename=/dev/vdb "
           "--time_based  --size={block_size}M --direct=1 --ioengine=libaio "
           "--iodepth=32 --numjobs=1  --randrepeat=0 --runtime={duration} "
           "--write_iops_log={mode}{bs} --write_bw_log={mode}{bs} --write_lat_log={mode}{bs} --write_hist_log={mode}{bs} "
           "--log_avg_msec=1000 --status-interval=1 --cpumask=14").format(
        mode=mode, bs=bs, block_size=BLOCK_DEVICE_SIZE,
        duration=ITERATION_DURATION)

    # Use noop in the guest too
    ssh_connection.execute_command(
        "echo 'noop' > /sys/block/vdb/queue/scheduler")

    # Start the CPU usage parser
    ssh_connection.execute_command(f"echo \"{cpu_usage}\" > ~/cpu_usage.awk")
    ssh_connection.execute_command(
        f"timeout {ITERATION_DURATION} awk -f ~/cpu_usage.awk > {mode}{bs}_cpu.log&")

    # Print the fio command in the log and run it
    log.error(cmd)
    ssh_connection.execute_command(cmd)

    #
    os.makedirs(f"results/{mode}{bs}", exist_ok=True)
    ssh_connection.scp_get_file("*.log", f"results/{mode}{bs}")

    ssh_connection.execute_command("rm *.log")

    log.error("Done")


@pytest.mark.timeout(ITERATION_DURATION * 1000)
@pytest.mark.benchmark
def test_block_device_performance(test_microvm_with_ssh, network_config):
    """Execute block device emulation benchmarking scenarios."""

    microvm = test_microvm_with_ssh
    microvm.spawn()
    microvm.basic_config(
        mem_size_mib=1024,
        vcpu_count=4,
        boot_args="isolcpus=1-3 nohz_full=1-3 rcu_nocbs=1-3")

    # Configure metrics system.
    metrics_fifo_path = os.path.join(microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = microvm.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(microvm.fsfiles, 'scratch'),
        BLOCK_DEVICE_SIZE
    )

    response = microvm.drive.put(
        drive_id='scratch',
        path_on_host=microvm.create_jailed_resource(fs.path),
        is_root_device=False,
        is_read_only=False
    )
    assert microvm.api_session.is_status_no_content(
        response.status_code)

    _tap, _, _ = microvm.ssh_network_config(network_config, '1')

    microvm.start()
    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

    # Get Firecracker PID so we can check the names of threads.
    firecracker_pid = microvm.jailer_clone_pid

    # Get names of threads in Firecracker.
    cmd = 'ps -T --no-headers -p {} | sed \'s/  */ /g\''.format(
        firecracker_pid
    )
    out = subprocess.run(cmd, shell=True, check=True,
                         stdout=subprocess.PIPE).stdout.decode("utf-8")
    for line in out.split("\n"):
        if line == "":
            continue

        # Pin each PID
        ps_data = line.split(" ")
        set_pinning(ps_data[2])

    for mode in FIO_TEST_MODES:
        for bs in FIO_BLOCK_SIZES:
            log.error(f"Run {mode} {bs}")
            run_fio(ssh_connection, mode, bs)

    lines = metrics_fifo.sequential_reader(100)

    for line in lines:
        print(json.loads(line)["block"]["flush_count"])
