# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests guest memory performance of Firecracker uVMs."""


import os
import csv
import json
import logging
import time
import concurrent.futures
import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder
from framework.statistics import core, consumer, producer, criteria,  types, \
    function
from framework.utils import CpuMap, CmdBuilder, run_cmd, eager_map, \
    get_cpu_percent
from framework.utils_cpuid import get_cpu_model_name

import host_tools.network as net_tools

ITERATIONS = 3
HOST_OUTPUT_FILE = "xmem_output_host.csv"
GUEST_OUTPUT_FILE = "xmem_output_guest.csv"
WORKER_THREADS = "2"


def get_measurements(csvfile):
    with open(csvfile) as file:
        reader = csv.DictReader(file)
        list = []
        line_count = 0

        for row in reader:
            if line_count == 0:
                # print(row)
                list.append(row['99th Percentile Load Throughput'])
            elif line_count == 1:
                # print(row)
                list.append(row['99th Percentile Load Throughput'])
            elif line_count == 2:
                # print(row)
                list.append(row['99th Percentile Latency'])

            line_count += 1

    return list


@ pytest.mark.nonci
@ pytest.mark.timeout(600)
def test_memory_performance(bin_cloner_path):
    """Test memory performance driver for multiple artifacts."""
    logger = logging.getLogger("memory")
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_1024mb"))
    # microvm_artifacts.insert(artifacts.microvms(keyword="1vcpu_1024mb"))
    kernel_artifacts = ArtifactSet(
        artifacts.kernels(keyword="vmlinux-4.14.bin"))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'logger': logger,
        'name': 'memory'
    }

    print(get_cpu_model_name())

    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])
    test_matrix.run_test(memory_workload)


def memory_workload(context):
    """Run a statistic exercise."""
    vm_builder = context.custom['builder']
    logger = context.custom["logger"]

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from artifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[rw_disk],
                              ssh_key=ssh_key,
                              config=context.microvm)

    basevm.start()

    conn = net_tools.SSHConnection(basevm.ssh_config)

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    # assert CpuMap.len() >= 2 + basevm.vcpus_count

    # Pin uVM threads to physical cores.
    current_avail_cpu = 2
    assert basevm.pin_vmm(current_avail_cpu), \
        "Failed to pin firecracker thread."
    current_avail_cpu += 1
    assert basevm.pin_api(current_avail_cpu), \
        "Failed to pin fc_api thread."
    for i in range(basevm.vcpus_count):
        current_avail_cpu += 1
        assert basevm.pin_vcpu(i, current_avail_cpu), \
            f"Failed to pin fc_vcpu {i} thread."

    logger.info("Testing with microvm: \"{}\", kernel {}, disk {}"
                .format(context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    cmd = "xmem -- -n{} -f{} -j1 --ignore_numa -w128000 -c64 -l -t -R -W"
    current_avail_cpu = 15

    # sudo cset shield --cpu current_avail_cpu
    # sudo cset shield --kthread on
    # sudo cset set --mem=1 --set=user

    # host_cmd = "taskset --cpu-list {} {}".format(
    #     current_avail_cpu, cmd.format(ITERATIONS, HOST_OUTPUT_FILE))
    shield_cmd = "cset set -c 0 -s system && cset set myset --cpu={}"
    host_cmd = "cset proc -s myset --exec {}".format(cmd.format(ITERATIONS, HOST_OUTPUT_FILE))

    run_cmd(shield_cmd.format(current_avail_cpu))
    print(run_cmd(host_cmd))

    # run_cmd("cset set --destroy myset")

    guest_cmd = "cset proc -s myset --exec {}".format(cmd.format(ITERATIONS, GUEST_OUTPUT_FILE))

    status, stdout, stderr = conn.execute_command(shield_cmd.format(1) + " && cset proc -m -f root -t system && cset proc -k -f root -t system")
    # print(stdout.read())
    # print(stderr.read())


    status, stdout, stderr = conn.execute_command(guest_cmd)
    print(stdout.read())
    # print(stderr.read())

    # assert status == 0
    # _, stdout, stderr = conn.execute_command("ntpd -gq")
    # print(stdout.read())
    # print(stderr.read())

    # _, stdout, stderr = conn.execute_command("service ntp start")
    # print(stdout.read())
    # print(stderr.read())

    _, stdout, _ = conn.execute_command("cat " + GUEST_OUTPUT_FILE)
    guest_csv = stdout.read()
    run_cmd("echo \"" + guest_csv + "\" > " + GUEST_OUTPUT_FILE)

    host_data = get_measurements(HOST_OUTPUT_FILE)
    guest_data = get_measurements(GUEST_OUTPUT_FILE)

    print("HOST: " + str(host_data))

    print("GUEST: " + str(guest_data))

    host_read_tput = float(host_data[0])
    guest_read_tput = float(guest_data[0])
    host_write_tput = float(host_data[1])
    guest_write_tput = float(guest_data[1])
    host_lat = float(host_data[2])
    guest_lat = float(guest_data[2])

    assert (host_read_tput - guest_read_tput) > 0
    print("Read tput difference % (must be positive): " +
          str(((host_read_tput - guest_read_tput) * 100) / host_read_tput))

    assert (host_write_tput - guest_write_tput) > 0
    print("Write tput difference % (must be positive): " +
          str(((host_write_tput - guest_write_tput) * 100) / host_write_tput))

    assert (guest_lat - host_lat) > 0
    print("Latency difference (must be positive): " +
          str(guest_lat - host_lat))

    # print(stdout.read())

    # xmem -n 2 -foutput.txt -j2 --ignore_numa -w16 -c64 -l -t -R

    # Start running the commands on guest, gather results and verify pass
    # criteria.

    basevm.kill()
