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
import tempfile

ITERATIONS = 3
WORKING_SET_SIZE_TPUT = 10485760  # 10 GB


def measurements_throughput():
    """Define the produced measurements for the memory throughput."""
    return [types.MeasurementDef("ThroughputDifference", "%"),
            types.MeasurementDef("HostThroughput", "MB/s"),
            types.MeasurementDef("GuestThroughput", "MB/s")
            ]


def stats_throughput():
    return [types.StatisticDef("overhead", "ThroughputDifference", function.Identity),
            types.StatisticDef("host", "HostThroughput", function.Identity),
            types.StatisticDef("guest", "GuestThroughput", function.Identity)
            ]


def produce_xmem_output(xmem_cmd_builder, basevm, current_avail_cpu, xmem_threads_count):
    host_data = run_xmem_host(
        xmem_cmd_builder, current_avail_cpu, xmem_threads_count)
    guest_data = run_xmem_guest(xmem_cmd_builder, basevm, xmem_threads_count)

    return {"host": host_data, "guest": guest_data}


def run_xmem_host(xmem_cmd_builder, current_avail_cpu, xmem_threads_count):
    host_csv_file = tempfile.NamedTemporaryFile(delete=False)
    xmem_cmd_builder.with_arg("-f", host_csv_file.name)

    # status, _, _ = run_cmd(
    #     f"taskset --cpu-list {current_avail_cpu + 1}-{current_avail_cpu + xmem_threads_count} {xmem_cmd_builder.build()}")

    status, _, _ = run_cmd(
        xmem_cmd_builder.build())

    assert status == 0

    with open(host_csv_file.name) as file:
        host_data = csv.DictReader(file.read().splitlines())

    os.unlink(host_csv_file.name)

    return host_data


def run_xmem_guest(xmem_cmd_builder, basevm, xmem_threads_count):
    conn = net_tools.SSHConnection(basevm.ssh_config)
    vm_csv_path = "xmem.csv"

    xmem_cmd_builder.with_arg("-f", vm_csv_path)

    # status, _, _ = conn.execute_command(
    #     f"taskset --cpu-list 0-{xmem_threads_count - 1} {xmem_cmd_builder.build()}")

    shield_cmd = f"cset shield --cpu 1-{xmem_threads_count} && cset shield --kthread on && cset set --mem=1 --set=user"

    status, stdout, stderr = conn.execute_command(shield_cmd)

    # print(stdout.read())
    # print(stderr.read())

    cmd = f"cset shield --exec xmem -- {xmem_cmd_builder.build()[5:]}"
    status, stdout, stderr = conn.execute_command(cmd)

    # print(stdout.read())
    # print(stderr.read())

    # status, _, _ = conn.execute_command(
    #     xmem_cmd_builder.build())

    assert status == 0

    status, stdout, _ = conn.execute_command("cat " + vm_csv_path)
    assert status == 0

    return csv.DictReader(stdout.read().splitlines())


def consume_xmem_output(cons, result):

    for line in result["host"]:
        host_tput = float(line["99th Percentile Load Throughput"])

    for line in result["guest"]:
        guest_tput = float(line["99th Percentile Load Throughput"])

    # host should always perform better
    assert (host_tput - guest_tput) > 0

    difference_percentage = ((host_tput - guest_tput) * 100) / host_tput

    cons.consume_stat("host", "HostThroughput",
                      host_tput)
    cons.consume_stat("guest", "GuestThroughput",
                      guest_tput)
    cons.consume_stat("overhead", "ThroughputDifference",
                      difference_percentage)


@ pytest.mark.nonci
@ pytest.mark.timeout(6000)
def test_memory_performance(bin_cloner_path):
    """Test memory performance driver for multiple artifacts."""
    logger = logging.getLogger("memory")
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_11gb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="3vcpu_11gb"))
    kernel_artifacts = ArtifactSet(
        artifacts.kernels(keyword="4.14"))

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

    # add loop for all combinations
    # -t -l by default
    # -R, -W, 1vcpu, 2vcpu,
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

    st_core = core.Core(name="memory_throughput",
                        iterations=1)

    # Check if the needed CPU cores are available. We have the API thread, VMM
    # thread and then one thread for each configured vCPU.
    assert CpuMap.len() >= 2 + basevm.vcpus_count

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

    num_threads = basevm.vcpus_count - 1
    assert num_threads > 0
    modes = ["--reads", "--writes"]
    chunks = ["64"]
    access_patterns = ["--random_access"]

    # chunks = ["64"]
    # modes = ["--reads"]
    # access_patterns = ["--sequential_access"]

    working_set_size = int(WORKING_SET_SIZE_TPUT / num_threads)

    for mode in modes:
        for chunk in chunks:
            for pattern in access_patterns:
                xmem_cmd_builder = CmdBuilder("xmem") \
                    .with_arg("-t") \
                    .with_arg("--ignore_numa") \
                    .with_arg("-n", ITERATIONS) \
                    .with_arg("-j", num_threads) \
                    .with_arg("-w", working_set_size) \
                    .with_arg("-c", chunk) \
                    .with_arg(pattern) \
                    .with_arg(mode)

                cons = consumer.LambdaConsumer(
                    consume_stats=True,
                    func=consume_xmem_output
                )

                tag = f"{context.microvm.name()}/{context.kernel.name()}/{context.disk.name()}"
                tag += f"/{mode[2:]}-c{chunk}-{pattern[2:]}"

                eager_map(cons.set_measurement_def,
                          measurements_throughput())

                eager_map(cons.set_stat_def, stats_throughput())

                prod_kwargs = {
                    "xmem_cmd_builder": xmem_cmd_builder,
                    "basevm": basevm,
                    "current_avail_cpu": current_avail_cpu,
                    "xmem_threads_count": num_threads,
                }

                prod = producer.LambdaProducer(produce_xmem_output,
                                               prod_kwargs)

                st_core.add_pipe(prod, cons, tag)

    print(st_core.run_exercise())

    basevm.kill()
