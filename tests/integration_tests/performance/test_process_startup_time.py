# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test that the process startup time up to socket bind is within spec."""

import json
import os
import platform
import time
import framework.utils as utils

import host_tools.logging as log_tools

MAX_STARTUP_TIME_CPU_US = {'x86_64': 5500, 'aarch64': 2600}
""" The maximum acceptable startup time in CPU us. """
# TODO: Keep a `current` startup time in S3 and validate we don't regress


def test_startup_time(test_microvm_with_api):
    """Check the startup time for jailer and Firecracker up to socket bind."""
    microvm = test_microvm_with_api
    microvm.spawn()

    microvm.basic_config(vcpu_count=2, mem_size_mib=1024)

    # Configure metrics.
    metrics_fifo_path = os.path.join(microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)

    response = microvm.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start()
    time.sleep(0.4)

    # The metrics fifo should be at index 1.
    # Since metrics are flushed at InstanceStart, the first line will suffice.
    lines = metrics_fifo.sequential_reader(1)
    metrics = json.loads(lines[0])
    startup_time_us = metrics['api_server']['process_startup_time_us']
    cpu_startup_time_us = metrics['api_server']['process_startup_time_cpu_us']

    print('Process startup time is: {} us ({} CPU us)'
          .format(startup_time_us, cpu_startup_time_us))

    assert cpu_startup_time_us > 0
    assert cpu_startup_time_us <= MAX_STARTUP_TIME_CPU_US[platform.machine()]


def _custom_filter_setup(test_microvm):
    bpf_path = os.path.join(test_microvm.path, 'bpf.out')

    cargo_target = '{}-unknown-linux-musl'.format(platform.machine())
    json_path = '../resources/seccomp/{}.json'.format(cargo_target)

    cmd = 'cargo run -p seccomp --target {} -- --input-file {} --target-arch\
        {} --output-file {}'.format(cargo_target, json_path,
                                    platform.machine(), bpf_path)

    utils.run_cmd(cmd)

    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": 'bpf.out'})


def test_startup_time_custom_seccomp(test_microvm_with_api):
    """
    Check the startup time for jailer and Firecracker up to socket bind,
    when using custom seccomp filters via the `--seccomp-filter` param.
    """

    microvm = test_microvm_with_api

    _custom_filter_setup(microvm)

    microvm.spawn()

    microvm.basic_config(vcpu_count=2, mem_size_mib=1024)

    # Configure metrics.
    metrics_fifo_path = os.path.join(microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)

    response = microvm.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start()
    time.sleep(0.4)

    # The metrics fifo should be at index 1.
    # Since metrics are flushed at InstanceStart, the first line will suffice.
    lines = metrics_fifo.sequential_reader(1)
    metrics = json.loads(lines[0])
    startup_time_us = metrics['api_server']['process_startup_time_us']
    cpu_startup_time_us = metrics['api_server']['process_startup_time_cpu_us']

    print('Process startup time is: {} us ({} CPU us)'
          .format(startup_time_us, cpu_startup_time_us))

    assert cpu_startup_time_us > 0
    assert cpu_startup_time_us <= MAX_STARTUP_TIME_CPU_US[platform.machine()]
