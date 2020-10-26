# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the --seccomp-filter parameter works as expected."""

import os
import platform
import tempfile
import time
import psutil
import pytest
import framework.utils as utils


def _assert_seccomp_level(firecracker_pid, seccomp_level):
    # Get number of threads in Firecracker
    cmd = 'ps -T --no-headers -p {} | awk \'{{print $2}}\''.format(
        firecracker_pid
    )
    process = utils.run_cmd(cmd)
    threads_out_lines = process.stdout.splitlines()
    for tid in threads_out_lines:
        # Verify each Firecracker thread Seccomp status
        cmd = 'cat /proc/{}/status | grep Seccomp'.format(tid)
        process = utils.run_cmd(cmd)
        seccomp_line = ''.join(process.stdout.split())
        assert seccomp_line == "Seccomp:" + seccomp_level


def _custom_filter_setup(test_microvm, json_filter):
    json_temp = tempfile.NamedTemporaryFile(delete=False)
    json_temp.write(json_filter)
    json_temp.flush()

    bpf_path = os.path.join(test_microvm.path, 'bpf.out')

    cargo_target = '{}-unknown-linux-musl'.format(platform.machine())
    cmd = 'cargo run -p seccomp --target {} -- --input_file {} --target_arch\
        {} --output_file {}'.format(cargo_target, json_temp.name,
                                    platform.machine(), bpf_path)
    utils.run_cmd(cmd)

    os.unlink(json_temp.name)
    test_microvm.create_jailed_resource(bpf_path)
    test_microvm.jailer.extra_args.update({"seccomp-filter": 'bpf.out'})


def test_allow_all(test_microvm_with_api):
    """Test --seccomp-filter, allowing all syscalls."""
    test_microvm = test_microvm_with_api

    _custom_filter_setup(test_microvm, b'{\
        "Vmm": {\
            "default_action": "Allow",\
            "filter_action": "Trap",\
            "filter": []\
        },\
        "Api": {\
            "default_action": "Allow",\
            "filter_action": "Trap",\
            "filter": []\
        },\
        "Vcpu": {\
            "default_action": "Allow",\
            "filter_action": "Trap",\
            "filter": []\
        }\
    }')

    test_microvm.jailer.extra_args.update({"seccomp-filter": 'bpf.out'})
    test_microvm.spawn()

    test_microvm.basic_config()

    test_microvm.start()

    # because Firecracker receives empty filters, the seccomp-level will
    # remain 0
    _assert_seccomp_level(test_microvm.jailer_clone_pid, "0")


def test_working_filter(test_microvm_with_api):
    """Test --seccomp-filter, rejecting some dangerous syscalls."""
    test_microvm = test_microvm_with_api

    _custom_filter_setup(test_microvm, b'{\
        "Vmm": {\
            "default_action": "Allow",\
            "filter_action": "Kill",\
            "filter": [\
                {\
                    "syscalls": ["SYS_clone", "SYS_execve"]\
                }\
            ]\
        },\
        "Api": {\
            "default_action": "Allow",\
            "filter_action": "Kill",\
            "filter": [\
                {\
                    "syscalls": ["SYS_clone", "SYS_execve"]\
                }\
            ]\
        },\
        "Vcpu": {\
            "default_action": "Allow",\
            "filter_action": "Kill",\
            "filter": [\
                {\
                    "syscalls": ["SYS_clone", "SYS_execve"]\
                }\
            ]\
        }\
    }')

    test_microvm.spawn()

    test_microvm.basic_config()

    test_microvm.start()

    # seccomp-level should be 2, with no additional errors
    _assert_seccomp_level(test_microvm.jailer_clone_pid, "2")


@pytest.mark.parametrize(
    "vm_config_file",
    ["framework/vm_config.json"]
)
def test_failing_filter(test_microvm_with_ssh, vm_config_file):
    """Test --seccomp-filter, denying some needed syscalls."""
    test_microvm = test_microvm_with_ssh

    # Configure VM from JSON. This way, we can check that the process was
    # killed after InstanceStart. Otherwise, the API call would time out.

    test_microvm.create_jailed_resource(test_microvm.kernel_file,
                                        create_jail=True)
    test_microvm.create_jailed_resource(test_microvm.rootfs_file,
                                        create_jail=True)

    vm_config_path = os.path.join(test_microvm.path,
                                  os.path.basename(vm_config_file))
    with open(vm_config_file) as f1:
        with open(vm_config_path, "w") as f2:
            for line in f1:
                f2.write(line)
    test_microvm.create_jailed_resource(vm_config_path, create_jail=True)
    test_microvm.jailer.extra_args = {'config-file': os.path.basename(
        vm_config_file)}

    test_microvm.jailer.extra_args.update({'no-api': None})

    _custom_filter_setup(test_microvm, b'{\
        "Vmm": {\
            "default_action": "Kill",\
            "filter_action": "Allow",\
            "filter": [\
                {\
                    "syscalls": ["SYS_read"]\
                }\
            ]\
        },\
        "Api": {\
            "default_action": "Kill",\
            "filter_action": "Allow",\
            "filter": [\
                {\
                    "syscalls": ["SYS_read"]\
                }\
            ]\
        },\
        "Vcpu": {\
            "default_action": "Kill",\
            "filter_action": "Allow",\
            "filter": [\
                {\
                    "syscalls": ["SYS_read"]\
                }\
            ]\
        }\
    }')

    test_microvm.spawn()

    # give time for the process to get killed
    time.sleep(1)

    # assert that the process was killed
    assert not psutil.pid_exists(test_microvm.jailer_clone_pid)
