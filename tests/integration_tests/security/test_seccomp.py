# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the seccomp filters don't let forbidden syscalls through."""

import os
import tempfile
import platform

import framework.utils as utils


def _get_basic_syscall_list():
    """Return the list of syscalls that the demo jailer needs."""
    if platform.machine() == "x86_64":
        return """[
            "SYS_rt_sigprocmask",
            "SYS_rt_sigaction",
            "SYS_execve",
            "SYS_mmap",
            "SYS_arch_prctl",
            "SYS_set_tid_address",
            "SYS_readlink",
            "SYS_open",
            "SYS_read",
            "SYS_close",
            "SYS_brk",
            "SYS_sched_getaffinity",
            "SYS_sigaltstack",
            "SYS_munmap",
            "SYS_exit_group"
        ]"""

    # platform.machine() == "aarch64"
    return """[
        "SYS_rt_sigprocmask",
        "SYS_rt_sigaction",
        "SYS_execve",
        "SYS_mmap",
        "SYS_set_tid_address",
        "SYS_read",
        "SYS_close",
        "SYS_brk",
        "SYS_sched_getaffinity",
        "SYS_sigaltstack",
        "SYS_munmap",
        "SYS_exit_group"
    ]"""


def _run_seccompiler(json_data):
    json_temp = tempfile.NamedTemporaryFile(delete=False)
    json_temp.write(json_data.encode('utf-8'))
    json_temp.flush()

    bpf_temp = tempfile.NamedTemporaryFile(delete=False)

    cargo_target = '{}-unknown-linux-musl'.format(platform.machine())
    cmd = 'cargo run -p seccomp --target {} -- --input-file {} --target-arch\
        {} --output-file {}'.format(cargo_target, json_temp.name,
                                    platform.machine(), bpf_temp.name)
    utils.run_cmd(cmd)

    os.unlink(json_temp.name)
    return bpf_temp.name


def test_seccomp_ls(bin_seccomp_paths):
    """Assert that the seccomp filter denies an unallowed syscall."""
    # pylint: disable=redefined-outer-name
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    # Path to the `ls` binary, which attempts to execute the forbidden
    # `SYS_access`.
    ls_command_path = '/bin/ls'
    demo_jailer = bin_seccomp_paths['demo_jailer']
    assert os.path.exists(demo_jailer)

    json_filter = """{{
        "main": {{
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [
                {{
                    "syscalls": {}
                }}
            ]
        }}
    }}""".format(_get_basic_syscall_list())

    # Run seccompiler.
    bpf_path = _run_seccompiler(json_filter)

    # Run the mini jailer.
    outcome = utils.run_cmd([demo_jailer, ls_command_path, bpf_path],
                            no_shell=True,
                            ignore_return_code=True)

    os.unlink(bpf_path)

    # The seccomp filters should send SIGSYS (31) to the binary. `ls` doesn't
    # handle it, so it will exit with error.
    assert outcome.returncode != 0


def test_advanced_seccomp(bin_seccomp_paths):
    """
    Test `demo_harmless`.

    Test that the demo jailer (with advanced seccomp) allows the harmless demo
    binary and denies the malicious demo binary.
    """
    # pylint: disable=redefined-outer-name
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    demo_jailer = bin_seccomp_paths['demo_jailer']
    demo_harmless = bin_seccomp_paths['demo_harmless']
    demo_malicious = bin_seccomp_paths['demo_malicious']

    assert os.path.exists(demo_jailer)
    assert os.path.exists(demo_harmless)
    assert os.path.exists(demo_malicious)

    json_filter = """{{
        "main": {{
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [
                {{
                    "syscalls": {}
                }},
                {{
                    "syscall": "SYS_write",
                    "args": [
                        {{
                            "arg_index": 0,
                            "arg_type": "dword",
                            "op": "eq",
                            "val": 1,
                            "comment": "stdout fd"
                        }},
                        {{
                            "arg_index": 2,
                            "arg_type": "qword",
                            "op": "eq",
                            "val": 14,
                            "comment": "nr of bytes"
                        }}
                    ]
                }}
            ]
        }}
    }}""".format(_get_basic_syscall_list())

    # Run seccompiler.
    bpf_path = _run_seccompiler(json_filter)

    # Run the mini jailer for harmless binary.
    outcome = utils.run_cmd([demo_jailer, demo_harmless, bpf_path],
                            no_shell=True,
                            ignore_return_code=True)

    # The demo harmless binary should have terminated gracefully.
    assert outcome.returncode == 0

    # Run the mini jailer for malicious binary.
    outcome = utils.run_cmd([demo_jailer, demo_malicious, bpf_path],
                            no_shell=True,
                            ignore_return_code=True)

    # The demo malicious binary should have received `SIGSYS`.
    assert outcome.returncode == -31

    os.unlink(bpf_path)


def test_seccomp_applies_to_all_threads(test_microvm_with_api):
    """Test all Firecracker threads get default seccomp level 2."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    test_microvm.start()

    # Get Firecracker PID so we can count the number of threads.
    firecracker_pid = test_microvm.jailer_clone_pid

    utils.assert_seccomp_level(firecracker_pid, "2")


def test_no_seccomp(test_microvm_with_api):
    """Test Firecracker --no-seccomp."""
    test_microvm = test_microvm_with_api
    test_microvm.jailer.extra_args.update({"no-seccomp": None})
    test_microvm.spawn()

    test_microvm.basic_config()

    test_microvm.start()

    utils.assert_seccomp_level(test_microvm.jailer_clone_pid, "0")
