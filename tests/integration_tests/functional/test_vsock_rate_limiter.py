# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that fail if network throughput does not obey rate limits."""
import time
import os
import json

import framework.utils as utils
from framework.utils import CmdBuilder, run_cmd
import host_tools.network as net_tools  # pylint: disable=import-error

# The iperf version to run this tests with
IPERF_BINARY = 'iperf3-vsock'

BASE_PORT = 5201

VSOCK_UDS_PATH = "v.sock"

# Interval used by iperf to get maximum bandwidth
IPERF_TRANSMIT_TIME = 4

# The rate limiting value
RATE_LIMIT_BYTES = 10485760

# The initial token bucket size
BURST_SIZE = 104857600

# The refill time for the token bucket
REFILL_TIME_MS = 100

# Deltas that are accepted between expected values and achieved
# values throughout the tests
MAX_BYTES_DIFF_PERCENTAGE = 10
MAX_TIME_DIFF = 25


def _make_host_port_path(uds_path, port):
    """Build the path for a Unix socket, mapped to host vsock port `port`."""
    return "{}_{}".format(uds_path, port)


def test_tx_rate_limiting(test_microvm_with_ssh, network_config):
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    test_microvm.basic_config()

    _tap, _, _ = test_microvm.ssh_network_config(
        network_config,
        '1'
    )

    test_microvm.vsock.put(
        vsock_id="vsock0",
        guest_cid=3,
        uds_path="/" + VSOCK_UDS_PATH,
        tx_rate_limiter={
            'bandwidth': {
                'size': 65536 * 3,
                'refill_time': 1
            }
        }
    )

    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    host_uds_path = os.path.join(
        test_microvm.path,
        VSOCK_UDS_PATH
    )

    ssh_connection.scp_file("/usr/local/bin/iperf3-vsock",
                            "/usr/local/bin/iperf3-vsock")

    iperf_server = \
        CmdBuilder(IPERF_BINARY) \
        .with_arg("-sD") \
        .with_arg("--vsock") \
        .with_arg("-B", host_uds_path) \
        .with_arg("-p", BASE_PORT) \
        .with_arg("-1") \
        .build()

    run_cmd(iperf_server)

    time.sleep(2)

    # Bind the UDS in the jailer's root.
    test_microvm.create_jailed_resource(os.path.join(
        test_microvm.path,
        _make_host_port_path(VSOCK_UDS_PATH, BASE_PORT)))

    iperf_guest_command = CmdBuilder(IPERF_BINARY) \
        .with_arg("--vsock") \
        .with_arg("-c", 2)       \
        .with_arg("--json") \
        .with_arg("--omit", 2) \
        .with_arg("--time", 10).with_arg("-p", BASE_PORT).build()

    rc, stdout, _stderr = ssh_connection.execute_command(iperf_guest_command)

    # assert rc == 0

    print(_stderr.read())
    print(stdout.read())

    print(test_microvm.log_data)

    # print(_process_iperf_output(stdout.read()))

    # # For this test we will be adding three interfaces:
    # # 1. No rate limiting
    # # 2. Rate limiting without burst
    # # 3. Rate limiting with burst
    # host_ips = ['', '', '']
    # guest_ips = ['', '', '']

    # iface_id = '1'
    # # Create tap before configuring interface.
    # _tap1, host_ip, guest_ip = test_microvm.ssh_network_config(
    #     network_config,
    #     iface_id
    # )
    # guest_ips[0] = guest_ip
    # host_ips[0] = host_ip

    # iface_id = '2'
    # tx_rate_limiter_no_burst = {
    #     'bandwidth': {
    #         'size': RATE_LIMIT_BYTES,
    #         'refill_time': REFILL_TIME_MS
    #     }
    # }
    # _tap2, host_ip, guest_ip = test_microvm.ssh_network_config(
    #     network_config,
    #     iface_id,
    #     tx_rate_limiter=tx_rate_limiter_no_burst
    # )
    # guest_ips[1] = guest_ip
    # host_ips[1] = host_ip

    # iface_id = '3'
    # tx_rate_limiter_with_burst = {
    #     'bandwidth': {
    #         'size': RATE_LIMIT_BYTES,
    #         'one_time_burst': BURST_SIZE,
    #         'refill_time': REFILL_TIME_MS
    #     }
    # }
    # _tap3, host_ip, guest_ip = test_microvm.ssh_network_config(
    #     network_config,
    #     iface_id,
    #     tx_rate_limiter=tx_rate_limiter_with_burst
    # )
    # guest_ips[2] = guest_ip
    # host_ips[2] = host_ip

    # test_microvm.start()

    # _check_tx_rate_limiting(test_microvm, guest_ips, host_ips)


# def test_rx_rate_limiting_cpu_load(test_microvm_with_ssh, network_config):
#     """Run iperf rx with rate limiting; verify cpu load is below threshold."""
#     test_microvm = test_microvm_with_ssh
#     test_microvm.spawn()

#     test_microvm.basic_config()

#     # Enable monitor that checks if the cpu load is over the threshold.
#     # After multiple runs, the average value for the cpu load
#     # seems to be around 10%. Setting the threshold a little
#     # higher to skip false positives.
#     threshold = 20
#     test_microvm.enable_cpu_load_monitor(threshold)

#     # Create interface with aggressive rate limiting enabled.
#     rx_rate_limiter_no_burst = {
#         'bandwidth': {
#             'size': 65536,  # 64KBytes
#             'refill_time': 1000  # 1s
#         }
#     }
#     _tap, _host_ip, guest_ip = test_microvm.ssh_network_config(
#         network_config,
#         '1',
#         rx_rate_limiter=rx_rate_limiter_no_burst
#     )

#     test_microvm.start()

#     # Start iperf server on guest.
#     _start_iperf_on_guest(test_microvm, guest_ip)

#     # Run iperf client sending UDP traffic.
#     iperf_cmd = '{} {} -u -c {} -b 1000000000 -t{} -f KBytes'.format(
#         test_microvm.jailer.netns_cmd_prefix(),
#         IPERF_BINARY,
#         guest_ip,
#         IPERF_TRANSMIT_TIME * 5
#     )
#     _iperf_out = _run_local_iperf(iperf_cmd)


# def _check_tx_rate_limiting(test_microvm, guest_ips, host_ips):
#     """Check that the transmit rate is within expectations."""
#     # Start iperf on the host as this is the tx rate limiting test.
#     _start_local_iperf(test_microvm.jailer.netns_cmd_prefix())

#     # First step: get the transfer rate when no rate limiting is enabled.
#     # We are receiving the result in KBytes from iperf.
#     print("Run guest TX iperf with no rate-limit")
#     rate_no_limit_kbps = _get_tx_bandwidth_with_duration(
#         test_microvm,
#         guest_ips[0],
#         host_ips[0],
#         IPERF_TRANSMIT_TIME
#     )
#     print("TX rate_no_limit_kbps: {}".format(rate_no_limit_kbps))

#     # Calculate the number of bytes that are expected to be sent
#     # in each second once the rate limiting is enabled.
#     expected_kbps = int(RATE_LIMIT_BYTES / (REFILL_TIME_MS / 1000.0) / 1024)
#     print("Rate-Limit TX expected_kbps: {}".format(expected_kbps))

#     # Sanity check that bandwidth with no rate limiting is at least double
#     # than the one expected when rate limiting is in place.
#     assert _get_percentage_difference(rate_no_limit_kbps, expected_kbps) > 100

#     # Second step: check bandwidth when rate limiting is on.
#     _check_tx_bandwidth(test_microvm, guest_ips[1], host_ips[1], expected_kbps)

#     # Third step: get the number of bytes when rate limiting is on and there is
#     # an initial burst size from where to consume.
#     print("Run guest TX iperf with exact burst size")
#     # Use iperf to obtain the bandwidth when there is burst to consume from,
#     # send exactly BURST_SIZE packets.
#     iperf_cmd = '{} -c {} -n {} -f KBytes -w {} -N'.format(
#         IPERF_BINARY,
#         host_ips[2],
#         BURST_SIZE,
#         IPERF_TCP_WINDOW
#     )
#     iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, guest_ips[2])
#     print(iperf_out)
#     _, burst_kbps = _process_iperf_output(iperf_out)
#     print("TX burst_kbps: {}".format(burst_kbps))
#     # Test that the burst bandwidth is at least as two times the rate limit.
#     assert _get_percentage_difference(burst_kbps, expected_kbps) > 100

#     # Since the burst should be consumed, check rate limit is in place.
#     _check_tx_bandwidth(test_microvm, guest_ips[2], host_ips[2], expected_kbps)


# def _check_tx_bandwidth(
#         test_microvm,
#         guest_ip,
#         host_ip,
#         expected_kbps
# ):
#     """Check that the rate-limited TX bandwidth is close to what we expect.

#     At this point, a daemonized iperf3 server is expected to be running on
#     the host.
#     """
#     print("Check guest TX rate-limit; expected kbps {}".format(expected_kbps))
#     observed_kbps = _get_tx_bandwidth_with_duration(
#         test_microvm,
#         guest_ip,
#         host_ip,
#         IPERF_TRANSMIT_TIME
#     )

#     diff_pc = _get_percentage_difference(observed_kbps, expected_kbps)
#     print("TX calculated diff percentage: {}\n".format(diff_pc))

#     if diff_pc >= MAX_BYTES_DIFF_PERCENTAGE:
#         print("Short duration test failed. Try another run with 10x duration.")

#         observed_kbps = _get_tx_bandwidth_with_duration(
#             test_microvm,
#             guest_ip,
#             host_ip,
#             10 * IPERF_TRANSMIT_TIME
#         )
#         diff_pc = _get_percentage_difference(observed_kbps, expected_kbps)
#         print("TX calculated diff percentage: {}\n".format(diff_pc))

#         assert diff_pc < MAX_BYTES_DIFF_PERCENTAGE


# def _get_tx_bandwidth_with_duration(
#         test_microvm,
#         guest_ip,
#         host_ip,
#         duration
# ):
#     """Check that the rate-limited TX bandwidth is close to what we expect."""
#     iperf_cmd = '{} -c {} -t {} -f KBytes -w {} -N'.format(
#         IPERF_BINARY,
#         host_ip,
#         duration,
#         IPERF_TCP_WINDOW
#     )

#     iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, guest_ip)
#     print(iperf_out)

#     _, observed_kbps = _process_iperf_output(iperf_out)
#     print("TX observed_kbps: {}".format(observed_kbps))
#     return observed_kbps


# def _start_iperf_on_guest(test_microvm, hostname):
#     """Start iperf in server mode through an SSH connection."""
#     test_microvm.ssh_config['hostname'] = hostname
#     ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

#     iperf_cmd = '{} -sD -f KBytes\n'.format(IPERF_BINARY)
#     ssh_connection.execute_command(iperf_cmd)

#     # Wait for the iperf daemon to start.
#     time.sleep(1)


# def _run_iperf_on_guest(test_microvm, iperf_cmd, hostname):
#     """Run a client related iperf command through an SSH connection."""
#     test_microvm.ssh_config['hostname'] = hostname
#     ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
#     _, stdout, stderr = ssh_connection.execute_command(iperf_cmd)
#     assert stderr.read() == ''

#     out = stdout.read()
#     return out


# def _start_local_iperf(netns_cmd_prefix):
#     """Start iperf in server mode after killing any leftover iperf daemon."""
#     iperf_cmd = 'pkill {}\n'.format(IPERF_BINARY)

#     # Don't check the result of this command because it can fail if no iperf
#     # is running.
#     utils.run_cmd(iperf_cmd, ignore_return_code=True)

#     iperf_cmd = '{} {} -sD -f KBytes\n'.format(netns_cmd_prefix, IPERF_BINARY)

#     utils.run_cmd(iperf_cmd)

#     # Wait for the iperf daemon to start.
#     time.sleep(1)


# def _run_local_iperf(iperf_cmd):
#     """Execute a client related iperf command locally."""
#     process = utils.run_cmd(iperf_cmd)
#     return process.stdout


# def _get_percentage_difference(measured, base):
#     """Return the percentage delta between the arguments."""
#     if measured == base:
#         return 0
#     try:
#         return (abs(measured - base) / base) * 100.0
#     except ZeroDivisionError:
#         # It means base and only base is 0.
#         return 100.0


# def _process_iperf_line(line):
#     """Parse iperf3 summary line and return test time and bandwidth."""
#     test_time = line.split('  ')[2].split('-')[1].strip().split(" ")[0]
#     test_bw = line.split('  ')[5].split(' ')[0].strip()
#     return float(test_time), float(test_bw)


# def _process_iperf_output(iperf_out):
#     """Parse iperf3 output and return average test time and bandwidth."""
#     iperf_out_lines = iperf_out.splitlines()
#     for line in iperf_out_lines:
#         if line.find('sender') != -1:
#             send_time, send_bw = _process_iperf_line(line)
#         if line.find('receiver') != -1:
#             rcv_time, rcv_bw = _process_iperf_line(line)
#     iperf_out_time = (send_time + rcv_time) / 2.0
#     iperf_out_bw = (send_bw + rcv_bw) / 2.0
#     return float(iperf_out_time), float(iperf_out_bw)
