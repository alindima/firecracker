# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Configuration file for the VSOCK throughput test."""

DEBUG = False

IPERF3 = "iperf3-vsock"
THROUGHPUT = "throughput"
THROUGHPUT_TOTAL = "total"
DURATION = "duration"
DURATION_TOTAL = "total"
RETRANSMITS = "retransmits"
RETRANSMITS_TOTAL = "total"
CPU_UTILIZATION_HOST = "cpu_utilization_host"
CPU_UTILIZATION_GUEST = "cpu_utilization_guest"
BASE_PORT = 5201
CPU_UTILIZATION_VMM_TAG = "vmm"
CPU_UTILIZATION_VCPUS_TOTAL_TAG = "vcpus_total"
IPERF3_CPU_UTILIZATION_PERCENT_OUT_TAG = "cpu_utilization_percent"
IPERF3_END_RESULTS_TAG = "end"
DEBUG_CPU_UTILIZATION_VMM_SAMPLES_TAG = "cpu_utilization_vmm_samples"

CONFIG = {
    "time": 20,  # seconds
    "load_factor": 1,
    "modes": {
        "g2h": [""],
        "h2g": ["-R"],
        "bd": ["", "-R"]
    },
    "protocols": [
        {
            "name": "tcp",
            "omit": 3,
            "payload_length": ["1024K",  None],
        }
    ],
    "hosts": {
        "instances": {
            "m5d.metal": {
                "cpus": [
                    {
                        # m5zn
                        "model": "Intel(R) Xeon(R) Platinum 8252C CPU @ 3.80GHz",
                    },
                    {
                        # m5d
                        "model": "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
                    },
                    {
                        # m5d
                        "model": "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
                    }
                ]
            }
        }
    }
}
