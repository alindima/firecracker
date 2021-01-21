# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Implement the DataParser for network tcp throughput test."""

import json
import statistics
import math
from collections import defaultdict, Iterator
from typing import List

from providers.types import DataParser


def nesteddict():
    """Create an infinitely nested dictionary."""
    return defaultdict(nesteddict)


# pylint: disable=R0903
class NetworkTcpDataParser(DataParser):
    """Parse the data provided by the network tcp performance test."""

    # pylint: disable=W0102
    def __init__(self, data_provider: Iterator):
        """Initialize the network data parser."""
        self._data_provider = iter(data_provider)
        self._baselines_defs = [
            "throughput/total",
            "cpu_utilization_vcpus_total/value",
            "cpu_utilization_vmm/value",
        ]
        # This object will hold the parsed data.
        self._data = nesteddict()

    # pylint: disable=R0201
    def _calculate_baseline(self, data: List[float]) -> dict:
        """Return the target and delta values, given a list of data points."""
        avg = statistics.mean(data)
        stddev = statistics.stdev(data)
        return {
            'target': math.ceil(round(avg, 2)),
            # We add a 3% extra margin, to account for small variations that
            # were not caught while gathering baselines. This provides
            # slightly better reliability, while not affecting regression
            # detection.
            'delta_percentage': math.ceil(round(3 * stddev/avg * 100, 2)) + 3
        }

    def _format_baselines(self) -> List[dict]:
        """Return the computed baselines into the right serializable format."""
        baselines = dict()

        for cpu_model in self._data:
            baselines[cpu_model] = {
                'model': cpu_model, **self._data[cpu_model]}

        temp_baselines = baselines
        baselines = []

        for cpu_model in self._data:
            baselines.append(temp_baselines[cpu_model])

        return baselines

    def parse(self) -> dict:
        """Parse the rows based on proposed baselines."""
        line = next(self._data_provider)
        while line:
            json_line = json.loads(line)
            measurements = json_line['results']
            cpu_model = json_line['custom']['cpu_model']

            # Consume the data and aggregate into lists.
            for tag in measurements.keys():
                for key in self._baselines_defs:
                    [ms_name, st_name] = key.split("/")
                    ms_data = measurements[tag].get(ms_name)

                    st_data = ms_data.get(st_name)

                    [kernel_version, rootfs_type,
                        iperf_config] = tag.split("/")

                    data = self._data[cpu_model][ms_name]
                    data = data[kernel_version][rootfs_type]
                    if isinstance(data[iperf_config], list):
                        data[iperf_config].append(st_data)
                    else:
                        data[iperf_config] = [st_data]
            line = next(self._data_provider)

        # Compute the baselines.
        for cpu_model in self._data:
            for baseline in self._data[cpu_model]:
                data = self._data[cpu_model]
                for kernel in data[baseline]:
                    data = self._data[cpu_model][baseline]
                    for rootfs in data[kernel]:
                        data = self._data[cpu_model][baseline][kernel]
                        for iperf_config in \
                                data[rootfs]:
                            data[rootfs][iperf_config] = \
                                self._calculate_baseline(
                                    data[rootfs][iperf_config])

        return self._format_baselines()
