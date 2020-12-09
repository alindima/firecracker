import sys
import json
import statistics
import math


def percentile(results, k):
    length = len(results)
    results.sort()
    idx = length * k // 100
    if idx is not int(idx):
        return (results[idx - 1] + results[idx]) / 2
    return results[idx]


# def print_data(data, kernel):
#     for key in data[kernel]:
#         print(kernel, key, "stddev", statistics.stdev(data[kernel][key]["throughput"]), statistics.stdev(
#             data[kernel][key]["retransmits"]), statistics.stdev(data[kernel][key]["vmm"]), statistics.stdev(data[kernel][key]["vcpus_total"]))
#         print(kernel, key, "avg", statistics.mean(data[kernel][key]["throughput"]), statistics.mean(
#             data[kernel][key]["retransmits"]), statistics.mean(data[kernel][key]["vmm"]), statistics.mean(data[kernel][key]["vcpus_total"]))
#         print(kernel, key, "min", min(data[kernel][key]["throughput"]), min(
#             data[kernel][key]["retransmits"]), min(data[kernel][key]["vmm"]), min(data[kernel][key]["vcpus_total"]))
#         print(kernel, key, "max", max(data[kernel][key]["throughput"]), max(
#             data[kernel][key]["retransmits"]), max(data[kernel][key]["vmm"]), max(data[kernel][key]["vcpus_total"]))
#         print(kernel, key, "p50", percentile(data[kernel][key]["throughput"], 50), percentile(
#             data[kernel][key]["retransmits"], 50), percentile(data[kernel][key]["vmm"], 50), percentile(data[kernel][key]["vcpus_total"], 50))
#         print(kernel, key, "p90", percentile(data[kernel][key]["throughput"], 90), percentile(
#             data[kernel][key]["retransmits"], 90), percentile(data[kernel][key]["vmm"], 90), percentile(data[kernel][key]["vcpus_total"], 90))
#         print(kernel, key, "p95", percentile(data[kernel][key]["throughput"], 95), percentile(
#             data[kernel][key]["retransmits"], 95), percentile(data[kernel][key]["vmm"], 95), percentile(data[kernel][key]["vcpus_total"], 95))
#         print(kernel, key, "p99", percentile(data[kernel][key]["throughput"], 99), percentile(
#             data[kernel][key]["retransmits"], 99), percentile(data[kernel][key]["vmm"], 99), percentile(data[kernel][key]["vcpus_total"], 50))


def construct_imp_data(data, kernel, tag, d):
    for key in data[kernel]:
        new_key = key[(len(tag) + 1):]
        d["baseline_bw"][tag][new_key] = dict()
        bw_avg = statistics.mean(data[kernel][key]["throughput"])
        bw_stddev = statistics.stdev(data[kernel][key]["throughput"])
        d["baseline_bw"][tag][new_key]["target"] = math.ceil(round(bw_avg, 2))
        d["baseline_bw"][tag][new_key]["delta_percentage"] = math.ceil(
            round(3*bw_stddev/bw_avg * 100, 2)) + 3

        d["baseline_cpu_utilization"][tag]["vmm"][new_key] = dict()
        vmm_avg = statistics.mean(data[kernel][key]["vmm"])
        vmm_stddev = statistics.stdev(data[kernel][key]["vmm"])
        d["baseline_cpu_utilization"][tag]["vmm"][new_key]["target"] = math.ceil(
            round(vmm_avg, 2))
        d["baseline_cpu_utilization"][tag]["vmm"][new_key]["delta_percentage"] = math.ceil(
            round(3*vmm_stddev/vmm_avg * 100, 2)) + 3

        d["baseline_cpu_utilization"][tag]["vcpus_total"][new_key] = dict()
        vcpus_avg = statistics.mean(data[kernel][key]["vcpus_total"])
        vcpus_stddev = statistics.stdev(data[kernel][key]["vcpus_total"])
        d["baseline_cpu_utilization"][tag]["vcpus_total"][new_key]["target"] = math.ceil(
            round(vcpus_avg, 2))
        d["baseline_cpu_utilization"][tag]["vcpus_total"][new_key]["delta_percentage"] = math.ceil(
            round(3*vcpus_stddev/vcpus_avg * 100, 2)) + 3

        # print()
        # print()
        # print(d"baseline_cpu_utilization"])
        # print()
        # print()
#		print(kernel, key, "throughput:", th_target, th_delta)
#		print(kernel, key, "vmm:", vmm_target, vmm_delta)
#		print(kernel, key, "vcpus_total:", vcpus_total_target, vcpus_total_delta)
#	print(d)
#	print()


# Parse curated data.
filename = sys.argv[1]
with open(filename) as f:
    line = f.readline()
    line = f.readline()
    iteration = 0
    stepper = 0
    final = dict()
    while line:
        if stepper == 0:
            iteration = iteration + 1
        # print(iteration)
        # print(line)
        parsed = json.loads(line)

        microvm = parsed["custom"]["microvm"]
        kernel = parsed["custom"]["kernel"]
        disk = parsed["custom"]["disk"]

        if kernel not in final:
            final[kernel] = dict()

        if iteration not in final[kernel]:
            final[kernel][iteration] = dict()

        results = parsed["results"]
        for key in results:
            final[kernel][iteration][key] = dict()

            final[kernel][iteration][key]["throughput"] = results[key]["throughput"]["total"]
            final[kernel][iteration][key]["vmm"] = results[key]["cpu_utilization_host"]["vmm"]
            final[kernel][iteration][key]["vcpus_total"] = results[key]["cpu_utilization_guest"]["vcpus_total"]
            # print(kernel, iteration, key, final[kernel][iteration][key]["throughput"], final[kernel][iteration][key]["retransmits"], final[kernel][iteration][key]["vmm"], final[kernel][iteration][key]["vcpus_total"])
        stepper = (stepper + 1) % 2
        line = f.readline()
        line = f.readline()
#		print(microvm, kernel, disk)

# print(json.dumps(final, indent=4))

# Print statistics
data = dict()
d = dict()
d["baseline_bw"] = dict()
d["baseline_cpu_utilization"] = dict()
disk = "ubuntu-18.04.ext4"

for kernel in final:
    data[kernel] = dict()
    tag = f"{kernel}/{disk}"
    d["baseline_bw"][tag] = dict()
    d["baseline_cpu_utilization"][tag] = dict()
    d["baseline_cpu_utilization"][tag]["vmm"] = dict()
    d["baseline_cpu_utilization"][tag]["vcpus_total"] = dict()

    for key in final[kernel][1]:
        # print(key)
        data[kernel][key] = dict()
        data[kernel][key]["throughput"] = list()
        data[kernel][key]["vmm"] = list()
        data[kernel][key]["vcpus_total"] = list()

    for iteration in final[kernel]:
        for key in final[kernel][iteration]:
            data[kernel][key]["throughput"].append(
                final[kernel][iteration][key]["throughput"])
            data[kernel][key]["vmm"].append(
                final[kernel][iteration][key]["vmm"])
            data[kernel][key]["vcpus_total"].append(
                final[kernel][iteration][key]["vcpus_total"])

    construct_imp_data(data, kernel, tag, d)
    # print_data(data, kernel)
print(json.dumps(d, indent=4))
