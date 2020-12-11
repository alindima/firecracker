import sys
import json
import statistics
import math

# how to get baselines for test_vsock_throughput:

# 1. Configure a buildkite pipeline with the appropriate repo and metal instance(s).
# 2. Run buildkite-run command, to spawn 100 builds and retrieve their artifacts:
# ./bkrun "mkdir artifacts && ./tools/devtool -y test -c \"1-10\" -m \"0\" -- integration_tests/performance/test_vsock_throughput.py -m \"nonci\" -s > artifacts/pytest_out.txt" --checkout 19c6790 --times 100 --download-artifacts artifacts
# 3. Build


def percentile(results, k):
    length = len(results)
    results.sort()
    idx = length * k // 100
    if idx is not int(idx):
        return (results[idx - 1] + results[idx]) / 2
    return results[idx]


# def print_data(data, kernel):
#     for key in data[kernel]:
#         print(kernel, key, "stddev", statistics.stdev(data[kernel][key]["throughput"]),
#               statistics.stdev(data[kernel][key]["vmm"]), statistics.stdev(data[kernel][key]["vcpus_total"]))
#         print(kernel, key, "avg", statistics.mean(data[kernel][key]["throughput"]), statistics.mean(
#             data[kernel][key]["vmm"]), statistics.mean(data[kernel][key]["vcpus_total"]))
#         print(kernel, key, "min", min(data[kernel][key]["throughput"]), min(
#             data[kernel][key]["vmm"]), min(data[kernel][key]["vcpus_total"]))
#         print(kernel, key, "max", max(data[kernel][key]["throughput"]), max(
#             data[kernel][key]["vmm"]), max(data[kernel][key]["vcpus_total"]))
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


# Parse curated data.
filename = sys.argv[1]
cpu_model_iter_count = dict()

with open(filename) as f:
    cpu_model_line = f.readline()
    json_line1 = f.readline()
    json_line2 = f.readline()
    final = dict()

    while cpu_model_line and json_line1 and json_line2:

        if cpu_model_line not in cpu_model_iter_count:
            cpu_model_iter_count[cpu_model_line] = 1
        else:
            cpu_model_iter_count[cpu_model_line] += 1

        lines = [json_line1, json_line2]
        for line in lines:
            parsed = json.loads(line)

            microvm = parsed["custom"]["microvm"]
            kernel = parsed["custom"]["kernel"]
            disk = parsed["custom"]["disk"]

            if cpu_model_line not in final:
                final[cpu_model_line] = dict()

            if kernel not in final[cpu_model_line]:
                final[cpu_model_line][kernel] = dict()

            results = parsed["results"]
            for key in results:
                if key not in final[cpu_model_line][kernel]:
                    final[cpu_model_line][kernel][key] = dict()
                    final[cpu_model_line][kernel][key]["throughput"] = list()
                    final[cpu_model_line][kernel][key]["vmm"] = list()
                    final[cpu_model_line][kernel][key]["vcpus_total"] = list()

                final[cpu_model_line][kernel][key]["throughput"].append(
                    results[key]["throughput"]["total"])
                final[cpu_model_line][kernel][key]["vmm"].append(
                    results[key]["cpu_utilization_host"]["vmm"])
                final[cpu_model_line][kernel][key]["vcpus_total"].append(
                    results[key]["cpu_utilization_guest"]["vcpus_total"])

        cpu_model_line = f.readline()
        json_line1 = f.readline()
        json_line2 = f.readline()


# Print statistics
for cpu_model in final:
    d = dict()
    d["baseline_bw"] = dict()
    d["baseline_cpu_utilization"] = dict()
    disk = "ubuntu-18.04.ext4"
    print(cpu_model)
    for kernel in final[cpu_model]:

        tag = f"{kernel}/{disk}"
        d["baseline_bw"][tag] = dict()
        d["baseline_cpu_utilization"][tag] = dict()
        d["baseline_cpu_utilization"][tag]["vmm"] = dict()
        d["baseline_cpu_utilization"][tag]["vcpus_total"] = dict()

        construct_imp_data(final[cpu_model], kernel, tag, d)
        print(json.dumps(d, indent=4))

print(cpu_model_iter_count)
