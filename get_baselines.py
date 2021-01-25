import sys
import json
import statistics
import math

# how to get baselines for test_vsock_throughput:

# 1. Configure a buildkite pipeline with the appropriate repo and metal instance(s).
# 2. Run buildkite-run command, to spawn 100 builds and retrieve their artifacts:
# ./bkrun "mkdir artifacts && ./tools/devtool -y test -c \"1-10\" -m \"0\" -- integration_tests/performance/test_vsock_throughput.py -m \"nonci\" -s > artifacts/pytest_out.txt" --checkout 4f77e8084e37c41aade6facee60f04884085c34b --times 2 --download-artifacts artifacts
# 3. Build


def percentile(results, k):
    length = len(results)
    results.sort()
    idx = length * k // 100
    if idx is not int(idx):
        return (results[idx - 1] + results[idx]) / 2
    return results[idx]


def construct_imp_data(data):
    result = dict()

    for key in data:
        array = data[key]
        avg = statistics.mean(array)
        stddev = statistics.stdev(array)
        result[key] = dict()
        result[key]["target"] = math.ceil(round(avg, 2))
        result[key]["delta_percentage"] = math.ceil(
            round(3*stddev/avg * 100, 2)) + 3

    return result

    # new_key = key[(len(tag)) + 1:]
    # d["baseline_bw"][tag][new_key] = dict()
    # bw_avg = statistics.mean(data[kernel][key]["throughput"])
    # bw_stddev = statistics.stdev(data[kernel][key]["throughput"])
    # d["baseline_bw"][tag][new_key]["target"] = math.ceil(round(bw_avg, 2))
    # d["baseline_bw"][tag][new_key]["delta_percentage"] = math.ceil(
    #     round(3*bw_stddev/bw_avg * 100, 2)) + 3

    # d["baseline_cpu_utilization"][tag]["vmm"][new_key] = dict()
    # vmm_avg = statistics.mean(data[kernel][key]["vmm"])
    # vmm_stddev = statistics.stdev(data[kernel][key]["vmm"])
    # d["baseline_cpu_utilization"][tag]["vmm"][new_key]["target"] = math.ceil(
    #     round(vmm_avg, 2))
    # d["baseline_cpu_utilization"][tag]["vmm"][new_key]["delta_percentage"] = math.ceil(
    #     round(3*vmm_stddev/vmm_avg * 100, 2)) + 3

    # d["baseline_cpu_utilization"][tag]["vcpus_total"][new_key] = dict()
    # vcpus_avg = statistics.mean(data[kernel][key]["vcpus_total"])
    # vcpus_stddev = statistics.stdev(data[kernel][key]["vcpus_total"])
    # d["baseline_cpu_utilization"][tag]["vcpus_total"][new_key]["target"] = math.ceil(
    #     round(vcpus_avg, 2))
    # d["baseline_cpu_utilization"][tag]["vcpus_total"][new_key]["delta_percentage"] = math.ceil(
    #     round(3*vcpus_stddev/vcpus_avg * 100, 2)) + 3


# Parse curated data.
filename = sys.argv[1]
cpu_model_iter_count = dict()

with open(filename) as f:
    cpu_model_line = f.readline()
    json_line1 = f.readline()
    json_line2 = f.readline()
    json_line3 = f.readline()
    json_line4 = f.readline()

    final = dict()

    while cpu_model_line and json_line1 and json_line2:

        if cpu_model_line not in cpu_model_iter_count:
            cpu_model_iter_count[cpu_model_line] = 1
            final[cpu_model_line] = dict()
        else:
            cpu_model_iter_count[cpu_model_line] += 1

        lines = [json_line1, json_line2, json_line3, json_line4]
        for line in lines:
            parsed = json.loads(line)

            for key in parsed['results']:
                if key not in final[cpu_model_line]:
                    final[cpu_model_line][key] = list()

                final[cpu_model_line][key].append(
                    parsed['results'][key]["ThroughputDifference"]["overhead"])

        cpu_model_line = f.readline()
        json_line1 = f.readline()
        json_line2 = f.readline()
        json_line3 = f.readline()
        json_line4 = f.readline()


print(json.dumps(final, indent=4))
# print(final)


# Print statistics
for cpu_model in final:
    print(cpu_model)
    for kernel in final[cpu_model]:

        data = construct_imp_data(final[cpu_model])
        print(json.dumps(data, indent=4))
