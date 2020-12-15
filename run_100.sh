for run in {1..1}
do
  ./tools/devtool -y test -c "1-10" -m "0" -- integration_tests/performance/test_vsock_throughput.py -m "nonci" -s >> pytest_out
done
