for run in {1..100}
do
  ./tools/devtool -y test -m 0 -c "0-10" -- integration_tests/performance/test_memory.py -m "nonci" -s >> pytest_out_new
done