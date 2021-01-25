for run in {1..1}
do
  ./tools/devtool -y test -m 0 -c "0-10" -- integration_tests/performance/test_memory.py -m "nonci" -s >> pytest_out_new_2
done