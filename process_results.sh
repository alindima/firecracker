cat $1 | sed 's/^\[Firecracker devtool\].\+$//g' |\
sed 's/^\[ performance.\+$//g' | sed 's/=======.\+//g' |\
sed 's/platform linux --.\+//g' | sed 's/cachedir:.\+//g' |\
sed 's/rootdir:.\+//g' | sed 's/plugins: timeout.\+//g' | sed 's/timeout: .\+//g' |\
sed 's/timeout method:.\+//g' | sed 's/timeout func_only:.\+//g' |\
sed 's/collected.\+//g' | sed 's/-------.\+//g' | sed 's/.\+retry\.api: WARNING.\+//g' |\
sed 's/.\+PASSED.\+//g' | sed 's/^[0-9]\+:[0-9]\+:[0-9]\+ \+//g' |\
sed 's/vsock_throughput: INFO Testing with microvm: "//g' |\
sed 's/", kernel//g' | sed 's/, disk/ /g' | sed 's/Linux .\+//g' | sed '/^$/d'