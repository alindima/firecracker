function filter_output() {
    cat $1 | sed 's/^\[Firecracker devtool\].\+$//g' |\
    sed 's/^\[ performance.\+$//g' | sed 's/=======.\+//g' |\
    sed 's/platform linux --.\+//g' | sed 's/cachedir:.\+//g' |\
    sed 's/rootdir:.\+//g' | sed 's/plugins: timeout.\+//g' | sed 's/timeout: .\+//g' |\
    sed 's/timeout method:.\+//g' | sed 's/timeout func_only:.\+//g' |\
    sed 's/collected.\+//g' | sed 's/-------.\+//g' | sed 's/.\+retry\.api: WARNING.\+//g' |\
    sed 's/.\+PASSED.\+//g' | sed 's/^[0-9]\+:[0-9]\+:[0-9]\+ \+//g' |\
    sed 's/vsock_throughput: INFO Testing with microvm: "//g' |\
    sed 's/", kernel//g' | sed 's/, disk/ /g' | sed 's/Linux .\+//g' |\
    sed '/Pulling/d' | sed '/Download/d' | sed '/Waiting/d' | sed '/Verifying/d' |\
    sed '/Digest/d' | sed '/status/d' | sed '/docker/d' | sed '/Pull/d' | sed '/^$/d'
}

# touch pytest_out
# # concatenate output
# for d in artifacts/*/
# do
#     [ -d "$d" ] && cat $d"pytest_out.txt" >> pytest_out
# done

# filter_output pytest_out

filter_output $1

# rm pytest_out
