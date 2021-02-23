# Seccomp in Firecracker


Seccomp filters are used by default to limit the host system calls Firecracker
can use. The default filters only allow the bare minimum set of system calls and
parameters that Firecracker needs in order to function correctly.

The filters are loaded in the Firecracker process, on a per-thread basis,
as follows:
- VMM (main) - right before executing client code on the VCPU threads;
- API - right before launching the HTTP server;
- VCPUs - right before executing client code.

**Note**: On experimental GNU targets, there are no default seccomp filters installed,
since they are not intended for production use.

Firecracker uses JSON files for expressing the filter rules and relies on the
[seccompiler](seccompiler.md) tool for all the seccomp functionality.

## Default filters (recommended)

At build time, the default target-specific JSON file is compiled into the serialized
binary file, using seccompiler, and gets embedded in the Firecracker binary.

This process is performed automatically, when building the executable.

To minimise the overhead of succesive builds, the compiled filter file is cached in
the build folder and is only recompiled if modified.

You can find the default seccomp filters under `resources/seccomp`.

## Custom filters (advanced users only)

Firecracker exposes a way for advanced users to override the default filters with
fully customisable alternatives, leveraging the same JSON/seccompiler tooling,
at startup time.

Via Firecracker's optional `--seccomp-filter` parameter, one can supply
the path to a custom filter file compiled with seccompiler.

Users of experimentally-supported targets (like GNU libc builds) may be able to use
this feature to implement seccomp filters without needing to have a custom build
of Firecracker.

**Note**: This feature overrides the default filters and can be dangerous. Filter
misconfiguration can result in abruptly terminating the process or disabling the seccomp
security boundary altogether.
We recommend using the default filters instead.

## Disabling seccomp (not recommended)

Firecracker also has support for a `--no-seccomp` parameter, which disables all seccomp
filtering.
Do **not** use in production.
