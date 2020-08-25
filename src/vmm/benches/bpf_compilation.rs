use criterion::{criterion_group, criterion_main, Criterion};
use seccomp::{SeccompFilter, SeccompLevel};
use vmm::default_syscalls::get_seccomp_filter;

pub fn benchmark_seccomp(c: &mut Criterion) {
    c.bench_function("bpf whitelist compilation", |b| {
        b.iter(|| {
            let seccomp_filter = get_seccomp_filter(SeccompLevel::Advanced).unwrap_or_else(|err| {
                panic!("Could not create seccomp filter: {}", err);
            });
        })
    });

    c.bench_function("bpf whitelist compilation & loading", |b| {
        b.iter(|| {
            std::thread::spawn(move || {
                let seccomp_filter =
                    get_seccomp_filter(SeccompLevel::Advanced).unwrap_or_else(|err| {
                        panic!("Could not create seccomp filter: {}", err);
                    });
                // // Apply seccomp filter.
                SeccompFilter::apply(seccomp_filter).unwrap();
            })
            .join()
            .unwrap();
        })
    });
}

criterion_group!(benches, benchmark_seccomp);
criterion_main!(benches);
