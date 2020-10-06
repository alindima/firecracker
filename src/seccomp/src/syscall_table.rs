// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(missing_docs)]

use std::collections::HashMap;

#[derive(Debug)]
pub struct SyscallTable {
    map: HashMap<String, i64>,

    arch: String,
}

// Creates and owns a mapping from the arch-specific syscall name to the right number
impl SyscallTable {
    pub fn new(arch: String) -> Self {
        let mut instance = Self {
            arch,
            map: HashMap::with_capacity(332), // nr of syscalls for x86_64
        };

        instance.populate_map();

        instance
    }

    pub fn get_syscall_nr(&self, sys_name: &str) -> Option<i64> {
        self.map.get(sys_name).copied()
    }

    // We need to create an architecture-specific map since the set of
    // possible syscalls is architecture-dependent
    fn populate_map(&mut self) {
        if self.arch == "aarch64" {
            self.map
                .insert("SYS_io_setup".to_string(), libc::SYS_io_setup);
            self.map
                .insert("SYS_io_destroy".to_string(), libc::SYS_io_destroy);
            self.map
                .insert("SYS_io_submit".to_string(), libc::SYS_io_submit);
            self.map
                .insert("SYS_io_cancel".to_string(), libc::SYS_io_cancel);
            self.map
                .insert("SYS_io_getevents".to_string(), libc::SYS_io_getevents);
            self.map
                .insert("SYS_setxattr".to_string(), libc::SYS_setxattr);
            self.map
                .insert("SYS_lsetxattr".to_string(), libc::SYS_lsetxattr);
            self.map
                .insert("SYS_fsetxattr".to_string(), libc::SYS_fsetxattr);
            self.map
                .insert("SYS_getxattr".to_string(), libc::SYS_getxattr);
            self.map
                .insert("SYS_lgetxattr".to_string(), libc::SYS_lgetxattr);
            self.map
                .insert("SYS_fgetxattr".to_string(), libc::SYS_fgetxattr);
            self.map
                .insert("SYS_listxattr".to_string(), libc::SYS_listxattr);
            self.map
                .insert("SYS_llistxattr".to_string(), libc::SYS_llistxattr);
            self.map
                .insert("SYS_flistxattr".to_string(), libc::SYS_flistxattr);
            self.map
                .insert("SYS_removexattr".to_string(), libc::SYS_removexattr);
            self.map
                .insert("SYS_lremovexattr".to_string(), libc::SYS_lremovexattr);
            self.map
                .insert("SYS_fremovexattr".to_string(), libc::SYS_fremovexattr);
            self.map.insert("SYS_getcwd".to_string(), libc::SYS_getcwd);
            self.map
                .insert("SYS_lookup_dcookie".to_string(), libc::SYS_lookup_dcookie);
            self.map
                .insert("SYS_eventfd2".to_string(), libc::SYS_eventfd2);
            self.map
                .insert("SYS_epoll_create1".to_string(), libc::SYS_epoll_create1);
            self.map
                .insert("SYS_epoll_ctl".to_string(), libc::SYS_epoll_ctl);
            self.map
                .insert("SYS_epoll_pwait".to_string(), libc::SYS_epoll_pwait);
            self.map.insert("SYS_dup".to_string(), libc::SYS_dup);
            self.map.insert("SYS_dup3".to_string(), libc::SYS_dup3);
            self.map.insert("SYS_fcntl".to_string(), libc::SYS_fcntl);
            self.map
                .insert("SYS_inotify_init1".to_string(), libc::SYS_inotify_init1);
            self.map.insert(
                "SYS_inotify_add_watch".to_string(),
                libc::SYS_inotify_add_watch,
            );
            self.map.insert(
                "SYS_inotify_rm_watch".to_string(),
                libc::SYS_inotify_rm_watch,
            );
            self.map.insert("SYS_ioctl".to_string(), libc::SYS_ioctl);
            self.map
                .insert("SYS_ioprio_set".to_string(), libc::SYS_ioprio_set);
            self.map
                .insert("SYS_ioprio_get".to_string(), libc::SYS_ioprio_get);
            self.map.insert("SYS_flock".to_string(), libc::SYS_flock);
            self.map
                .insert("SYS_mknodat".to_string(), libc::SYS_mknodat);
            self.map
                .insert("SYS_mkdirat".to_string(), libc::SYS_mkdirat);
            self.map
                .insert("SYS_unlinkat".to_string(), libc::SYS_unlinkat);
            self.map
                .insert("SYS_symlinkat".to_string(), libc::SYS_symlinkat);
            self.map.insert("SYS_linkat".to_string(), libc::SYS_linkat);
            self.map
                .insert("SYS_renameat".to_string(), libc::SYS_renameat);
            self.map
                .insert("SYS_umount2".to_string(), libc::SYS_umount2);
            self.map.insert("SYS_mount".to_string(), libc::SYS_mount);
            self.map
                .insert("SYS_pivot_root".to_string(), libc::SYS_pivot_root);
            self.map
                .insert("SYS_nfsservctl".to_string(), libc::SYS_nfsservctl);
            self.map.insert("SYS_statfs".to_string(), libc::SYS_statfs);
            self.map
                .insert("SYS_fstatfs".to_string(), libc::SYS_fstatfs);
            self.map
                .insert("SYS_truncate".to_string(), libc::SYS_truncate);
            self.map
                .insert("SYS_ftruncate".to_string(), libc::SYS_ftruncate);
            self.map
                .insert("SYS_fallocate".to_string(), libc::SYS_fallocate);
            self.map
                .insert("SYS_faccessat".to_string(), libc::SYS_faccessat);
            self.map.insert("SYS_chdir".to_string(), libc::SYS_chdir);
            self.map.insert("SYS_fchdir".to_string(), libc::SYS_fchdir);
            self.map.insert("SYS_chroot".to_string(), libc::SYS_chroot);
            self.map.insert("SYS_fchmod".to_string(), libc::SYS_fchmod);
            self.map
                .insert("SYS_fchmodat".to_string(), libc::SYS_fchmodat);
            self.map
                .insert("SYS_fchownat".to_string(), libc::SYS_fchownat);
            self.map.insert("SYS_fchown".to_string(), libc::SYS_fchown);
            self.map.insert("SYS_openat".to_string(), libc::SYS_openat);
            self.map.insert("SYS_close".to_string(), libc::SYS_close);
            self.map
                .insert("SYS_vhangup".to_string(), libc::SYS_vhangup);
            self.map.insert("SYS_pipe2".to_string(), libc::SYS_pipe2);
            self.map
                .insert("SYS_quotactl".to_string(), libc::SYS_quotactl);
            self.map
                .insert("SYS_getdents64".to_string(), libc::SYS_getdents64);
            self.map.insert("SYS_lseek".to_string(), libc::SYS_lseek);
            self.map.insert("SYS_read".to_string(), libc::SYS_read);
            self.map.insert("SYS_write".to_string(), libc::SYS_write);
            self.map.insert("SYS_readv".to_string(), libc::SYS_readv);
            self.map.insert("SYS_writev".to_string(), libc::SYS_writev);
            self.map
                .insert("SYS_pread64".to_string(), libc::SYS_pread64);
            self.map
                .insert("SYS_pwrite64".to_string(), libc::SYS_pwrite64);
            self.map.insert("SYS_preadv".to_string(), libc::SYS_preadv);
            self.map
                .insert("SYS_pwritev".to_string(), libc::SYS_pwritev);
            self.map
                .insert("SYS_pselect6".to_string(), libc::SYS_pselect6);
            self.map.insert("SYS_ppoll".to_string(), libc::SYS_ppoll);
            self.map
                .insert("SYS_signalfd4".to_string(), libc::SYS_signalfd4);
            self.map
                .insert("SYS_vmsplice".to_string(), libc::SYS_vmsplice);
            self.map.insert("SYS_splice".to_string(), libc::SYS_splice);
            self.map.insert("SYS_tee".to_string(), libc::SYS_tee);
            self.map
                .insert("SYS_readlinkat".to_string(), libc::SYS_readlinkat);
            self.map
                .insert("SYS_newfstatat".to_string(), libc::SYS_newfstatat);
            self.map.insert("SYS_fstat".to_string(), libc::SYS_fstat);
            self.map.insert("SYS_sync".to_string(), libc::SYS_sync);
            self.map.insert("SYS_fsync".to_string(), libc::SYS_fsync);
            self.map
                .insert("SYS_fdatasync".to_string(), libc::SYS_fdatasync);
            self.map
                .insert("SYS_sync_file_range".to_string(), libc::SYS_sync_file_range);
            self.map
                .insert("SYS_timerfd_create".to_string(), libc::SYS_timerfd_create);
            self.map
                .insert("SYS_timerfd_settime".to_string(), libc::SYS_timerfd_settime);
            self.map
                .insert("SYS_timerfd_gettime".to_string(), libc::SYS_timerfd_gettime);
            self.map
                .insert("SYS_utimensat".to_string(), libc::SYS_utimensat);
            self.map.insert("SYS_acct".to_string(), libc::SYS_acct);
            self.map.insert("SYS_capget".to_string(), libc::SYS_capget);
            self.map.insert("SYS_capset".to_string(), libc::SYS_capset);
            self.map
                .insert("SYS_personality".to_string(), libc::SYS_personality);
            self.map.insert("SYS_exit".to_string(), libc::SYS_exit);
            self.map
                .insert("SYS_exit_group".to_string(), libc::SYS_exit_group);
            self.map.insert("SYS_waitid".to_string(), libc::SYS_waitid);
            self.map
                .insert("SYS_set_tid_address".to_string(), libc::SYS_set_tid_address);
            self.map
                .insert("SYS_unshare".to_string(), libc::SYS_unshare);
            self.map.insert("SYS_futex".to_string(), libc::SYS_futex);
            self.map
                .insert("SYS_set_robust_list".to_string(), libc::SYS_set_robust_list);
            self.map
                .insert("SYS_get_robust_list".to_string(), libc::SYS_get_robust_list);
            self.map
                .insert("SYS_nanosleep".to_string(), libc::SYS_nanosleep);
            self.map
                .insert("SYS_getitimer".to_string(), libc::SYS_getitimer);
            self.map
                .insert("SYS_setitimer".to_string(), libc::SYS_setitimer);
            self.map
                .insert("SYS_kexec_load".to_string(), libc::SYS_kexec_load);
            self.map
                .insert("SYS_init_module".to_string(), libc::SYS_init_module);
            self.map
                .insert("SYS_delete_module".to_string(), libc::SYS_delete_module);
            self.map
                .insert("SYS_timer_create".to_string(), libc::SYS_timer_create);
            self.map
                .insert("SYS_timer_gettime".to_string(), libc::SYS_timer_gettime);
            self.map.insert(
                "SYS_timer_getoverrun".to_string(),
                libc::SYS_timer_getoverrun,
            );
            self.map
                .insert("SYS_timer_settime".to_string(), libc::SYS_timer_settime);
            self.map
                .insert("SYS_timer_delete".to_string(), libc::SYS_timer_delete);
            self.map
                .insert("SYS_clock_settime".to_string(), libc::SYS_clock_settime);
            self.map
                .insert("SYS_clock_gettime".to_string(), libc::SYS_clock_gettime);
            self.map
                .insert("SYS_clock_getres".to_string(), libc::SYS_clock_getres);
            self.map
                .insert("SYS_clock_nanosleep".to_string(), libc::SYS_clock_nanosleep);
            self.map.insert("SYS_syslog".to_string(), libc::SYS_syslog);
            self.map.insert("SYS_ptrace".to_string(), libc::SYS_ptrace);
            self.map
                .insert("SYS_sched_setparam".to_string(), libc::SYS_sched_setparam);
            self.map.insert(
                "SYS_sched_setscheduler".to_string(),
                libc::SYS_sched_setscheduler,
            );
            self.map.insert(
                "SYS_sched_getscheduler".to_string(),
                libc::SYS_sched_getscheduler,
            );
            self.map
                .insert("SYS_sched_getparam".to_string(), libc::SYS_sched_getparam);
            self.map.insert(
                "SYS_sched_setaffinity".to_string(),
                libc::SYS_sched_setaffinity,
            );
            self.map.insert(
                "SYS_sched_getaffinity".to_string(),
                libc::SYS_sched_getaffinity,
            );
            self.map
                .insert("SYS_sched_yield".to_string(), libc::SYS_sched_yield);
            self.map.insert(
                "SYS_sched_get_priority_max".to_string(),
                libc::SYS_sched_get_priority_max,
            );
            self.map.insert(
                "SYS_sched_get_priority_min".to_string(),
                libc::SYS_sched_get_priority_min,
            );
            self.map.insert(
                "SYS_sched_rr_get_interval".to_string(),
                libc::SYS_sched_rr_get_interval,
            );
            self.map
                .insert("SYS_restart_syscall".to_string(), libc::SYS_restart_syscall);
            self.map.insert("SYS_kill".to_string(), libc::SYS_kill);
            self.map.insert("SYS_tkill".to_string(), libc::SYS_tkill);
            self.map.insert("SYS_tgkill".to_string(), libc::SYS_tgkill);
            self.map
                .insert("SYS_sigaltstack".to_string(), libc::SYS_sigaltstack);
            self.map
                .insert("SYS_rt_sigsuspend".to_string(), libc::SYS_rt_sigsuspend);
            self.map
                .insert("SYS_rt_sigaction".to_string(), libc::SYS_rt_sigaction);
            self.map
                .insert("SYS_rt_sigprocmask".to_string(), libc::SYS_rt_sigprocmask);
            self.map
                .insert("SYS_rt_sigpending".to_string(), libc::SYS_rt_sigpending);
            self.map
                .insert("SYS_rt_sigtimedwait".to_string(), libc::SYS_rt_sigtimedwait);
            self.map
                .insert("SYS_rt_sigqueueinfo".to_string(), libc::SYS_rt_sigqueueinfo);
            self.map
                .insert("SYS_rt_sigreturn".to_string(), libc::SYS_rt_sigreturn);
            self.map
                .insert("SYS_setpriority".to_string(), libc::SYS_setpriority);
            self.map
                .insert("SYS_getpriority".to_string(), libc::SYS_getpriority);
            self.map.insert("SYS_reboot".to_string(), libc::SYS_reboot);
            self.map
                .insert("SYS_setregid".to_string(), libc::SYS_setregid);
            self.map.insert("SYS_setgid".to_string(), libc::SYS_setgid);
            self.map
                .insert("SYS_setreuid".to_string(), libc::SYS_setreuid);
            self.map.insert("SYS_setuid".to_string(), libc::SYS_setuid);
            self.map
                .insert("SYS_setresuid".to_string(), libc::SYS_setresuid);
            self.map
                .insert("SYS_getresuid".to_string(), libc::SYS_getresuid);
            self.map
                .insert("SYS_setresgid".to_string(), libc::SYS_setresgid);
            self.map
                .insert("SYS_getresgid".to_string(), libc::SYS_getresgid);
            self.map
                .insert("SYS_setfsuid".to_string(), libc::SYS_setfsuid);
            self.map
                .insert("SYS_setfsgid".to_string(), libc::SYS_setfsgid);
            self.map.insert("SYS_times".to_string(), libc::SYS_times);
            self.map
                .insert("SYS_setpgid".to_string(), libc::SYS_setpgid);
            self.map
                .insert("SYS_getpgid".to_string(), libc::SYS_getpgid);
            self.map.insert("SYS_getsid".to_string(), libc::SYS_getsid);
            self.map.insert("SYS_setsid".to_string(), libc::SYS_setsid);
            self.map
                .insert("SYS_getgroups".to_string(), libc::SYS_getgroups);
            self.map
                .insert("SYS_setgroups".to_string(), libc::SYS_setgroups);
            self.map.insert("SYS_uname".to_string(), libc::SYS_uname);
            self.map
                .insert("SYS_sethostname".to_string(), libc::SYS_sethostname);
            self.map
                .insert("SYS_setdomainname".to_string(), libc::SYS_setdomainname);
            self.map
                .insert("SYS_getrlimit".to_string(), libc::SYS_getrlimit);
            self.map
                .insert("SYS_setrlimit".to_string(), libc::SYS_setrlimit);
            self.map
                .insert("SYS_getrusage".to_string(), libc::SYS_getrusage);
            self.map.insert("SYS_umask".to_string(), libc::SYS_umask);
            self.map.insert("SYS_prctl".to_string(), libc::SYS_prctl);
            self.map.insert("SYS_getcpu".to_string(), libc::SYS_getcpu);
            self.map
                .insert("SYS_gettimeofday".to_string(), libc::SYS_gettimeofday);
            self.map
                .insert("SYS_settimeofday".to_string(), libc::SYS_settimeofday);
            self.map
                .insert("SYS_adjtimex".to_string(), libc::SYS_adjtimex);
            self.map.insert("SYS_getpid".to_string(), libc::SYS_getpid);
            self.map
                .insert("SYS_getppid".to_string(), libc::SYS_getppid);
            self.map.insert("SYS_getuid".to_string(), libc::SYS_getuid);
            self.map
                .insert("SYS_geteuid".to_string(), libc::SYS_geteuid);
            self.map.insert("SYS_getgid".to_string(), libc::SYS_getgid);
            self.map
                .insert("SYS_getegid".to_string(), libc::SYS_getegid);
            self.map.insert("SYS_gettid".to_string(), libc::SYS_gettid);
            self.map
                .insert("SYS_sysinfo".to_string(), libc::SYS_sysinfo);
            self.map
                .insert("SYS_mq_open".to_string(), libc::SYS_mq_open);
            self.map
                .insert("SYS_mq_unlink".to_string(), libc::SYS_mq_unlink);
            self.map
                .insert("SYS_mq_timedsend".to_string(), libc::SYS_mq_timedsend);
            self.map
                .insert("SYS_mq_timedreceive".to_string(), libc::SYS_mq_timedreceive);
            self.map
                .insert("SYS_mq_notify".to_string(), libc::SYS_mq_notify);
            self.map
                .insert("SYS_mq_getsetattr".to_string(), libc::SYS_mq_getsetattr);
            self.map.insert("SYS_msgget".to_string(), libc::SYS_msgget);
            self.map.insert("SYS_msgctl".to_string(), libc::SYS_msgctl);
            self.map.insert("SYS_msgrcv".to_string(), libc::SYS_msgrcv);
            self.map.insert("SYS_msgsnd".to_string(), libc::SYS_msgsnd);
            self.map.insert("SYS_semget".to_string(), libc::SYS_semget);
            self.map.insert("SYS_semctl".to_string(), libc::SYS_semctl);
            self.map
                .insert("SYS_semtimedop".to_string(), libc::SYS_semtimedop);
            self.map.insert("SYS_semop".to_string(), libc::SYS_semop);
            self.map.insert("SYS_shmget".to_string(), libc::SYS_shmget);
            self.map.insert("SYS_shmctl".to_string(), libc::SYS_shmctl);
            self.map.insert("SYS_shmat".to_string(), libc::SYS_shmat);
            self.map.insert("SYS_shmdt".to_string(), libc::SYS_shmdt);
            self.map.insert("SYS_socket".to_string(), libc::SYS_socket);
            self.map
                .insert("SYS_socketpair".to_string(), libc::SYS_socketpair);
            self.map.insert("SYS_bind".to_string(), libc::SYS_bind);
            self.map.insert("SYS_listen".to_string(), libc::SYS_listen);
            self.map.insert("SYS_accept".to_string(), libc::SYS_accept);
            self.map
                .insert("SYS_connect".to_string(), libc::SYS_connect);
            self.map
                .insert("SYS_getsockname".to_string(), libc::SYS_getsockname);
            self.map
                .insert("SYS_getpeername".to_string(), libc::SYS_getpeername);
            self.map.insert("SYS_sendto".to_string(), libc::SYS_sendto);
            self.map
                .insert("SYS_recvfrom".to_string(), libc::SYS_recvfrom);
            self.map
                .insert("SYS_setsockopt".to_string(), libc::SYS_setsockopt);
            self.map
                .insert("SYS_getsockopt".to_string(), libc::SYS_getsockopt);
            self.map
                .insert("SYS_shutdown".to_string(), libc::SYS_shutdown);
            self.map
                .insert("SYS_sendmsg".to_string(), libc::SYS_sendmsg);
            self.map
                .insert("SYS_recvmsg".to_string(), libc::SYS_recvmsg);
            self.map
                .insert("SYS_readahead".to_string(), libc::SYS_readahead);
            self.map.insert("SYS_brk".to_string(), libc::SYS_brk);
            self.map.insert("SYS_munmap".to_string(), libc::SYS_munmap);
            self.map.insert("SYS_mremap".to_string(), libc::SYS_mremap);
            self.map
                .insert("SYS_add_key".to_string(), libc::SYS_add_key);
            self.map
                .insert("SYS_request_key".to_string(), libc::SYS_request_key);
            self.map.insert("SYS_keyctl".to_string(), libc::SYS_keyctl);
            self.map.insert("SYS_clone".to_string(), libc::SYS_clone);
            self.map.insert("SYS_execve".to_string(), libc::SYS_execve);
            self.map.insert("SYS_mmap".to_string(), libc::SYS_mmap);
            self.map.insert("SYS_swapon".to_string(), libc::SYS_swapon);
            self.map
                .insert("SYS_swapoff".to_string(), libc::SYS_swapoff);
            self.map
                .insert("SYS_mprotect".to_string(), libc::SYS_mprotect);
            self.map.insert("SYS_msync".to_string(), libc::SYS_msync);
            self.map.insert("SYS_mlock".to_string(), libc::SYS_mlock);
            self.map
                .insert("SYS_munlock".to_string(), libc::SYS_munlock);
            self.map
                .insert("SYS_mlockall".to_string(), libc::SYS_mlockall);
            self.map
                .insert("SYS_munlockall".to_string(), libc::SYS_munlockall);
            self.map
                .insert("SYS_mincore".to_string(), libc::SYS_mincore);
            self.map
                .insert("SYS_madvise".to_string(), libc::SYS_madvise);
            self.map.insert(
                "SYS_remap_file_pages".to_string(),
                libc::SYS_remap_file_pages,
            );
            self.map.insert("SYS_mbind".to_string(), libc::SYS_mbind);
            self.map
                .insert("SYS_get_mempolicy".to_string(), libc::SYS_get_mempolicy);
            self.map
                .insert("SYS_set_mempolicy".to_string(), libc::SYS_set_mempolicy);
            self.map
                .insert("SYS_migrate_pages".to_string(), libc::SYS_migrate_pages);
            self.map
                .insert("SYS_move_pages".to_string(), libc::SYS_move_pages);
            self.map.insert(
                "SYS_rt_tgsigqueueinfo".to_string(),
                libc::SYS_rt_tgsigqueueinfo,
            );
            self.map
                .insert("SYS_perf_event_open".to_string(), libc::SYS_perf_event_open);
            self.map
                .insert("SYS_accept4".to_string(), libc::SYS_accept4);
            self.map
                .insert("SYS_recvmmsg".to_string(), libc::SYS_recvmmsg);
            self.map.insert("SYS_wait4".to_string(), libc::SYS_wait4);
            self.map
                .insert("SYS_prlimit64".to_string(), libc::SYS_prlimit64);
            self.map
                .insert("SYS_fanotify_init".to_string(), libc::SYS_fanotify_init);
            self.map
                .insert("SYS_fanotify_mark".to_string(), libc::SYS_fanotify_mark);
            self.map.insert(
                "SYS_name_to_handle_at".to_string(),
                libc::SYS_name_to_handle_at,
            );
            self.map.insert(
                "SYS_open_by_handle_at".to_string(),
                libc::SYS_open_by_handle_at,
            );
            self.map
                .insert("SYS_clock_adjtime".to_string(), libc::SYS_clock_adjtime);
            self.map.insert("SYS_syncfs".to_string(), libc::SYS_syncfs);
            self.map.insert("SYS_setns".to_string(), libc::SYS_setns);
            self.map
                .insert("SYS_sendmmsg".to_string(), libc::SYS_sendmmsg);
            self.map.insert(
                "SYS_process_vm_readv".to_string(),
                libc::SYS_process_vm_readv,
            );
            self.map.insert(
                "SYS_process_vm_writev".to_string(),
                libc::SYS_process_vm_writev,
            );
            self.map.insert("SYS_kcmp".to_string(), libc::SYS_kcmp);
            self.map
                .insert("SYS_finit_module".to_string(), libc::SYS_finit_module);
            self.map
                .insert("SYS_sched_setattr".to_string(), libc::SYS_sched_setattr);
            self.map
                .insert("SYS_sched_getattr".to_string(), libc::SYS_sched_getattr);
            self.map
                .insert("SYS_renameat2".to_string(), libc::SYS_renameat2);
            self.map
                .insert("SYS_seccomp".to_string(), libc::SYS_seccomp);
            self.map
                .insert("SYS_getrandom".to_string(), libc::SYS_getrandom);
            self.map
                .insert("SYS_memfd_create".to_string(), libc::SYS_memfd_create);
            self.map.insert("SYS_bpf".to_string(), libc::SYS_bpf);
            self.map
                .insert("SYS_execveat".to_string(), libc::SYS_execveat);
            self.map
                .insert("SYS_userfaultfd".to_string(), libc::SYS_userfaultfd);
            self.map
                .insert("SYS_membarrier".to_string(), libc::SYS_membarrier);
            self.map.insert("SYS_mlock2".to_string(), libc::SYS_mlock2);
            self.map
                .insert("SYS_copy_file_range".to_string(), libc::SYS_copy_file_range);
            self.map
                .insert("SYS_preadv2".to_string(), libc::SYS_preadv2);
            self.map
                .insert("SYS_pwritev2".to_string(), libc::SYS_pwritev2);
            self.map
                .insert("SYS_pkey_mprotect".to_string(), libc::SYS_pkey_mprotect);
            self.map
                .insert("SYS_pkey_alloc".to_string(), libc::SYS_pkey_alloc);
            self.map
                .insert("SYS_pkey_free".to_string(), libc::SYS_pkey_free);
            self.map.insert("SYS_statx".to_string(), libc::SYS_statx);
        }

        if self.arch == "x86_64" {
            self.map.insert("SYS_read".to_string(), libc::SYS_read);
            self.map.insert("SYS_write".to_string(), libc::SYS_write);
            self.map.insert("SYS_open".to_string(), libc::SYS_open);
            self.map.insert("SYS_close".to_string(), libc::SYS_close);
            self.map.insert("SYS_stat".to_string(), libc::SYS_stat);
            self.map.insert("SYS_fstat".to_string(), libc::SYS_fstat);
            self.map.insert("SYS_lstat".to_string(), libc::SYS_lstat);
            self.map.insert("SYS_poll".to_string(), libc::SYS_poll);
            self.map.insert("SYS_lseek".to_string(), libc::SYS_lseek);
            self.map.insert("SYS_mmap".to_string(), libc::SYS_mmap);
            self.map
                .insert("SYS_mprotect".to_string(), libc::SYS_mprotect);
            self.map.insert("SYS_munmap".to_string(), libc::SYS_munmap);
            self.map.insert("SYS_brk".to_string(), libc::SYS_brk);
            self.map
                .insert("SYS_rt_sigaction".to_string(), libc::SYS_rt_sigaction);
            self.map
                .insert("SYS_rt_sigprocmask".to_string(), libc::SYS_rt_sigprocmask);
            self.map
                .insert("SYS_rt_sigreturn".to_string(), libc::SYS_rt_sigreturn);
            self.map.insert("SYS_ioctl".to_string(), libc::SYS_ioctl);
            self.map
                .insert("SYS_pread64".to_string(), libc::SYS_pread64);
            self.map
                .insert("SYS_pwrite64".to_string(), libc::SYS_pwrite64);
            self.map.insert("SYS_readv".to_string(), libc::SYS_readv);
            self.map.insert("SYS_writev".to_string(), libc::SYS_writev);
            self.map.insert("SYS_access".to_string(), libc::SYS_access);
            self.map.insert("SYS_pipe".to_string(), libc::SYS_pipe);
            self.map.insert("SYS_select".to_string(), libc::SYS_select);
            self.map
                .insert("SYS_sched_yield".to_string(), libc::SYS_sched_yield);
            self.map.insert("SYS_mremap".to_string(), libc::SYS_mremap);
            self.map.insert("SYS_msync".to_string(), libc::SYS_msync);
            self.map
                .insert("SYS_mincore".to_string(), libc::SYS_mincore);
            self.map
                .insert("SYS_madvise".to_string(), libc::SYS_madvise);
            self.map.insert("SYS_shmget".to_string(), libc::SYS_shmget);
            self.map.insert("SYS_shmat".to_string(), libc::SYS_shmat);
            self.map.insert("SYS_shmctl".to_string(), libc::SYS_shmctl);
            self.map.insert("SYS_dup".to_string(), libc::SYS_dup);
            self.map.insert("SYS_dup2".to_string(), libc::SYS_dup2);
            self.map.insert("SYS_pause".to_string(), libc::SYS_pause);
            self.map
                .insert("SYS_nanosleep".to_string(), libc::SYS_nanosleep);
            self.map
                .insert("SYS_getitimer".to_string(), libc::SYS_getitimer);
            self.map.insert("SYS_alarm".to_string(), libc::SYS_alarm);
            self.map
                .insert("SYS_setitimer".to_string(), libc::SYS_setitimer);
            self.map.insert("SYS_getpid".to_string(), libc::SYS_getpid);
            self.map
                .insert("SYS_sendfile".to_string(), libc::SYS_sendfile);
            self.map.insert("SYS_socket".to_string(), libc::SYS_socket);
            self.map
                .insert("SYS_connect".to_string(), libc::SYS_connect);
            self.map.insert("SYS_accept".to_string(), libc::SYS_accept);
            self.map.insert("SYS_sendto".to_string(), libc::SYS_sendto);
            self.map
                .insert("SYS_recvfrom".to_string(), libc::SYS_recvfrom);
            self.map
                .insert("SYS_sendmsg".to_string(), libc::SYS_sendmsg);
            self.map
                .insert("SYS_recvmsg".to_string(), libc::SYS_recvmsg);
            self.map
                .insert("SYS_shutdown".to_string(), libc::SYS_shutdown);
            self.map.insert("SYS_bind".to_string(), libc::SYS_bind);
            self.map.insert("SYS_listen".to_string(), libc::SYS_listen);
            self.map
                .insert("SYS_getsockname".to_string(), libc::SYS_getsockname);
            self.map
                .insert("SYS_getpeername".to_string(), libc::SYS_getpeername);
            self.map
                .insert("SYS_socketpair".to_string(), libc::SYS_socketpair);
            self.map
                .insert("SYS_setsockopt".to_string(), libc::SYS_setsockopt);
            self.map
                .insert("SYS_getsockopt".to_string(), libc::SYS_getsockopt);
            self.map.insert("SYS_clone".to_string(), libc::SYS_clone);
            self.map.insert("SYS_fork".to_string(), libc::SYS_fork);
            self.map.insert("SYS_vfork".to_string(), libc::SYS_vfork);
            self.map.insert("SYS_execve".to_string(), libc::SYS_execve);
            self.map.insert("SYS_exit".to_string(), libc::SYS_exit);
            self.map.insert("SYS_wait4".to_string(), libc::SYS_wait4);
            self.map.insert("SYS_kill".to_string(), libc::SYS_kill);
            self.map.insert("SYS_uname".to_string(), libc::SYS_uname);
            self.map.insert("SYS_semget".to_string(), libc::SYS_semget);
            self.map.insert("SYS_semop".to_string(), libc::SYS_semop);
            self.map.insert("SYS_semctl".to_string(), libc::SYS_semctl);
            self.map.insert("SYS_shmdt".to_string(), libc::SYS_shmdt);
            self.map.insert("SYS_msgget".to_string(), libc::SYS_msgget);
            self.map.insert("SYS_msgsnd".to_string(), libc::SYS_msgsnd);
            self.map.insert("SYS_msgrcv".to_string(), libc::SYS_msgrcv);
            self.map.insert("SYS_msgctl".to_string(), libc::SYS_msgctl);
            self.map.insert("SYS_fcntl".to_string(), libc::SYS_fcntl);
            self.map.insert("SYS_flock".to_string(), libc::SYS_flock);
            self.map.insert("SYS_fsync".to_string(), libc::SYS_fsync);
            self.map
                .insert("SYS_fdatasync".to_string(), libc::SYS_fdatasync);
            self.map
                .insert("SYS_truncate".to_string(), libc::SYS_truncate);
            self.map
                .insert("SYS_ftruncate".to_string(), libc::SYS_ftruncate);
            self.map
                .insert("SYS_getdents".to_string(), libc::SYS_getdents);
            self.map.insert("SYS_getcwd".to_string(), libc::SYS_getcwd);
            self.map.insert("SYS_chdir".to_string(), libc::SYS_chdir);
            self.map.insert("SYS_fchdir".to_string(), libc::SYS_fchdir);
            self.map.insert("SYS_rename".to_string(), libc::SYS_rename);
            self.map.insert("SYS_mkdir".to_string(), libc::SYS_mkdir);
            self.map.insert("SYS_rmdir".to_string(), libc::SYS_rmdir);
            self.map.insert("SYS_creat".to_string(), libc::SYS_creat);
            self.map.insert("SYS_link".to_string(), libc::SYS_link);
            self.map.insert("SYS_unlink".to_string(), libc::SYS_unlink);
            self.map
                .insert("SYS_symlink".to_string(), libc::SYS_symlink);
            self.map
                .insert("SYS_readlink".to_string(), libc::SYS_readlink);
            self.map.insert("SYS_chmod".to_string(), libc::SYS_chmod);
            self.map.insert("SYS_fchmod".to_string(), libc::SYS_fchmod);
            self.map.insert("SYS_chown".to_string(), libc::SYS_chown);
            self.map.insert("SYS_fchown".to_string(), libc::SYS_fchown);
            self.map.insert("SYS_lchown".to_string(), libc::SYS_lchown);
            self.map.insert("SYS_umask".to_string(), libc::SYS_umask);
            self.map
                .insert("SYS_gettimeofday".to_string(), libc::SYS_gettimeofday);
            self.map
                .insert("SYS_getrlimit".to_string(), libc::SYS_getrlimit);
            self.map
                .insert("SYS_getrusage".to_string(), libc::SYS_getrusage);
            self.map
                .insert("SYS_sysinfo".to_string(), libc::SYS_sysinfo);
            self.map.insert("SYS_times".to_string(), libc::SYS_times);
            self.map.insert("SYS_ptrace".to_string(), libc::SYS_ptrace);
            self.map.insert("SYS_getuid".to_string(), libc::SYS_getuid);
            self.map.insert("SYS_syslog".to_string(), libc::SYS_syslog);
            self.map.insert("SYS_getgid".to_string(), libc::SYS_getgid);
            self.map.insert("SYS_setuid".to_string(), libc::SYS_setuid);
            self.map.insert("SYS_setgid".to_string(), libc::SYS_setgid);
            self.map
                .insert("SYS_geteuid".to_string(), libc::SYS_geteuid);
            self.map
                .insert("SYS_getegid".to_string(), libc::SYS_getegid);
            self.map
                .insert("SYS_setpgid".to_string(), libc::SYS_setpgid);
            self.map
                .insert("SYS_getppid".to_string(), libc::SYS_getppid);
            self.map
                .insert("SYS_getpgrp".to_string(), libc::SYS_getpgrp);
            self.map.insert("SYS_setsid".to_string(), libc::SYS_setsid);
            self.map
                .insert("SYS_setreuid".to_string(), libc::SYS_setreuid);
            self.map
                .insert("SYS_setregid".to_string(), libc::SYS_setregid);
            self.map
                .insert("SYS_getgroups".to_string(), libc::SYS_getgroups);
            self.map
                .insert("SYS_setgroups".to_string(), libc::SYS_setgroups);
            self.map
                .insert("SYS_setresuid".to_string(), libc::SYS_setresuid);
            self.map
                .insert("SYS_getresuid".to_string(), libc::SYS_getresuid);
            self.map
                .insert("SYS_setresgid".to_string(), libc::SYS_setresgid);
            self.map
                .insert("SYS_getresgid".to_string(), libc::SYS_getresgid);
            self.map
                .insert("SYS_getpgid".to_string(), libc::SYS_getpgid);
            self.map
                .insert("SYS_setfsuid".to_string(), libc::SYS_setfsuid);
            self.map
                .insert("SYS_setfsgid".to_string(), libc::SYS_setfsgid);
            self.map.insert("SYS_getsid".to_string(), libc::SYS_getsid);
            self.map.insert("SYS_capget".to_string(), libc::SYS_capget);
            self.map.insert("SYS_capset".to_string(), libc::SYS_capset);
            self.map
                .insert("SYS_rt_sigpending".to_string(), libc::SYS_rt_sigpending);
            self.map
                .insert("SYS_rt_sigtimedwait".to_string(), libc::SYS_rt_sigtimedwait);
            self.map
                .insert("SYS_rt_sigqueueinfo".to_string(), libc::SYS_rt_sigqueueinfo);
            self.map
                .insert("SYS_rt_sigsuspend".to_string(), libc::SYS_rt_sigsuspend);
            self.map
                .insert("SYS_sigaltstack".to_string(), libc::SYS_sigaltstack);
            self.map.insert("SYS_utime".to_string(), libc::SYS_utime);
            self.map.insert("SYS_mknod".to_string(), libc::SYS_mknod);
            self.map.insert("SYS_uselib".to_string(), libc::SYS_uselib);
            self.map
                .insert("SYS_personality".to_string(), libc::SYS_personality);
            self.map.insert("SYS_ustat".to_string(), libc::SYS_ustat);
            self.map.insert("SYS_statfs".to_string(), libc::SYS_statfs);
            self.map
                .insert("SYS_fstatfs".to_string(), libc::SYS_fstatfs);
            self.map.insert("SYS_sysfs".to_string(), libc::SYS_sysfs);
            self.map
                .insert("SYS_getpriority".to_string(), libc::SYS_getpriority);
            self.map
                .insert("SYS_setpriority".to_string(), libc::SYS_setpriority);
            self.map
                .insert("SYS_sched_setparam".to_string(), libc::SYS_sched_setparam);
            self.map
                .insert("SYS_sched_getparam".to_string(), libc::SYS_sched_getparam);
            self.map.insert(
                "SYS_sched_setscheduler".to_string(),
                libc::SYS_sched_setscheduler,
            );
            self.map.insert(
                "SYS_sched_getscheduler".to_string(),
                libc::SYS_sched_getscheduler,
            );
            self.map.insert(
                "SYS_sched_get_priority_max".to_string(),
                libc::SYS_sched_get_priority_max,
            );
            self.map.insert(
                "SYS_sched_get_priority_min".to_string(),
                libc::SYS_sched_get_priority_min,
            );
            self.map.insert(
                "SYS_sched_rr_get_interval".to_string(),
                libc::SYS_sched_rr_get_interval,
            );
            self.map.insert("SYS_mlock".to_string(), libc::SYS_mlock);
            self.map
                .insert("SYS_munlock".to_string(), libc::SYS_munlock);
            self.map
                .insert("SYS_mlockall".to_string(), libc::SYS_mlockall);
            self.map
                .insert("SYS_munlockall".to_string(), libc::SYS_munlockall);
            self.map
                .insert("SYS_vhangup".to_string(), libc::SYS_vhangup);
            self.map
                .insert("SYS_modify_ldt".to_string(), libc::SYS_modify_ldt);
            self.map
                .insert("SYS_pivot_root".to_string(), libc::SYS_pivot_root);
            self.map
                .insert("SYS__sysctl".to_string(), libc::SYS__sysctl);
            self.map.insert("SYS_prctl".to_string(), libc::SYS_prctl);
            self.map
                .insert("SYS_arch_prctl".to_string(), libc::SYS_arch_prctl);
            self.map
                .insert("SYS_adjtimex".to_string(), libc::SYS_adjtimex);
            self.map
                .insert("SYS_setrlimit".to_string(), libc::SYS_setrlimit);
            self.map.insert("SYS_chroot".to_string(), libc::SYS_chroot);
            self.map.insert("SYS_sync".to_string(), libc::SYS_sync);
            self.map.insert("SYS_acct".to_string(), libc::SYS_acct);
            self.map
                .insert("SYS_settimeofday".to_string(), libc::SYS_settimeofday);
            self.map.insert("SYS_mount".to_string(), libc::SYS_mount);
            self.map
                .insert("SYS_umount2".to_string(), libc::SYS_umount2);
            self.map.insert("SYS_swapon".to_string(), libc::SYS_swapon);
            self.map
                .insert("SYS_swapoff".to_string(), libc::SYS_swapoff);
            self.map.insert("SYS_reboot".to_string(), libc::SYS_reboot);
            self.map
                .insert("SYS_sethostname".to_string(), libc::SYS_sethostname);
            self.map
                .insert("SYS_setdomainname".to_string(), libc::SYS_setdomainname);
            self.map.insert("SYS_iopl".to_string(), libc::SYS_iopl);
            self.map.insert("SYS_ioperm".to_string(), libc::SYS_ioperm);
            self.map
                .insert("SYS_create_module".to_string(), libc::SYS_create_module);
            self.map
                .insert("SYS_init_module".to_string(), libc::SYS_init_module);
            self.map
                .insert("SYS_delete_module".to_string(), libc::SYS_delete_module);
            self.map
                .insert("SYS_get_kernel_syms".to_string(), libc::SYS_get_kernel_syms);
            self.map
                .insert("SYS_query_module".to_string(), libc::SYS_query_module);
            self.map
                .insert("SYS_quotactl".to_string(), libc::SYS_quotactl);
            self.map
                .insert("SYS_nfsservctl".to_string(), libc::SYS_nfsservctl);
            self.map
                .insert("SYS_getpmsg".to_string(), libc::SYS_getpmsg);
            self.map
                .insert("SYS_putpmsg".to_string(), libc::SYS_putpmsg);
            self.map
                .insert("SYS_afs_syscall".to_string(), libc::SYS_afs_syscall);
            self.map
                .insert("SYS_tuxcall".to_string(), libc::SYS_tuxcall);
            self.map
                .insert("SYS_security".to_string(), libc::SYS_security);
            self.map.insert("SYS_gettid".to_string(), libc::SYS_gettid);
            self.map
                .insert("SYS_readahead".to_string(), libc::SYS_readahead);
            self.map
                .insert("SYS_setxattr".to_string(), libc::SYS_setxattr);
            self.map
                .insert("SYS_lsetxattr".to_string(), libc::SYS_lsetxattr);
            self.map
                .insert("SYS_fsetxattr".to_string(), libc::SYS_fsetxattr);
            self.map
                .insert("SYS_getxattr".to_string(), libc::SYS_getxattr);
            self.map
                .insert("SYS_lgetxattr".to_string(), libc::SYS_lgetxattr);
            self.map
                .insert("SYS_fgetxattr".to_string(), libc::SYS_fgetxattr);
            self.map
                .insert("SYS_listxattr".to_string(), libc::SYS_listxattr);
            self.map
                .insert("SYS_llistxattr".to_string(), libc::SYS_llistxattr);
            self.map
                .insert("SYS_flistxattr".to_string(), libc::SYS_flistxattr);
            self.map
                .insert("SYS_removexattr".to_string(), libc::SYS_removexattr);
            self.map
                .insert("SYS_lremovexattr".to_string(), libc::SYS_lremovexattr);
            self.map
                .insert("SYS_fremovexattr".to_string(), libc::SYS_fremovexattr);
            self.map.insert("SYS_tkill".to_string(), libc::SYS_tkill);
            self.map.insert("SYS_time".to_string(), libc::SYS_time);
            self.map.insert("SYS_futex".to_string(), libc::SYS_futex);
            self.map.insert(
                "SYS_sched_setaffinity".to_string(),
                libc::SYS_sched_setaffinity,
            );
            self.map.insert(
                "SYS_sched_getaffinity".to_string(),
                libc::SYS_sched_getaffinity,
            );
            self.map
                .insert("SYS_set_thread_area".to_string(), libc::SYS_set_thread_area);
            self.map
                .insert("SYS_io_setup".to_string(), libc::SYS_io_setup);
            self.map
                .insert("SYS_io_destroy".to_string(), libc::SYS_io_destroy);
            self.map
                .insert("SYS_io_getevents".to_string(), libc::SYS_io_getevents);
            self.map
                .insert("SYS_io_submit".to_string(), libc::SYS_io_submit);
            self.map
                .insert("SYS_io_cancel".to_string(), libc::SYS_io_cancel);
            self.map
                .insert("SYS_get_thread_area".to_string(), libc::SYS_get_thread_area);
            self.map
                .insert("SYS_lookup_dcookie".to_string(), libc::SYS_lookup_dcookie);
            self.map
                .insert("SYS_epoll_create".to_string(), libc::SYS_epoll_create);
            self.map
                .insert("SYS_epoll_ctl_old".to_string(), libc::SYS_epoll_ctl_old);
            self.map
                .insert("SYS_epoll_wait_old".to_string(), libc::SYS_epoll_wait_old);
            self.map.insert(
                "SYS_remap_file_pages".to_string(),
                libc::SYS_remap_file_pages,
            );
            self.map
                .insert("SYS_getdents64".to_string(), libc::SYS_getdents64);
            self.map
                .insert("SYS_set_tid_address".to_string(), libc::SYS_set_tid_address);
            self.map
                .insert("SYS_restart_syscall".to_string(), libc::SYS_restart_syscall);
            self.map
                .insert("SYS_semtimedop".to_string(), libc::SYS_semtimedop);
            self.map
                .insert("SYS_fadvise64".to_string(), libc::SYS_fadvise64);
            self.map
                .insert("SYS_timer_create".to_string(), libc::SYS_timer_create);
            self.map
                .insert("SYS_timer_settime".to_string(), libc::SYS_timer_settime);
            self.map
                .insert("SYS_timer_gettime".to_string(), libc::SYS_timer_gettime);
            self.map.insert(
                "SYS_timer_getoverrun".to_string(),
                libc::SYS_timer_getoverrun,
            );
            self.map
                .insert("SYS_timer_delete".to_string(), libc::SYS_timer_delete);
            self.map
                .insert("SYS_clock_settime".to_string(), libc::SYS_clock_settime);
            self.map
                .insert("SYS_clock_gettime".to_string(), libc::SYS_clock_gettime);
            self.map
                .insert("SYS_clock_getres".to_string(), libc::SYS_clock_getres);
            self.map
                .insert("SYS_clock_nanosleep".to_string(), libc::SYS_clock_nanosleep);
            self.map
                .insert("SYS_exit_group".to_string(), libc::SYS_exit_group);
            self.map
                .insert("SYS_epoll_wait".to_string(), libc::SYS_epoll_wait);
            self.map
                .insert("SYS_epoll_ctl".to_string(), libc::SYS_epoll_ctl);
            self.map.insert("SYS_tgkill".to_string(), libc::SYS_tgkill);
            self.map.insert("SYS_utimes".to_string(), libc::SYS_utimes);
            self.map
                .insert("SYS_vserver".to_string(), libc::SYS_vserver);
            self.map.insert("SYS_mbind".to_string(), libc::SYS_mbind);
            self.map
                .insert("SYS_set_mempolicy".to_string(), libc::SYS_set_mempolicy);
            self.map
                .insert("SYS_get_mempolicy".to_string(), libc::SYS_get_mempolicy);
            self.map
                .insert("SYS_mq_open".to_string(), libc::SYS_mq_open);
            self.map
                .insert("SYS_mq_unlink".to_string(), libc::SYS_mq_unlink);
            self.map
                .insert("SYS_mq_timedsend".to_string(), libc::SYS_mq_timedsend);
            self.map
                .insert("SYS_mq_timedreceive".to_string(), libc::SYS_mq_timedreceive);
            self.map
                .insert("SYS_mq_notify".to_string(), libc::SYS_mq_notify);
            self.map
                .insert("SYS_mq_getsetattr".to_string(), libc::SYS_mq_getsetattr);
            self.map
                .insert("SYS_kexec_load".to_string(), libc::SYS_kexec_load);
            self.map.insert("SYS_waitid".to_string(), libc::SYS_waitid);
            self.map
                .insert("SYS_add_key".to_string(), libc::SYS_add_key);
            self.map
                .insert("SYS_request_key".to_string(), libc::SYS_request_key);
            self.map.insert("SYS_keyctl".to_string(), libc::SYS_keyctl);
            self.map
                .insert("SYS_ioprio_set".to_string(), libc::SYS_ioprio_set);
            self.map
                .insert("SYS_ioprio_get".to_string(), libc::SYS_ioprio_get);
            self.map
                .insert("SYS_inotify_init".to_string(), libc::SYS_inotify_init);
            self.map.insert(
                "SYS_inotify_add_watch".to_string(),
                libc::SYS_inotify_add_watch,
            );
            self.map.insert(
                "SYS_inotify_rm_watch".to_string(),
                libc::SYS_inotify_rm_watch,
            );
            self.map
                .insert("SYS_migrate_pages".to_string(), libc::SYS_migrate_pages);
            self.map.insert("SYS_openat".to_string(), libc::SYS_openat);
            self.map
                .insert("SYS_mkdirat".to_string(), libc::SYS_mkdirat);
            self.map
                .insert("SYS_mknodat".to_string(), libc::SYS_mknodat);
            self.map
                .insert("SYS_fchownat".to_string(), libc::SYS_fchownat);
            self.map
                .insert("SYS_futimesat".to_string(), libc::SYS_futimesat);
            self.map
                .insert("SYS_newfstatat".to_string(), libc::SYS_newfstatat);
            self.map
                .insert("SYS_unlinkat".to_string(), libc::SYS_unlinkat);
            self.map
                .insert("SYS_renameat".to_string(), libc::SYS_renameat);
            self.map.insert("SYS_linkat".to_string(), libc::SYS_linkat);
            self.map
                .insert("SYS_symlinkat".to_string(), libc::SYS_symlinkat);
            self.map
                .insert("SYS_readlinkat".to_string(), libc::SYS_readlinkat);
            self.map
                .insert("SYS_fchmodat".to_string(), libc::SYS_fchmodat);
            self.map
                .insert("SYS_faccessat".to_string(), libc::SYS_faccessat);
            self.map
                .insert("SYS_pselect6".to_string(), libc::SYS_pselect6);
            self.map.insert("SYS_ppoll".to_string(), libc::SYS_ppoll);
            self.map
                .insert("SYS_unshare".to_string(), libc::SYS_unshare);
            self.map
                .insert("SYS_set_robust_list".to_string(), libc::SYS_set_robust_list);
            self.map
                .insert("SYS_get_robust_list".to_string(), libc::SYS_get_robust_list);
            self.map.insert("SYS_splice".to_string(), libc::SYS_splice);
            self.map.insert("SYS_tee".to_string(), libc::SYS_tee);
            self.map
                .insert("SYS_sync_file_range".to_string(), libc::SYS_sync_file_range);
            self.map
                .insert("SYS_vmsplice".to_string(), libc::SYS_vmsplice);
            self.map
                .insert("SYS_move_pages".to_string(), libc::SYS_move_pages);
            self.map
                .insert("SYS_utimensat".to_string(), libc::SYS_utimensat);
            self.map
                .insert("SYS_epoll_pwait".to_string(), libc::SYS_epoll_pwait);
            self.map
                .insert("SYS_signalfd".to_string(), libc::SYS_signalfd);
            self.map
                .insert("SYS_timerfd_create".to_string(), libc::SYS_timerfd_create);
            self.map
                .insert("SYS_eventfd".to_string(), libc::SYS_eventfd);
            self.map
                .insert("SYS_fallocate".to_string(), libc::SYS_fallocate);
            self.map
                .insert("SYS_timerfd_settime".to_string(), libc::SYS_timerfd_settime);
            self.map
                .insert("SYS_timerfd_gettime".to_string(), libc::SYS_timerfd_gettime);
            self.map
                .insert("SYS_accept4".to_string(), libc::SYS_accept4);
            self.map
                .insert("SYS_signalfd4".to_string(), libc::SYS_signalfd4);
            self.map
                .insert("SYS_eventfd2".to_string(), libc::SYS_eventfd2);
            self.map
                .insert("SYS_epoll_create1".to_string(), libc::SYS_epoll_create1);
            self.map.insert("SYS_dup3".to_string(), libc::SYS_dup3);
            self.map.insert("SYS_pipe2".to_string(), libc::SYS_pipe2);
            self.map
                .insert("SYS_inotify_init1".to_string(), libc::SYS_inotify_init1);
            self.map.insert("SYS_preadv".to_string(), libc::SYS_preadv);
            self.map
                .insert("SYS_pwritev".to_string(), libc::SYS_pwritev);
            self.map.insert(
                "SYS_rt_tgsigqueueinfo".to_string(),
                libc::SYS_rt_tgsigqueueinfo,
            );
            self.map
                .insert("SYS_perf_event_open".to_string(), libc::SYS_perf_event_open);
            self.map
                .insert("SYS_recvmmsg".to_string(), libc::SYS_recvmmsg);
            self.map
                .insert("SYS_fanotify_init".to_string(), libc::SYS_fanotify_init);
            self.map
                .insert("SYS_fanotify_mark".to_string(), libc::SYS_fanotify_mark);
            self.map
                .insert("SYS_prlimit64".to_string(), libc::SYS_prlimit64);
            self.map.insert(
                "SYS_name_to_handle_at".to_string(),
                libc::SYS_name_to_handle_at,
            );
            self.map.insert(
                "SYS_open_by_handle_at".to_string(),
                libc::SYS_open_by_handle_at,
            );
            self.map
                .insert("SYS_clock_adjtime".to_string(), libc::SYS_clock_adjtime);
            self.map.insert("SYS_syncfs".to_string(), libc::SYS_syncfs);
            self.map
                .insert("SYS_sendmmsg".to_string(), libc::SYS_sendmmsg);
            self.map.insert("SYS_setns".to_string(), libc::SYS_setns);
            self.map.insert("SYS_getcpu".to_string(), libc::SYS_getcpu);
            self.map.insert(
                "SYS_process_vm_readv".to_string(),
                libc::SYS_process_vm_readv,
            );
            self.map.insert(
                "SYS_process_vm_writev".to_string(),
                libc::SYS_process_vm_writev,
            );
            self.map.insert("SYS_kcmp".to_string(), libc::SYS_kcmp);
            self.map
                .insert("SYS_finit_module".to_string(), libc::SYS_finit_module);
            self.map
                .insert("SYS_sched_setattr".to_string(), libc::SYS_sched_setattr);
            self.map
                .insert("SYS_sched_getattr".to_string(), libc::SYS_sched_getattr);
            self.map
                .insert("SYS_renameat2".to_string(), libc::SYS_renameat2);
            self.map
                .insert("SYS_seccomp".to_string(), libc::SYS_seccomp);
            self.map
                .insert("SYS_getrandom".to_string(), libc::SYS_getrandom);
            self.map
                .insert("SYS_memfd_create".to_string(), libc::SYS_memfd_create);
            self.map
                .insert("SYS_kexec_file_load".to_string(), libc::SYS_kexec_file_load);
            self.map.insert("SYS_bpf".to_string(), libc::SYS_bpf);
            self.map
                .insert("SYS_execveat".to_string(), libc::SYS_execveat);
            self.map
                .insert("SYS_userfaultfd".to_string(), libc::SYS_userfaultfd);
            self.map
                .insert("SYS_membarrier".to_string(), libc::SYS_membarrier);
            self.map.insert("SYS_mlock2".to_string(), libc::SYS_mlock2);
            self.map
                .insert("SYS_copy_file_range".to_string(), libc::SYS_copy_file_range);
            self.map
                .insert("SYS_preadv2".to_string(), libc::SYS_preadv2);
            self.map
                .insert("SYS_pwritev2".to_string(), libc::SYS_pwritev2);
            self.map
                .insert("SYS_pkey_mprotect".to_string(), libc::SYS_pkey_mprotect);
            self.map
                .insert("SYS_pkey_alloc".to_string(), libc::SYS_pkey_alloc);
            self.map
                .insert("SYS_pkey_free".to_string(), libc::SYS_pkey_free);
            self.map.insert("SYS_statx".to_string(), libc::SYS_statx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SyscallTable;

    #[test]
    fn test_get_syscall_nr() {
        // get number for a valid syscall
        let instance = SyscallTable::new(std::env::consts::ARCH.to_string());

        assert_eq!(
            instance.get_syscall_nr("SYS_close").unwrap(),
            libc::SYS_close
        );

        // invalid syscall name
        assert!(instance.get_syscall_nr("sdffs").is_none());
    }
}
