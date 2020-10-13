// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

/// Creates and owns a mapping from the arch-specific syscall name to the right number.
#[derive(Debug)]
pub(crate) struct SyscallTable {
    map: HashMap<String, i64>,
    arch: String,
}

impl SyscallTable {
    pub fn new(arch: String) -> Self {
        let mut instance = Self {
            arch,
            map: HashMap::with_capacity(332), // nr of syscalls for x86_64 (upper bound)
        };

        instance.populate_map();

        instance
    }

    /// Returns the arch-specific syscall number based on the given name.
    /// Adheres to the "SYS_*" notation.
    pub fn get_syscall_nr(&self, sys_name: &str) -> Option<i64> {
        self.map.get(sys_name).copied()
    }

    // We need to create an architecture-specific map since the set of
    // possible syscalls is architecture-dependent. We can't just map to their
    // corresponding libc constant.
    fn populate_map(&mut self) {
        if self.arch == "aarch64" {
            self.map.insert("SYS_io_setup".to_string(), 0);
            self.map.insert("SYS_io_destroy".to_string(), 1);
            self.map.insert("SYS_io_submit".to_string(), 2);
            self.map.insert("SYS_io_cancel".to_string(), 3);
            self.map.insert("SYS_io_getevents".to_string(), 4);
            self.map.insert("SYS_setxattr".to_string(), 5);
            self.map.insert("SYS_lsetxattr".to_string(), 6);
            self.map.insert("SYS_fsetxattr".to_string(), 7);
            self.map.insert("SYS_getxattr".to_string(), 8);
            self.map.insert("SYS_lgetxattr".to_string(), 9);
            self.map.insert("SYS_fgetxattr".to_string(), 10);
            self.map.insert("SYS_listxattr".to_string(), 11);
            self.map.insert("SYS_llistxattr".to_string(), 12);
            self.map.insert("SYS_flistxattr".to_string(), 13);
            self.map.insert("SYS_removexattr".to_string(), 14);
            self.map.insert("SYS_lremovexattr".to_string(), 15);
            self.map.insert("SYS_fremovexattr".to_string(), 16);
            self.map.insert("SYS_getcwd".to_string(), 17);
            self.map.insert("SYS_lookup_dcookie".to_string(), 18);
            self.map.insert("SYS_eventfd2".to_string(), 19);
            self.map.insert("SYS_epoll_create1".to_string(), 20);
            self.map.insert("SYS_epoll_ctl".to_string(), 21);
            self.map.insert("SYS_epoll_pwait".to_string(), 22);
            self.map.insert("SYS_dup".to_string(), 23);
            self.map.insert("SYS_dup3".to_string(), 24);
            self.map.insert("SYS_fcntl".to_string(), 25);
            self.map.insert("SYS_inotify_init1".to_string(), 26);
            self.map.insert("SYS_inotify_add_watch".to_string(), 27);
            self.map.insert("SYS_inotify_rm_watch".to_string(), 28);
            self.map.insert("SYS_ioctl".to_string(), 29);
            self.map.insert("SYS_ioprio_set".to_string(), 30);
            self.map.insert("SYS_ioprio_get".to_string(), 31);
            self.map.insert("SYS_flock".to_string(), 32);
            self.map.insert("SYS_mknodat".to_string(), 33);
            self.map.insert("SYS_mkdirat".to_string(), 34);
            self.map.insert("SYS_unlinkat".to_string(), 35);
            self.map.insert("SYS_symlinkat".to_string(), 36);
            self.map.insert("SYS_linkat".to_string(), 37);
            self.map.insert("SYS_renameat".to_string(), 38);
            self.map.insert("SYS_umount2".to_string(), 39);
            self.map.insert("SYS_mount".to_string(), 40);
            self.map.insert("SYS_pivot_root".to_string(), 41);
            self.map.insert("SYS_nfsservctl".to_string(), 42);
            self.map.insert("SYS_statfs".to_string(), 43);
            self.map.insert("SYS_fstatfs".to_string(), 44);
            self.map.insert("SYS_truncate".to_string(), 45);
            self.map.insert("SYS_ftruncate".to_string(), 46);
            self.map.insert("SYS_fallocate".to_string(), 47);
            self.map.insert("SYS_faccessat".to_string(), 48);
            self.map.insert("SYS_chdir".to_string(), 49);
            self.map.insert("SYS_fchdir".to_string(), 50);
            self.map.insert("SYS_chroot".to_string(), 51);
            self.map.insert("SYS_fchmod".to_string(), 52);
            self.map.insert("SYS_fchmodat".to_string(), 53);
            self.map.insert("SYS_fchownat".to_string(), 54);
            self.map.insert("SYS_fchown".to_string(), 55);
            self.map.insert("SYS_openat".to_string(), 56);
            self.map.insert("SYS_close".to_string(), 57);
            self.map.insert("SYS_vhangup".to_string(), 58);
            self.map.insert("SYS_pipe2".to_string(), 59);
            self.map.insert("SYS_quotactl".to_string(), 60);
            self.map.insert("SYS_getdents64".to_string(), 61);
            self.map.insert("SYS_lseek".to_string(), 62);
            self.map.insert("SYS_read".to_string(), 63);
            self.map.insert("SYS_write".to_string(), 64);
            self.map.insert("SYS_readv".to_string(), 65);
            self.map.insert("SYS_writev".to_string(), 66);
            self.map.insert("SYS_pread64".to_string(), 67);
            self.map.insert("SYS_pwrite64".to_string(), 68);
            self.map.insert("SYS_preadv".to_string(), 69);
            self.map.insert("SYS_pwritev".to_string(), 70);
            self.map.insert("SYS_pselect6".to_string(), 72);
            self.map.insert("SYS_ppoll".to_string(), 73);
            self.map.insert("SYS_signalfd4".to_string(), 74);
            self.map.insert("SYS_vmsplice".to_string(), 75);
            self.map.insert("SYS_splice".to_string(), 76);
            self.map.insert("SYS_tee".to_string(), 77);
            self.map.insert("SYS_readlinkat".to_string(), 78);
            self.map.insert("SYS_newfstatat".to_string(), 79);
            self.map.insert("SYS_fstat".to_string(), 80);
            self.map.insert("SYS_sync".to_string(), 81);
            self.map.insert("SYS_fsync".to_string(), 82);
            self.map.insert("SYS_fdatasync".to_string(), 83);
            self.map.insert("SYS_sync_file_range".to_string(), 84);
            self.map.insert("SYS_timerfd_create".to_string(), 85);
            self.map.insert("SYS_timerfd_settime".to_string(), 86);
            self.map.insert("SYS_timerfd_gettime".to_string(), 87);
            self.map.insert("SYS_utimensat".to_string(), 88);
            self.map.insert("SYS_acct".to_string(), 89);
            self.map.insert("SYS_capget".to_string(), 90);
            self.map.insert("SYS_capset".to_string(), 91);
            self.map.insert("SYS_personality".to_string(), 92);
            self.map.insert("SYS_exit".to_string(), 93);
            self.map.insert("SYS_exit_group".to_string(), 94);
            self.map.insert("SYS_waitid".to_string(), 95);
            self.map.insert("SYS_set_tid_address".to_string(), 96);
            self.map.insert("SYS_unshare".to_string(), 97);
            self.map.insert("SYS_futex".to_string(), 98);
            self.map.insert("SYS_set_robust_list".to_string(), 99);
            self.map.insert("SYS_get_robust_list".to_string(), 100);
            self.map.insert("SYS_nanosleep".to_string(), 101);
            self.map.insert("SYS_getitimer".to_string(), 102);
            self.map.insert("SYS_setitimer".to_string(), 103);
            self.map.insert("SYS_kexec_load".to_string(), 104);
            self.map.insert("SYS_init_module".to_string(), 105);
            self.map.insert("SYS_delete_module".to_string(), 106);
            self.map.insert("SYS_timer_create".to_string(), 107);
            self.map.insert("SYS_timer_gettime".to_string(), 108);
            self.map.insert("SYS_timer_getoverrun".to_string(), 109);
            self.map.insert("SYS_timer_settime".to_string(), 110);
            self.map.insert("SYS_timer_delete".to_string(), 111);
            self.map.insert("SYS_clock_settime".to_string(), 112);
            self.map.insert("SYS_clock_gettime".to_string(), 113);
            self.map.insert("SYS_clock_getres".to_string(), 114);
            self.map.insert("SYS_clock_nanosleep".to_string(), 115);
            self.map.insert("SYS_syslog".to_string(), 116);
            self.map.insert("SYS_ptrace".to_string(), 117);
            self.map.insert("SYS_sched_setparam".to_string(), 118);
            self.map.insert("SYS_sched_setscheduler".to_string(), 119);
            self.map.insert("SYS_sched_getscheduler".to_string(), 120);
            self.map.insert("SYS_sched_getparam".to_string(), 121);
            self.map.insert("SYS_sched_setaffinity".to_string(), 122);
            self.map.insert("SYS_sched_getaffinity".to_string(), 123);
            self.map.insert("SYS_sched_yield".to_string(), 124);
            self.map
                .insert("SYS_sched_get_priority_max".to_string(), 125);
            self.map
                .insert("SYS_sched_get_priority_min".to_string(), 126);
            self.map
                .insert("SYS_sched_rr_get_interval".to_string(), 127);
            self.map.insert("SYS_restart_syscall".to_string(), 128);
            self.map.insert("SYS_kill".to_string(), 129);
            self.map.insert("SYS_tkill".to_string(), 130);
            self.map.insert("SYS_tgkill".to_string(), 131);
            self.map.insert("SYS_sigaltstack".to_string(), 132);
            self.map.insert("SYS_rt_sigsuspend".to_string(), 133);
            self.map.insert("SYS_rt_sigaction".to_string(), 134);
            self.map.insert("SYS_rt_sigprocmask".to_string(), 135);
            self.map.insert("SYS_rt_sigpending".to_string(), 136);
            self.map.insert("SYS_rt_sigtimedwait".to_string(), 137);
            self.map.insert("SYS_rt_sigqueueinfo".to_string(), 138);
            self.map.insert("SYS_rt_sigreturn".to_string(), 139);
            self.map.insert("SYS_setpriority".to_string(), 140);
            self.map.insert("SYS_getpriority".to_string(), 141);
            self.map.insert("SYS_reboot".to_string(), 142);
            self.map.insert("SYS_setregid".to_string(), 143);
            self.map.insert("SYS_setgid".to_string(), 144);
            self.map.insert("SYS_setreuid".to_string(), 145);
            self.map.insert("SYS_setuid".to_string(), 146);
            self.map.insert("SYS_setresuid".to_string(), 147);
            self.map.insert("SYS_getresuid".to_string(), 148);
            self.map.insert("SYS_setresgid".to_string(), 149);
            self.map.insert("SYS_getresgid".to_string(), 150);
            self.map.insert("SYS_setfsuid".to_string(), 151);
            self.map.insert("SYS_setfsgid".to_string(), 152);
            self.map.insert("SYS_times".to_string(), 153);
            self.map.insert("SYS_setpgid".to_string(), 154);
            self.map.insert("SYS_getpgid".to_string(), 155);
            self.map.insert("SYS_getsid".to_string(), 156);
            self.map.insert("SYS_setsid".to_string(), 157);
            self.map.insert("SYS_getgroups".to_string(), 158);
            self.map.insert("SYS_setgroups".to_string(), 159);
            self.map.insert("SYS_uname".to_string(), 160);
            self.map.insert("SYS_sethostname".to_string(), 161);
            self.map.insert("SYS_setdomainname".to_string(), 162);
            self.map.insert("SYS_getrlimit".to_string(), 163);
            self.map.insert("SYS_setrlimit".to_string(), 164);
            self.map.insert("SYS_getrusage".to_string(), 165);
            self.map.insert("SYS_umask".to_string(), 166);
            self.map.insert("SYS_prctl".to_string(), 167);
            self.map.insert("SYS_getcpu".to_string(), 168);
            self.map.insert("SYS_gettimeofday".to_string(), 169);
            self.map.insert("SYS_settimeofday".to_string(), 170);
            self.map.insert("SYS_adjtimex".to_string(), 171);
            self.map.insert("SYS_getpid".to_string(), 172);
            self.map.insert("SYS_getppid".to_string(), 173);
            self.map.insert("SYS_getuid".to_string(), 174);
            self.map.insert("SYS_geteuid".to_string(), 175);
            self.map.insert("SYS_getgid".to_string(), 176);
            self.map.insert("SYS_getegid".to_string(), 177);
            self.map.insert("SYS_gettid".to_string(), 178);
            self.map.insert("SYS_sysinfo".to_string(), 179);
            self.map.insert("SYS_mq_open".to_string(), 180);
            self.map.insert("SYS_mq_unlink".to_string(), 181);
            self.map.insert("SYS_mq_timedsend".to_string(), 182);
            self.map.insert("SYS_mq_timedreceive".to_string(), 183);
            self.map.insert("SYS_mq_notify".to_string(), 184);
            self.map.insert("SYS_mq_getsetattr".to_string(), 185);
            self.map.insert("SYS_msgget".to_string(), 186);
            self.map.insert("SYS_msgctl".to_string(), 187);
            self.map.insert("SYS_msgrcv".to_string(), 188);
            self.map.insert("SYS_msgsnd".to_string(), 189);
            self.map.insert("SYS_semget".to_string(), 190);
            self.map.insert("SYS_semctl".to_string(), 191);
            self.map.insert("SYS_semtimedop".to_string(), 192);
            self.map.insert("SYS_semop".to_string(), 193);
            self.map.insert("SYS_shmget".to_string(), 194);
            self.map.insert("SYS_shmctl".to_string(), 195);
            self.map.insert("SYS_shmat".to_string(), 196);
            self.map.insert("SYS_shmdt".to_string(), 197);
            self.map.insert("SYS_socket".to_string(), 198);
            self.map.insert("SYS_socketpair".to_string(), 199);
            self.map.insert("SYS_bind".to_string(), 200);
            self.map.insert("SYS_listen".to_string(), 201);
            self.map.insert("SYS_accept".to_string(), 202);
            self.map.insert("SYS_connect".to_string(), 203);
            self.map.insert("SYS_getsockname".to_string(), 204);
            self.map.insert("SYS_getpeername".to_string(), 205);
            self.map.insert("SYS_sendto".to_string(), 206);
            self.map.insert("SYS_recvfrom".to_string(), 207);
            self.map.insert("SYS_setsockopt".to_string(), 208);
            self.map.insert("SYS_getsockopt".to_string(), 209);
            self.map.insert("SYS_shutdown".to_string(), 210);
            self.map.insert("SYS_sendmsg".to_string(), 211);
            self.map.insert("SYS_recvmsg".to_string(), 212);
            self.map.insert("SYS_readahead".to_string(), 213);
            self.map.insert("SYS_brk".to_string(), 214);
            self.map.insert("SYS_munmap".to_string(), 215);
            self.map.insert("SYS_mremap".to_string(), 216);
            self.map.insert("SYS_add_key".to_string(), 217);
            self.map.insert("SYS_request_key".to_string(), 218);
            self.map.insert("SYS_keyctl".to_string(), 219);
            self.map.insert("SYS_clone".to_string(), 220);
            self.map.insert("SYS_execve".to_string(), 221);
            self.map.insert("SYS_mmap".to_string(), 222);
            self.map.insert("SYS_swapon".to_string(), 224);
            self.map.insert("SYS_swapoff".to_string(), 225);
            self.map.insert("SYS_mprotect".to_string(), 226);
            self.map.insert("SYS_msync".to_string(), 227);
            self.map.insert("SYS_mlock".to_string(), 228);
            self.map.insert("SYS_munlock".to_string(), 229);
            self.map.insert("SYS_mlockall".to_string(), 230);
            self.map.insert("SYS_munlockall".to_string(), 231);
            self.map.insert("SYS_mincore".to_string(), 232);
            self.map.insert("SYS_madvise".to_string(), 233);
            self.map.insert("SYS_remap_file_pages".to_string(), 234);
            self.map.insert("SYS_mbind".to_string(), 235);
            self.map.insert("SYS_get_mempolicy".to_string(), 236);
            self.map.insert("SYS_set_mempolicy".to_string(), 237);
            self.map.insert("SYS_migrate_pages".to_string(), 238);
            self.map.insert("SYS_move_pages".to_string(), 239);
            self.map.insert("SYS_rt_tgsigqueueinfo".to_string(), 240);
            self.map.insert("SYS_perf_event_open".to_string(), 241);
            self.map.insert("SYS_accept4".to_string(), 242);
            self.map.insert("SYS_recvmmsg".to_string(), 243);
            self.map.insert("SYS_wait4".to_string(), 260);
            self.map.insert("SYS_prlimit64".to_string(), 261);
            self.map.insert("SYS_fanotify_init".to_string(), 262);
            self.map.insert("SYS_fanotify_mark".to_string(), 263);
            self.map.insert("SYS_name_to_handle_at".to_string(), 264);
            self.map.insert("SYS_open_by_handle_at".to_string(), 265);
            self.map.insert("SYS_clock_adjtime".to_string(), 266);
            self.map.insert("SYS_syncfs".to_string(), 267);
            self.map.insert("SYS_setns".to_string(), 268);
            self.map.insert("SYS_sendmmsg".to_string(), 269);
            self.map.insert("SYS_process_vm_readv".to_string(), 270);
            self.map.insert("SYS_process_vm_writev".to_string(), 271);
            self.map.insert("SYS_kcmp".to_string(), 272);
            self.map.insert("SYS_finit_module".to_string(), 273);
            self.map.insert("SYS_sched_setattr".to_string(), 274);
            self.map.insert("SYS_sched_getattr".to_string(), 275);
            self.map.insert("SYS_renameat2".to_string(), 276);
            self.map.insert("SYS_seccomp".to_string(), 277);
            self.map.insert("SYS_getrandom".to_string(), 278);
            self.map.insert("SYS_memfd_create".to_string(), 279);
            self.map.insert("SYS_bpf".to_string(), 280);
            self.map.insert("SYS_execveat".to_string(), 281);
            self.map.insert("SYS_userfaultfd".to_string(), 282);
            self.map.insert("SYS_membarrier".to_string(), 283);
            self.map.insert("SYS_mlock2".to_string(), 284);
            self.map.insert("SYS_copy_file_range".to_string(), 285);
            self.map.insert("SYS_preadv2".to_string(), 286);
            self.map.insert("SYS_pwritev2".to_string(), 287);
            self.map.insert("SYS_pkey_mprotect".to_string(), 288);
            self.map.insert("SYS_pkey_alloc".to_string(), 289);
            self.map.insert("SYS_pkey_free".to_string(), 290);
            self.map.insert("SYS_statx".to_string(), 291);
        }

        if self.arch == "x86_64" {
            self.map.insert("SYS_read".to_string(), 0);
            self.map.insert("SYS_write".to_string(), 1);
            self.map.insert("SYS_open".to_string(), 2);
            self.map.insert("SYS_close".to_string(), 3);
            self.map.insert("SYS_stat".to_string(), 4);
            self.map.insert("SYS_fstat".to_string(), 5);
            self.map.insert("SYS_lstat".to_string(), 6);
            self.map.insert("SYS_poll".to_string(), 7);
            self.map.insert("SYS_lseek".to_string(), 8);
            self.map.insert("SYS_mmap".to_string(), 9);
            self.map.insert("SYS_mprotect".to_string(), 10);
            self.map.insert("SYS_munmap".to_string(), 11);
            self.map.insert("SYS_brk".to_string(), 12);
            self.map.insert("SYS_rt_sigaction".to_string(), 13);
            self.map.insert("SYS_rt_sigprocmask".to_string(), 14);
            self.map.insert("SYS_rt_sigreturn".to_string(), 15);
            self.map.insert("SYS_ioctl".to_string(), 16);
            self.map.insert("SYS_pread64".to_string(), 17);
            self.map.insert("SYS_pwrite64".to_string(), 18);
            self.map.insert("SYS_readv".to_string(), 19);
            self.map.insert("SYS_writev".to_string(), 20);
            self.map.insert("SYS_access".to_string(), 21);
            self.map.insert("SYS_pipe".to_string(), 22);
            self.map.insert("SYS_select".to_string(), 23);
            self.map.insert("SYS_sched_yield".to_string(), 24);
            self.map.insert("SYS_mremap".to_string(), 25);
            self.map.insert("SYS_msync".to_string(), 26);
            self.map.insert("SYS_mincore".to_string(), 27);
            self.map.insert("SYS_madvise".to_string(), 28);
            self.map.insert("SYS_shmget".to_string(), 29);
            self.map.insert("SYS_shmat".to_string(), 30);
            self.map.insert("SYS_shmctl".to_string(), 31);
            self.map.insert("SYS_dup".to_string(), 32);
            self.map.insert("SYS_dup2".to_string(), 33);
            self.map.insert("SYS_pause".to_string(), 34);
            self.map.insert("SYS_nanosleep".to_string(), 35);
            self.map.insert("SYS_getitimer".to_string(), 36);
            self.map.insert("SYS_alarm".to_string(), 37);
            self.map.insert("SYS_setitimer".to_string(), 38);
            self.map.insert("SYS_getpid".to_string(), 39);
            self.map.insert("SYS_sendfile".to_string(), 40);
            self.map.insert("SYS_socket".to_string(), 41);
            self.map.insert("SYS_connect".to_string(), 42);
            self.map.insert("SYS_accept".to_string(), 43);
            self.map.insert("SYS_sendto".to_string(), 44);
            self.map.insert("SYS_recvfrom".to_string(), 45);
            self.map.insert("SYS_sendmsg".to_string(), 46);
            self.map.insert("SYS_recvmsg".to_string(), 47);
            self.map.insert("SYS_shutdown".to_string(), 48);
            self.map.insert("SYS_bind".to_string(), 49);
            self.map.insert("SYS_listen".to_string(), 50);
            self.map.insert("SYS_getsockname".to_string(), 51);
            self.map.insert("SYS_getpeername".to_string(), 52);
            self.map.insert("SYS_socketpair".to_string(), 53);
            self.map.insert("SYS_setsockopt".to_string(), 54);
            self.map.insert("SYS_getsockopt".to_string(), 55);
            self.map.insert("SYS_clone".to_string(), 56);
            self.map.insert("SYS_fork".to_string(), 57);
            self.map.insert("SYS_vfork".to_string(), 58);
            self.map.insert("SYS_execve".to_string(), 59);
            self.map.insert("SYS_exit".to_string(), 60);
            self.map.insert("SYS_wait4".to_string(), 61);
            self.map.insert("SYS_kill".to_string(), 62);
            self.map.insert("SYS_uname".to_string(), 63);
            self.map.insert("SYS_semget".to_string(), 64);
            self.map.insert("SYS_semop".to_string(), 65);
            self.map.insert("SYS_semctl".to_string(), 66);
            self.map.insert("SYS_shmdt".to_string(), 67);
            self.map.insert("SYS_msgget".to_string(), 68);
            self.map.insert("SYS_msgsnd".to_string(), 69);
            self.map.insert("SYS_msgrcv".to_string(), 70);
            self.map.insert("SYS_msgctl".to_string(), 71);
            self.map.insert("SYS_fcntl".to_string(), 72);
            self.map.insert("SYS_flock".to_string(), 73);
            self.map.insert("SYS_fsync".to_string(), 74);
            self.map.insert("SYS_fdatasync".to_string(), 75);
            self.map.insert("SYS_truncate".to_string(), 76);
            self.map.insert("SYS_ftruncate".to_string(), 77);
            self.map.insert("SYS_getdents".to_string(), 78);
            self.map.insert("SYS_getcwd".to_string(), 79);
            self.map.insert("SYS_chdir".to_string(), 80);
            self.map.insert("SYS_fchdir".to_string(), 81);
            self.map.insert("SYS_rename".to_string(), 82);
            self.map.insert("SYS_mkdir".to_string(), 83);
            self.map.insert("SYS_rmdir".to_string(), 84);
            self.map.insert("SYS_creat".to_string(), 85);
            self.map.insert("SYS_link".to_string(), 86);
            self.map.insert("SYS_unlink".to_string(), 87);
            self.map.insert("SYS_symlink".to_string(), 88);
            self.map.insert("SYS_readlink".to_string(), 89);
            self.map.insert("SYS_chmod".to_string(), 90);
            self.map.insert("SYS_fchmod".to_string(), 91);
            self.map.insert("SYS_chown".to_string(), 92);
            self.map.insert("SYS_fchown".to_string(), 93);
            self.map.insert("SYS_lchown".to_string(), 94);
            self.map.insert("SYS_umask".to_string(), 95);
            self.map.insert("SYS_gettimeofday".to_string(), 96);
            self.map.insert("SYS_getrlimit".to_string(), 97);
            self.map.insert("SYS_getrusage".to_string(), 98);
            self.map.insert("SYS_sysinfo".to_string(), 99);
            self.map.insert("SYS_times".to_string(), 100);
            self.map.insert("SYS_ptrace".to_string(), 101);
            self.map.insert("SYS_getuid".to_string(), 102);
            self.map.insert("SYS_syslog".to_string(), 103);
            self.map.insert("SYS_getgid".to_string(), 104);
            self.map.insert("SYS_setuid".to_string(), 105);
            self.map.insert("SYS_setgid".to_string(), 106);
            self.map.insert("SYS_geteuid".to_string(), 107);
            self.map.insert("SYS_getegid".to_string(), 108);
            self.map.insert("SYS_setpgid".to_string(), 109);
            self.map.insert("SYS_getppid".to_string(), 110);
            self.map.insert("SYS_getpgrp".to_string(), 111);
            self.map.insert("SYS_setsid".to_string(), 112);
            self.map.insert("SYS_setreuid".to_string(), 113);
            self.map.insert("SYS_setregid".to_string(), 114);
            self.map.insert("SYS_getgroups".to_string(), 115);
            self.map.insert("SYS_setgroups".to_string(), 116);
            self.map.insert("SYS_setresuid".to_string(), 117);
            self.map.insert("SYS_getresuid".to_string(), 118);
            self.map.insert("SYS_setresgid".to_string(), 119);
            self.map.insert("SYS_getresgid".to_string(), 120);
            self.map.insert("SYS_getpgid".to_string(), 121);
            self.map.insert("SYS_setfsuid".to_string(), 122);
            self.map.insert("SYS_setfsgid".to_string(), 123);
            self.map.insert("SYS_getsid".to_string(), 124);
            self.map.insert("SYS_capget".to_string(), 125);
            self.map.insert("SYS_capset".to_string(), 126);
            self.map.insert("SYS_rt_sigpending".to_string(), 127);
            self.map.insert("SYS_rt_sigtimedwait".to_string(), 128);
            self.map.insert("SYS_rt_sigqueueinfo".to_string(), 129);
            self.map.insert("SYS_rt_sigsuspend".to_string(), 130);
            self.map.insert("SYS_sigaltstack".to_string(), 131);
            self.map.insert("SYS_utime".to_string(), 132);
            self.map.insert("SYS_mknod".to_string(), 133);
            self.map.insert("SYS_uselib".to_string(), 134);
            self.map.insert("SYS_personality".to_string(), 135);
            self.map.insert("SYS_ustat".to_string(), 136);
            self.map.insert("SYS_statfs".to_string(), 137);
            self.map.insert("SYS_fstatfs".to_string(), 138);
            self.map.insert("SYS_sysfs".to_string(), 139);
            self.map.insert("SYS_getpriority".to_string(), 140);
            self.map.insert("SYS_setpriority".to_string(), 141);
            self.map.insert("SYS_sched_setparam".to_string(), 142);
            self.map.insert("SYS_sched_getparam".to_string(), 143);
            self.map.insert("SYS_sched_setscheduler".to_string(), 144);
            self.map.insert("SYS_sched_getscheduler".to_string(), 145);
            self.map
                .insert("SYS_sched_get_priority_max".to_string(), 146);
            self.map
                .insert("SYS_sched_get_priority_min".to_string(), 147);
            self.map
                .insert("SYS_sched_rr_get_interval".to_string(), 148);
            self.map.insert("SYS_mlock".to_string(), 149);
            self.map.insert("SYS_munlock".to_string(), 150);
            self.map.insert("SYS_mlockall".to_string(), 151);
            self.map.insert("SYS_munlockall".to_string(), 152);
            self.map.insert("SYS_vhangup".to_string(), 153);
            self.map.insert("SYS_modify_ldt".to_string(), 154);
            self.map.insert("SYS_pivot_root".to_string(), 155);
            self.map.insert("SYS__sysctl".to_string(), 156);
            self.map.insert("SYS_prctl".to_string(), 157);
            self.map.insert("SYS_arch_prctl".to_string(), 158);
            self.map.insert("SYS_adjtimex".to_string(), 159);
            self.map.insert("SYS_setrlimit".to_string(), 160);
            self.map.insert("SYS_chroot".to_string(), 161);
            self.map.insert("SYS_sync".to_string(), 162);
            self.map.insert("SYS_acct".to_string(), 163);
            self.map.insert("SYS_settimeofday".to_string(), 164);
            self.map.insert("SYS_mount".to_string(), 165);
            self.map.insert("SYS_umount2".to_string(), 166);
            self.map.insert("SYS_swapon".to_string(), 167);
            self.map.insert("SYS_swapoff".to_string(), 168);
            self.map.insert("SYS_reboot".to_string(), 169);
            self.map.insert("SYS_sethostname".to_string(), 170);
            self.map.insert("SYS_setdomainname".to_string(), 171);
            self.map.insert("SYS_iopl".to_string(), 172);
            self.map.insert("SYS_ioperm".to_string(), 173);
            self.map.insert("SYS_create_module".to_string(), 174);
            self.map.insert("SYS_init_module".to_string(), 175);
            self.map.insert("SYS_delete_module".to_string(), 176);
            self.map.insert("SYS_get_kernel_syms".to_string(), 177);
            self.map.insert("SYS_query_module".to_string(), 178);
            self.map.insert("SYS_quotactl".to_string(), 179);
            self.map.insert("SYS_nfsservctl".to_string(), 180);
            self.map.insert("SYS_getpmsg".to_string(), 181);
            self.map.insert("SYS_putpmsg".to_string(), 182);
            self.map.insert("SYS_afs_syscall".to_string(), 183);
            self.map.insert("SYS_tuxcall".to_string(), 184);
            self.map.insert("SYS_security".to_string(), 185);
            self.map.insert("SYS_gettid".to_string(), 186);
            self.map.insert("SYS_readahead".to_string(), 187);
            self.map.insert("SYS_setxattr".to_string(), 188);
            self.map.insert("SYS_lsetxattr".to_string(), 189);
            self.map.insert("SYS_fsetxattr".to_string(), 190);
            self.map.insert("SYS_getxattr".to_string(), 191);
            self.map.insert("SYS_lgetxattr".to_string(), 192);
            self.map.insert("SYS_fgetxattr".to_string(), 193);
            self.map.insert("SYS_listxattr".to_string(), 194);
            self.map.insert("SYS_llistxattr".to_string(), 195);
            self.map.insert("SYS_flistxattr".to_string(), 196);
            self.map.insert("SYS_removexattr".to_string(), 197);
            self.map.insert("SYS_lremovexattr".to_string(), 198);
            self.map.insert("SYS_fremovexattr".to_string(), 199);
            self.map.insert("SYS_tkill".to_string(), 200);
            self.map.insert("SYS_time".to_string(), 201);
            self.map.insert("SYS_futex".to_string(), 202);
            self.map.insert("SYS_sched_setaffinity".to_string(), 203);
            self.map.insert("SYS_sched_getaffinity".to_string(), 204);
            self.map.insert("SYS_set_thread_area".to_string(), 205);
            self.map.insert("SYS_io_setup".to_string(), 206);
            self.map.insert("SYS_io_destroy".to_string(), 207);
            self.map.insert("SYS_io_getevents".to_string(), 208);
            self.map.insert("SYS_io_submit".to_string(), 209);
            self.map.insert("SYS_io_cancel".to_string(), 210);
            self.map.insert("SYS_get_thread_area".to_string(), 211);
            self.map.insert("SYS_lookup_dcookie".to_string(), 212);
            self.map.insert("SYS_epoll_create".to_string(), 213);
            self.map.insert("SYS_epoll_ctl_old".to_string(), 214);
            self.map.insert("SYS_epoll_wait_old".to_string(), 215);
            self.map.insert("SYS_remap_file_pages".to_string(), 216);
            self.map.insert("SYS_getdents64".to_string(), 217);
            self.map.insert("SYS_set_tid_address".to_string(), 218);
            self.map.insert("SYS_restart_syscall".to_string(), 219);
            self.map.insert("SYS_semtimedop".to_string(), 220);
            self.map.insert("SYS_fadvise64".to_string(), 221);
            self.map.insert("SYS_timer_create".to_string(), 222);
            self.map.insert("SYS_timer_settime".to_string(), 223);
            self.map.insert("SYS_timer_gettime".to_string(), 224);
            self.map.insert("SYS_timer_getoverrun".to_string(), 225);
            self.map.insert("SYS_timer_delete".to_string(), 226);
            self.map.insert("SYS_clock_settime".to_string(), 227);
            self.map.insert("SYS_clock_gettime".to_string(), 228);
            self.map.insert("SYS_clock_getres".to_string(), 229);
            self.map.insert("SYS_clock_nanosleep".to_string(), 230);
            self.map.insert("SYS_exit_group".to_string(), 231);
            self.map.insert("SYS_epoll_wait".to_string(), 232);
            self.map.insert("SYS_epoll_ctl".to_string(), 233);
            self.map.insert("SYS_tgkill".to_string(), 234);
            self.map.insert("SYS_utimes".to_string(), 235);
            self.map.insert("SYS_vserver".to_string(), 236);
            self.map.insert("SYS_mbind".to_string(), 237);
            self.map.insert("SYS_set_mempolicy".to_string(), 238);
            self.map.insert("SYS_get_mempolicy".to_string(), 239);
            self.map.insert("SYS_mq_open".to_string(), 240);
            self.map.insert("SYS_mq_unlink".to_string(), 241);
            self.map.insert("SYS_mq_timedsend".to_string(), 242);
            self.map.insert("SYS_mq_timedreceive".to_string(), 243);
            self.map.insert("SYS_mq_notify".to_string(), 244);
            self.map.insert("SYS_mq_getsetattr".to_string(), 245);
            self.map.insert("SYS_kexec_load".to_string(), 246);
            self.map.insert("SYS_waitid".to_string(), 247);
            self.map.insert("SYS_add_key".to_string(), 248);
            self.map.insert("SYS_request_key".to_string(), 249);
            self.map.insert("SYS_keyctl".to_string(), 250);
            self.map.insert("SYS_ioprio_set".to_string(), 251);
            self.map.insert("SYS_ioprio_get".to_string(), 252);
            self.map.insert("SYS_inotify_init".to_string(), 253);
            self.map.insert("SYS_inotify_add_watch".to_string(), 254);
            self.map.insert("SYS_inotify_rm_watch".to_string(), 255);
            self.map.insert("SYS_migrate_pages".to_string(), 256);
            self.map.insert("SYS_openat".to_string(), 257);
            self.map.insert("SYS_mkdirat".to_string(), 258);
            self.map.insert("SYS_mknodat".to_string(), 259);
            self.map.insert("SYS_fchownat".to_string(), 260);
            self.map.insert("SYS_futimesat".to_string(), 261);
            self.map.insert("SYS_newfstatat".to_string(), 262);
            self.map.insert("SYS_unlinkat".to_string(), 263);
            self.map.insert("SYS_renameat".to_string(), 264);
            self.map.insert("SYS_linkat".to_string(), 265);
            self.map.insert("SYS_symlinkat".to_string(), 266);
            self.map.insert("SYS_readlinkat".to_string(), 267);
            self.map.insert("SYS_fchmodat".to_string(), 268);
            self.map.insert("SYS_faccessat".to_string(), 269);
            self.map.insert("SYS_pselect6".to_string(), 270);
            self.map.insert("SYS_ppoll".to_string(), 271);
            self.map.insert("SYS_unshare".to_string(), 272);
            self.map.insert("SYS_set_robust_list".to_string(), 273);
            self.map.insert("SYS_get_robust_list".to_string(), 274);
            self.map.insert("SYS_splice".to_string(), 275);
            self.map.insert("SYS_tee".to_string(), 276);
            self.map.insert("SYS_sync_file_range".to_string(), 277);
            self.map.insert("SYS_vmsplice".to_string(), 278);
            self.map.insert("SYS_move_pages".to_string(), 279);
            self.map.insert("SYS_utimensat".to_string(), 280);
            self.map.insert("SYS_epoll_pwait".to_string(), 281);
            self.map.insert("SYS_signalfd".to_string(), 282);
            self.map.insert("SYS_timerfd_create".to_string(), 283);
            self.map.insert("SYS_eventfd".to_string(), 284);
            self.map.insert("SYS_fallocate".to_string(), 285);
            self.map.insert("SYS_timerfd_settime".to_string(), 286);
            self.map.insert("SYS_timerfd_gettime".to_string(), 287);
            self.map.insert("SYS_accept4".to_string(), 288);
            self.map.insert("SYS_signalfd4".to_string(), 289);
            self.map.insert("SYS_eventfd2".to_string(), 290);
            self.map.insert("SYS_epoll_create1".to_string(), 291);
            self.map.insert("SYS_dup3".to_string(), 292);
            self.map.insert("SYS_pipe2".to_string(), 293);
            self.map.insert("SYS_inotify_init1".to_string(), 294);
            self.map.insert("SYS_preadv".to_string(), 295);
            self.map.insert("SYS_pwritev".to_string(), 296);
            self.map.insert("SYS_rt_tgsigqueueinfo".to_string(), 297);
            self.map.insert("SYS_perf_event_open".to_string(), 298);
            self.map.insert("SYS_recvmmsg".to_string(), 299);
            self.map.insert("SYS_fanotify_init".to_string(), 300);
            self.map.insert("SYS_fanotify_mark".to_string(), 301);
            self.map.insert("SYS_prlimit64".to_string(), 302);
            self.map.insert("SYS_name_to_handle_at".to_string(), 303);
            self.map.insert("SYS_open_by_handle_at".to_string(), 304);
            self.map.insert("SYS_clock_adjtime".to_string(), 305);
            self.map.insert("SYS_syncfs".to_string(), 306);
            self.map.insert("SYS_sendmmsg".to_string(), 307);
            self.map.insert("SYS_setns".to_string(), 308);
            self.map.insert("SYS_getcpu".to_string(), 309);
            self.map.insert("SYS_process_vm_readv".to_string(), 310);
            self.map.insert("SYS_process_vm_writev".to_string(), 311);
            self.map.insert("SYS_kcmp".to_string(), 312);
            self.map.insert("SYS_finit_module".to_string(), 313);
            self.map.insert("SYS_sched_setattr".to_string(), 314);
            self.map.insert("SYS_sched_getattr".to_string(), 315);
            self.map.insert("SYS_renameat2".to_string(), 316);
            self.map.insert("SYS_seccomp".to_string(), 317);
            self.map.insert("SYS_getrandom".to_string(), 318);
            self.map.insert("SYS_memfd_create".to_string(), 319);
            self.map.insert("SYS_kexec_file_load".to_string(), 320);
            self.map.insert("SYS_bpf".to_string(), 321);
            self.map.insert("SYS_execveat".to_string(), 322);
            self.map.insert("SYS_userfaultfd".to_string(), 323);
            self.map.insert("SYS_membarrier".to_string(), 324);
            self.map.insert("SYS_mlock2".to_string(), 325);
            self.map.insert("SYS_copy_file_range".to_string(), 326);
            self.map.insert("SYS_preadv2".to_string(), 327);
            self.map.insert("SYS_pwritev2".to_string(), 328);
            self.map.insert("SYS_pkey_mprotect".to_string(), 329);
            self.map.insert("SYS_pkey_alloc".to_string(), 330);
            self.map.insert("SYS_pkey_free".to_string(), 331);
            self.map.insert("SYS_statx".to_string(), 332);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SyscallTable;

    #[test]
    fn test_get_syscall_nr() {
        // get number for a valid syscall
        let instance_x86_64 = SyscallTable::new("x86_64".to_string());
        let instance_aarch64 = SyscallTable::new("aarch64".to_string());

        assert_eq!(instance_x86_64.get_syscall_nr("SYS_close").unwrap(), 3);
        assert_eq!(instance_aarch64.get_syscall_nr("SYS_close").unwrap(), 57);

        // invalid syscall name
        assert!(instance_x86_64.get_syscall_nr("nosyscall").is_none());
        assert!(instance_aarch64.get_syscall_nr("nosyscall").is_none());
    }
}
