# syscall-inject
`syscall-inject` is a command-line utility designed for advanced debugging and testing. It allows users to inject system calls into a running process and retrieve information about the process such as open files, memory maps, and environment variables.

## Features
- **System Call Injection**: Inject single or multiple system calls into a target process.
- **Process Information**: List open files, memory maps, and environment variables of a target process.

## Requirements
- **Root Privileges**: The tool requires root privileges to operate.
- **Linux Environment**: Designed to work on Linux-based systems with access to `/proc` filesystem.

## Usage
```bash
syscall-inject [options] <pid> <syscall_number> | -m <syscall_list>
```

### Options:
- `-h, --help`: Display help information.
- `-v, --version`: Display version information.
- `-m, --multiple`: Inject multiple system calls, specified as a comma-separated list (e.g., `"60,39,1"`).
- `-l, --list`: List open files, memory maps, and environment variables of the target process.

### Arguments:
- `<pid>`: The process ID of the target process.
- `<syscall_number>`: The system call number to inject.

### Examples
1. Inject a single system call (e.g., `60`):
   ```bash
   syscall-inject 1234 60
   ```

2. Inject multiple system calls:
   ```bash
   syscall-inject -m 1234 60,39,1
   ```

3. List process information:
   ```bash
   syscall-inject -l 1234
   ```

## Build and Install
To build the project, ensure you have `gcc` installed, then compile the code as follows:

```bash
cd ./syscall-injector
```
```bash
make
```
```bash
make install
```

Linux Syscall Table
-------------------
| **System Call #** | **Name**                | **Entry Point**             |
|--------------------|-------------------------|-----------------------------|
| 0                  | read                    | sys_read                    |
| 1                  | write                   | sys_write                   |
| 2                  | open                    | sys_open                    |
| 3                  | close                   | sys_close                   |
| 4                  | stat                    | sys_newstat                 |
| 5                  | fstat                   | sys_newfstat                |
| 6                  | lstat                   | sys_newlstat                |
| 7                  | poll                    | sys_poll                    |
| 8                  | lseek                   | sys_lseek                   |
| 9                  | mmap                    | sys_ksys_mmap_pgoff         |
| 10                 | mprotect                | sys_mprotect                |
| 11                 | munmap                  | sys_munmap                  |
| 12                 | brk                     | sys_brk                     |
| 13                 | rt_sigaction            | sys_rt_sigaction            |
| 14                 | rt_sigprocmask          | sys_rt_sigprocmask          |
| 15                 | rt_sigreturn            | sys_rt_sigreturn            |
| 16                 | ioctl                   | sys_ioctl                   |
| 17                 | pread64                 | sys_pread64                 |
| 18                 | pwrite64                | sys_pwrite64                |
| 19                 | readv                   | sys_readv                   |
| 20                 | writev                  | sys_writev                  |
| 21                 | access                  | sys_access                  |
| 22                 | pipe                    | sys_pipe                    |
| 23                 | select                  | sys_select                  |
| 24                 | sched_yield             | sys_sched_yield             |
| 25                 | mremap                  | sys_mremap                  |
| 26                 | msync                   | sys_msync                   |
| 27                 | mincore                 | sys_mincore                 |
| 28                 | madvise                 | sys_madvise                 |
| 29                 | shmget                  | sys_shmget                  |
| 30                 | shmat                   | sys_shmat                   |
| 31                 | shmctl                  | sys_shmctl                  |
| 32                 | dup                     | sys_dup                     |
| 33                 | dup2                    | sys_dup2                    |
| 34                 | pause                   | sys_pause                   |
| 35                 | nanosleep               | sys_nanosleep               |
| 36                 | getitimer               | sys_getitimer               |
| 37                 | alarm                   | sys_alarm                   |
| 38                 | setitimer               | sys_setitimer               |
| 39                 | getpid                  | sys_getpid                  |
| 40                 | sendfile                | sys_sendfile64              |
| 41                 | socket                  | sys_socket                  |
| 42                 | connect                 | sys_connect                 |
| 43                 | accept                  | sys_accept                  |
| 44                 | sendto                  | sys_sendto                  |
| 45                 | recvfrom                | sys_recvfrom                |
| 46                 | sendmsg                 | sys_sendmsg                 |
| 47                 | recvmsg                 | sys_recvmsg                 |
| 48                 | shutdown                | sys_shutdown                |
| 49                 | bind                    | sys_bind                    |
| 50                 | listen                  | sys_listen                  |
| 51                 | getsockname             | sys_getsockname             |
| 52                 | getpeername             | sys_getpeername             |
| 53                 | socketpair              | sys_socketpair              |
| 54                 | setsockopt              | sys_setsockopt              |
| 55                 | getsockopt              | sys_getsockopt              |
| 56                 | clone                   | sys_clone                   |
| 57                 | fork                    | sys_fork                    |
| 58                 | vfork                   | sys_vfork                   |
| 59                 | execve                  | sys_execve                  |
| 60                 | exit                    | sys_exit                    |
| 61                 | wait4                   | sys_wait4                   |
| 62                 | kill                    | sys_kill                    |
| 63                 | uname                   | sys_newuname                |
| 64                 | semget                  | sys_semget                  |
| 65                 | semop                   | sys_semop                   |
| 66                 | semctl                  | sys_semctl                  |
| 67                 | shmdt                   | sys_shmdt                   |
| 68                 | msgget                  | sys_msgget                  |
| 69                 | msgsnd                  | sys_msgsnd                  |
| 70                 | msgrcv                  | sys_msgrcv                  |
| 71                 | msgctl                  | sys_msgctl                  |
| 72                 | fcntl                   | sys_fcntl                   |
| 73                 | flock                   | sys_flock                   |
| 74                 | fsync                   | sys_fsync                   |
| 75                 | fdatasync               | sys_fdatasync               |
| 76                 | truncate                | sys_truncate                |
| 77                 | ftruncate               | sys_ftruncate               |
| 78                 | getdents                | sys_getdents                |
| 79                 | getcwd                  | sys_getcwd                  |
| 80                 | chdir                   | sys_chdir                   |
| 81                 | fchdir                  | sys_fchdir                  |
| 82                 | rename                  | sys_rename                  |
| 83                 | mkdir                   | sys_mkdir                   |
| 84                 | rmdir                   | sys_rmdir                   |
| 85                 | creat                   | sys_creat                   |
| 86                 | link                    | sys_link                    |
| 87                 | unlink                  | sys_unlink                  |
| 88                 | symlink                 | sys_symlink                 |
| 89                 | readlink                | sys_readlink                |
| 90                 | chmod                   | sys_chmod                   |
| 91                 | fchmod                  | sys_fchmod                  |
| 92                 | chown                   | sys_chown                   |
| 93                 | fchown                  | sys_fchown                  |
| 94                 | lchown                  | sys_lchown                  |
| 95                 | umask                   | sys_umask                   |
| 96                 | gettimeofday            | sys_gettimeofday            |
| 97                 | getrlimit               | sys_getrlimit               |
| 98                 | getrusage               | sys_getrusage               |
| 99                 | sysinfo                 | sys_sysinfo                 |
| 100                | times                   | sys_times                   |
| 101                | ptrace                  | sys_ptrace                  |
| 102                | getuid                  | sys_getuid                  |
| 103                | syslog                  | sys_syslog                  |
| 104                | getgid                  | sys_getgid                  |
| 105                | setuid                  | sys_setuid                  |
| 106                | setgid                  | sys_setgid                  |
| 107                | geteuid                 | sys_geteuid                 |
| 108                | getegid                 | sys_getegid                 |
| 109                | setpgid                 | sys_setpgid                 |
| 110                | getppid                 | sys_getppid                 |
| 111                | getpgrp                 | sys_getpgrp                 |
| 112                | setsid                  | sys_setsid                  |
| 113                | setreuid                | sys_setreuid                |
| 114                | setregid                | sys_setregid                |
| 115                | getgroups               | sys_getgroups               |
| 116                | setgroups               | sys_setgroups               |
| 117                | setresuid               | sys_setresuid               |
| 118                | getresuid               | sys_getresuid               |
| 119                | setresgid               | sys_setresgid               |
| 120                | getresgid               | sys_getresgid               |
| 121                | getpgid                 | sys_getpgid                 |
| 122                | setfsuid                | sys_setfsuid                |
| 123                | setfsgid                | sys_setfsgid                |
| 124                | getsid                  | sys_getsid                  |
| 125                | capget                  | sys_capget                  |
| 126                | capset                  | sys_capset                  |
| 127                | rt_sigpending           | sys_rt_sigpending           |
| 128                | rt_sigtimedwait         | sys_rt_sigtimedwait         |
| 129                | rt_sigqueueinfo         | sys_rt_sigqueueinfo         |
| 130                | rt_sigsuspend           | sys_rt_sigsuspend           |
| 131                | sigaltstack             | sys_sigaltstack             |
| 132                | utime                   | sys_utime                   |
| 133                | mknod                   | sys_mknod                   |
| 134                | uselib                  |                             |
| 135                | personality             | sys_personality             |
| 136                | ustat                   | sys_ustat                   |
| 137                | statfs                  | sys_statfs                  |
| 138                | fstatfs                 | sys_fstatfs                 |
| 139                | sysfs                   | sys_sysfs                   |
| 140                | getpriority             | sys_getpriority             |
| 141                | setpriority             | sys_setpriority             |
| 142                | sched_setparam          | sys_sched_setparam          |
| 143                | sched_getparam          | sys_sched_getparam          |
| 144                | sched_setscheduler      | sys_sched_setscheduler      |
| 145                | sched_getscheduler      | sys_sched_getscheduler      |
| 146                | sched_get_priority_max  | sys_sched_get_priority_max  |
| 147                | sched_get_priority_min  | sys_sched_get_priority_min  |
| 148                | sched_rr_get_interval   | sys_sched_rr_get_interval   |
| 149                | mlock                   | sys_mlock                   |
| 150                | munlock                 | sys_munlock                 |
| 151                | mlockall                | sys_mlockall                |
| 152                | munlockall              | sys_munlockall              |
| 153                | vhangup                 | sys_vhangup                 |
| 154                | modify_ldt              | sys_modify_ldt              |
| 155                | pivot_root              | sys_pivot_root              |
| 156                | _sysctl                 | sys_ni_syscall              |
| 157                | prctl                   | sys_prctl                   |
| 158                | arch_prctl              | sys_arch_prctl              |
| 159                | adjtimex                | sys_adjtimex                |
| 160                | setrlimit               | sys_setrlimit               |
| 161                | chroot                  | sys_chroot                  |
| 162                | sync                    | sys_sync                    |
| 163                | acct                    | sys_acct                    |
| 164                | settimeofday            | sys_settimeofday            |
| 165                | mount                   | sys_mount                   |
| 166                | umount2                 | sys_umount                  |
| 167                | swapon                  | sys_swapon                  |
| 168                | swapoff                 | sys_swapoff                 |
| 169                | reboot                  | sys_reboot                  |
| 170                | sethostname             | sys_sethostname             |
| 171                | setdomainname           | sys_setdomainname           |
| 172                | iopl                    | sys_iopl                    |
| 173                | ioperm                  | sys_ioperm                  |
| 174                | create_module           |                             |
| 175                | init_module             | sys_init_module             |
| 176                | delete_module           | sys_delete_module           |
| 177                | get_kernel_syms         |                             |
| 178                | query_module            |                             |
| 179                | quotactl                | sys_quotactl                |
| 180                | nfsservctl              |                             |
| 181                | getpmsg                 |                             |
| 182                | putpmsg                 |                             |
| 183                | afs_syscall             |                             |
| 184                | tuxcall                 |                             |
| 185                | security                |                             |
| 186                | gettid                  | sys_gettid                  |
| 187                | readahead               | sys_readahead               |
| 188                | setxattr                | sys_setxattr                |
| 189                | lsetxattr               | sys_lsetxattr               |
| 190                | fsetxattr               | sys_fsetxattr               |
| 191                | getxattr                | sys_getxattr                |
| 192                | lgetxattr               | sys_lgetxattr               |
| 193                | fgetxattr               | sys_fgetxattr               |
| 194                | listxattr               | sys_listxattr               |
| 195                | llistxattr              | sys_llistxattr              |
| 196                | flistxattr              | sys_flistxattr              |
| 197                | removexattr             | sys_removexattr             |
| 198                | lremovexattr            | sys_lremovexattr            |
| 199                | fremovexattr            | sys_fremovexattr            |
| 200                | tkill                   | sys_tkill                   |
| 201                | time                    | sys_time                    |
| 202                | futex                   | sys_futex                   |
| 203                | sched_setaffinity       | sys_sched_setaffinity       |
| 204                | sched_getaffinity       | sys_sched_getaffinity       |
| 205                | set_thread_area         |                             |
| 206                | io_setup                | sys_io_setup                |
| 207                | io_destroy              | sys_io_destroy              |
| 208                | io_getevents            | sys_io_getevents            |
| 209                | io_submit               | sys_io_submit               |
| 210                | io_cancel               | sys_io_cancel               |
| 211                | get_thread_area         |                             |
| 212                | lookup_dcookie          |                             |
| 213                | epoll_create            | sys_epoll_create            |
| 214                | epoll_ctl_old           |                             |
| 215                | epoll_wait_old          |                             |
| 216                | remap_file_pages        | sys_remap_file_pages        |
| 217                | getdents64              | sys_getdents64              |
| 218                | set_tid_address         | sys_set_tid_address         |
| 219                | restart_syscall         | sys_restart_syscall         |
| 220                | semtimedop              | sys_semtimedop              |
| 221                | fadvise64               | sys_fadvise64               |
| 222                | timer_create            | sys_timer_create            |
| 223                | timer_settime           | sys_timer_settime           |
| 224                | timer_gettime           | sys_timer_gettime           |
| 225                | timer_getoverrun        | sys_timer_getoverrun        |
| 226                | timer_delete            | sys_timer_delete            |
| 227                | clock_settime           | sys_clock_settime           |
| 228                | clock_gettime           | sys_clock_gettime           |
| 229                | clock_getres            | sys_clock_getres            |
| 230                | clock_nanosleep         | sys_clock_nanosleep         |
| 231                | exit_group              | sys_exit_group              |
| 232                | epoll_wait              | sys_epoll_wait              |
| 233                | epoll_ctl               | sys_epoll_ctl               |
| 234                | tgkill                  | sys_tgkill                  |
| 235                | utimes                  | sys_utimes                  |
| 236                | vserver                 |                             |
| 237                | mbind                   | sys_mbind                   |
| 238                | set_mempolicy           | sys_set_mempolicy           |
| 239                | get_mempolicy           | sys_get_mempolicy           |
| 240                | mq_open                 | sys_mq_open                 |
| 241                | mq_unlink               | sys_mq_unlink               |
| 242                | mq_timedsend            | sys_mq_timedsend            |
| 243                | mq_timedreceive         | sys_mq_timedreceive         |
| 244                | mq_notify               | sys_mq_notify               |
| 245                | mq_getsetattr           | sys_mq_getsetattr           |
| 246                | kexec_load              | sys_kexec_load              |
| 247                | waitid                  | sys_waitid                  |
| 248                | add_key                 | sys_add_key                 |
| 249                | request_key             | sys_request_key             |
| 250                | keyctl                  | sys_keyctl                  |
| 251                | ioprio_set              | sys_ioprio_set              |
| 252                | ioprio_get              | sys_ioprio_get              |
| 253                | inotify_init            | sys_inotify_init            |
| 254                | inotify_add_watch       | sys_inotify_add_watch       |
| 255                | inotify_rm_watch        | sys_inotify_rm_watch        |
| 256                | migrate_pages           | sys_migrate_pages           |
| 257                | openat                  | sys_openat                  |
| 258                | mkdirat                 | sys_mkdirat                 |
| 259                | mknodat                 | sys_mknodat                 |
| 260                | fchownat                | sys_fchownat                |
| 261                | futimesat               | sys_futimesat               |
| 262                | newfstatat              | sys_newfstatat              |
| 263                | unlinkat                | sys_unlinkat                |
| 264                | renameat                | sys_renameat                |
| 265                | linkat                  | sys_linkat                  |
| 266                | symlinkat               | sys_symlinkat               |
| 267                | readlinkat              | sys_readlinkat              |
| 268                | fchmodat                | sys_fchmodat                |
| 269                | faccessat               | sys_faccessat               |
| 270                | pselect6                | sys_pselect6                |
| 271                | ppoll                   | sys_ppoll                   |
| 272                | unshare                 | sys_unshare                 |
| 273                | set_robust_list         | sys_set_robust_list         |
| 274                | get_robust_list         | sys_get_robust_list         |
| 275                | splice                  | sys_splice                  |
| 276                | tee                     | sys_tee                     |
| 277                | sync_file_range         | sys_sync_file_range         |
| 278                | vmsplice                | sys_vmsplice                |
| 279                | move_pages              | sys_move_pages              |
| 280                | utimensat               | sys_utimensat               |
| 281                | epoll_pwait             | sys_epoll_pwait             |
| 282                | signalfd                | sys_signalfd                |
| 283                | timerfd_create          | sys_timerfd_create          |
| 284                | eventfd                 | sys_eventfd                 |
| 285                | fallocate               | sys_fallocate               |
| 286                | timerfd_settime         | sys_timerfd_settime         |
| 287                | timerfd_gettime         | sys_timerfd_gettime         |
| 288                | accept4                 | sys_accept4                 |
| 289                | signalfd4               | sys_signalfd4               |
| 290                | eventfd2                | sys_eventfd2                |
| 291                | epoll_create1           | sys_epoll_create1           |
| 292                | dup3                    | sys_dup3                    |
| 293                | pipe2                   | sys_pipe2                   |
| 294                | inotify_init1           | sys_inotify_init1           |
| 295                | preadv                  | sys_preadv                  |
| 296                | pwritev                 | sys_pwritev                 |
| 297                | rt_tgsigqueueinfo       | sys_rt_tgsigqueueinfo       |
| 298                | perf_event_open         | sys_perf_event_open         |
| 299                | recvmmsg                | sys_recvmmsg                |
| 300                | fanotify_init           | sys_fanotify_init           |
| 301                | fanotify_mark           | sys_fanotify_mark           |
| 302                | prlimit64               | sys_prlimit64               |
| 303                | name_to_handle_at       | sys_name_to_handle_at       |
| 304                | open_by_handle_at       | sys_open_by_handle_at       |
| 305                | clock_adjtime           | sys_clock_adjtime           |
| 306                | syncfs                  | sys_syncfs                  |
| 307                | sendmmsg                | sys_sendmmsg                |
| 308                | setns                   | sys_setns                   |
| 309                | getcpu                  | sys_getcpu                  |
| 310                | process_vm_readv        | sys_process_vm_readv        |
| 311                | process_vm_writev       | sys_process_vm_writev       |
| 312                | kcmp                    | sys_kcmp                    |
| 313                | finit_module            | sys_finit_module            |
| 314                | sched_setattr           | sys_sched_setattr           |
| 315                | sched_getattr           | sys_sched_getattr           |
| 316                | renameat2               | sys_renameat2               |
| 317                | seccomp                 | sys_seccomp                 |
| 318                | getrandom               | sys_getrandom               |
| 319                | memfd_create            | sys_memfd_create            |
| 320                | kexec_file_load         | sys_kexec_file_load         |
| 321                | bpf                     | sys_bpf                     |
| 322                | execveat                | sys_execveat                |
| 323                | userfaultfd             | sys_userfaultfd             |
| 324                | membarrier              | sys_membarrier              |
| 325                | mlock2                  | sys_mlock2                  |
| 326                | copy_file_range         | sys_copy_file_range         |
| 327                | preadv2                 | sys_preadv2                 |
| 328                | pwritev2                | sys_pwritev2                |
| 329                | pkey_mprotect           | sys_pkey_mprotect           |
| 330                | pkey_alloc              | sys_pkey_alloc              |
| 331                | pkey_free               | sys_pkey_free               |
| 332                | statx                   | sys_statx                   |
| 333                | io_pgetevents           | sys_io_pgetevents           |
| 334                | rseq                    | sys_rseq                    |
| 424                | pidfd_send_signal       | sys_pidfd_send_signal       |
| 425                | io_uring_setup          | sys_io_uring_setup          |
| 426                | io_uring_enter          | sys_io_uring_enter          |
| 427                | io_uring_register       | sys_io_uring_register       |
| 428                | open_tree               | sys_open_tree               |
| 429                | move_mount              | sys_move_mount              |
| 430                | fsopen                  | sys_fsopen                  |
| 431                | fsconfig                | sys_fsconfig                |
| 432                | fsmount                 | sys_fsmount                 |
| 433                | fspick                  | sys_fspick                  |
| 434                | pidfd_open              | sys_pidfd_open              |
| 435                | clone3                  | sys_clone3                  |
| 436                | close_range             | sys_close_range             |
| 437                | openat2                 | sys_openat2                 |
| 438                | pidfd_getfd             | sys_pidfd_getfd             |
| 439                | faccessat2              | sys_faccessat2              |
| 440                | process_madvise         | sys_process_madvise         |
| 441                | epoll_pwait2            | sys_epoll_pwait2            |
| 442                | mount_setattr           | sys_mount_setattr           |
| 443                | quotactl_fd             | sys_quotactl_fd             |
| 444                | landlock_create_ruleset | sys_landlock_create_ruleset |
| 445                | landlock_add_rule       | sys_landlock_add_rule       |
| 446                | landlock_restrict_self  | sys_landlock_restrict_self  |
| 447                | memfd_secret            | sys_memfd_secret            |
| 448                | process_mrelease        | sys_process_mrelease        |
| 449                | futex_waitv             | sys_futex_waitv             |
| 450                | set_mempolicy_home_node | sys_set_mempolicy_home_node |
| 451                | cachestat               | sys_cachestat               |
| 452                | fchmodat2               | sys_fchmodat2               |
| 453                | map_shadow_stack        | sys_map_shadow_stack        |
| 454                | futex_wake              | sys_futex_wake              |
| 455                | futex_wait              | sys_futex_wait              |
| 456                | futex_requeue           | sys_futex_requeue           |


## Additional Information
- The make file is written to allow for static compiling of the program.
    - Statically compile by `$ make static`

## Limitations
- This tool is designed for educational and research purposes only. Use responsibly.
- Using `ptrace` can interfere with the target process's execution and stability.
- The tool assumes knowledge of system calls and their effects on processes.

## Disclaimer
This tool modifies running processes, which can lead to unexpected behavior. Use with caution and ensure proper permissions and backups. The author is not responsible for any damage or loss resulting from the use of this tool.

## License
This tool is licensed under the GNU General Public License (GPL). See ./LICENSE for more details.

## Contact
nbrandolino
nickbrandolino134@gmail.com
