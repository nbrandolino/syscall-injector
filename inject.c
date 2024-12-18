#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>

// define software and version name
#define NAME "inject"
#define VERSION "1.0"

// error checking macro
#define CHECKERROR(cond, msg) \
    if (cond) { perror(msg); exit(EXIT_FAILURE); }


// display help information
void showHelp() {
    printf("Usage: %s [options] <pid> <syscall_number>\n", NAME);
    printf("\n");
    printf("Options:\n");
    printf("    -h, --help                  Display this help message.\n");
    printf("    -v, --version               Display version information.\n");
    printf("    -st, --syscall-table        Display system call number table.\n");
    printf("\n");
    printf("Arguments:\n");
    printf("    <pid>                       The process ID of the target process.\n");
    printf("    <syscall_number>            The system call number to inject into the process.\n");
    printf("\n");
    printf("Example:\n");
    printf("    $ %s 1234 60\n", NAME);
    exit(EXIT_SUCCESS);
}


// display version information
void showVersion() {
    printf("%s Version %s\n", NAME, VERSION);
    printf("Licensed under the terms of the GNU General Public License.\n");
    exit(EXIT_SUCCESS);
}


// display syscall number table
void syscallTable() {
    printf("┌────────────────┬─────────────────────────┬─────────────────────────────┐\n");
    printf("│ Syscall Number │ Name                    │ Entry Point                 │\n");
    printf("├────────────────┼─────────────────────────┼─────────────────────────────┤\n");
    printf("│ 0              │ read                    │ sys_read                    │\n");
    printf("│ 1              │ write                   │ sys_write                   │\n");
    printf("│ 2              │ open                    │ sys_open                    │\n");
    printf("│ 3              │ close                   │ sys_close                   │\n");
    printf("│ 4              │ stat                    │ sys_newstat                 │\n");
    printf("│ 5              │ fstat                   │ sys_newfstat                │\n");
    printf("│ 6              │ lstat                   │ sys_newlstat                │\n");
    printf("│ 7              │ poll                    │ sys_poll                    │\n");
    printf("│ 8              │ lseek                   │ sys_lseek                   │\n");
    printf("│ 9              │ mmap                    │ sys_ksys_mmap_pgoff         │\n");
    printf("│ 10             │ mprotect                │ sys_mprotect                │\n");
    printf("│ 11             │ munmap                  │ sys_munmap                  │\n");
    printf("│ 12             │ brk                     │ sys_brk                     │\n");
    printf("│ 13             │ rt_sigaction            │ sys_rt_sigaction            │\n");
    printf("│ 14             │ rt_sigprocmask          │ sys_rt_sigprocmask          │\n");
    printf("│ 15             │ rt_sigreturn            │ sys_rt_sigreturn            │\n");
    printf("│ 16             │ ioctl                   │ sys_ioctl                   │\n");
    printf("│ 17             │ pread64                 │ sys_pread64                 │\n");
    printf("│ 18             │ pwrite64                │ sys_pwrite64                │\n");
    printf("│ 19             │ readv                   │ sys_readv                   │\n");
    printf("│ 20             │ writev                  │ sys_writev                  │\n");
    printf("│ 21             │ access                  │ sys_access                  │\n");
    printf("│ 22             │ pipe                    │ sys_pipe                    │\n");
    printf("│ 23             │ select                  │ sys_select                  │\n");
    printf("│ 24             │ sched_yield             │ sys_sched_yield             │\n");
    printf("│ 25             │ mremap                  │ sys_mremap                  │\n");
    printf("│ 26             │ msync                   │ sys_msync                   │\n");
    printf("│ 27             │ mincore                 │ sys_mincore                 │\n");
    printf("│ 28             │ madvise                 │ sys_madvise                 │\n");
    printf("│ 29             │ shmget                  │ sys_shmget                  │\n");
    printf("│ 30             │ shmat                   │ sys_shmat                   │\n");
    printf("│ 31             │ shmctl                  │ sys_shmctl                  │\n");
    printf("│ 32             │ dup                     │ sys_dup                     │\n");
    printf("│ 33             │ dup2                    │ sys_dup2                    │\n");
    printf("│ 34             │ pause                   │ sys_pause                   │\n");
    printf("│ 35             │ nanosleep               │ sys_nanosleep               │\n");
    printf("│ 36             │ getitimer               │ sys_getitimer               │\n");
    printf("│ 37             │ alarm                   │ sys_alarm                   │\n");
    printf("│ 38             │ setitimer               │ sys_setitimer               │\n");
    printf("│ 39             │ getpid                  │ sys_getpid                  │\n");
    printf("│ 40             │ sendfile                │ sys_sendfile64              │\n");
    printf("│ 41             │ socket                  │ sys_socket                  │\n");
    printf("│ 42             │ connect                 │ sys_connect                 │\n");
    printf("│ 43             │ accept                  │ sys_accept                  │\n");
    printf("│ 44             │ sendto                  │ sys_sendto                  │\n");
    printf("│ 45             │ recvfrom                │ sys_recvfrom                │\n");
    printf("│ 46             │ sendmsg                 │ sys_sendmsg                 │\n");
    printf("│ 47             │ recvmsg                 │ sys_recvmsg                 │\n");
    printf("│ 48             │ shutdown                │ sys_shutdown                │\n");
    printf("│ 49             │ bind                    │ sys_bind                    │\n");
    printf("│ 50             │ listen                  │ sys_listen                  │\n");
    printf("│ 51             │ getsockname             │ sys_getsockname             │\n");
    printf("│ 52             │ getpeername             │ sys_getpeername             │\n");
    printf("│ 53             │ socketpair              │ sys_socketpair              │\n");
    printf("│ 54             │ setsockopt              │ sys_setsockopt              │\n");
    printf("│ 55             │ getsockopt              │ sys_getsockopt              │\n");
    printf("│ 56             │ clone                   │ sys_clone                   │\n");
    printf("│ 57             │ fork                    │ sys_fork                    │\n");
    printf("│ 58             │ vfork                   │ sys_vfork                   │\n");
    printf("│ 59             │ execve                  │ sys_execve                  │\n");
    printf("│ 60             │ exit                    │ sys_exit                    │\n");
    printf("│ 61             │ wait4                   │ sys_wait4                   │\n");
    printf("│ 62             │ kill                    │ sys_kill                    │\n");
    printf("│ 63             │ uname                   │ sys_newuname                │\n");
    printf("│ 64             │ semget                  │ sys_semget                  │\n");
    printf("│ 65             │ semop                   │ sys_semop                   │\n");
    printf("│ 66             │ semctl                  │ sys_semctl                  │\n");
    printf("│ 67             │ shmdt                   │ sys_shmdt                   │\n");
    printf("│ 68             │ msgget                  │ sys_msgget                  │\n");
    printf("│ 69             │ msgsnd                  │ sys_msgsnd                  │\n");
    printf("│ 70             │ msgrcv                  │ sys_msgrcv                  │\n");
    printf("│ 71             │ msgctl                  │ sys_msgctl                  │\n");
    printf("│ 72             │ fcntl                   │ sys_fcntl                   │\n");
    printf("│ 73             │ flock                   │ sys_flock                   │\n");
    printf("│ 74             │ fsync                   │ sys_fsync                   │\n");
    printf("│ 75             │ fdatasync               │ sys_fdatasync               │\n");
    printf("│ 76             │ truncate                │ sys_truncate                │\n");
    printf("│ 77             │ ftruncate               │ sys_ftruncate               │\n");
    printf("│ 78             │ getdents                │ sys_getdents                │\n");
    printf("│ 79             │ getcwd                  │ sys_getcwd                  │\n");
    printf("│ 80             │ chdir                   │ sys_chdir                   │\n");
    printf("│ 81             │ fchdir                  │ sys_fchdir                  │\n");
    printf("│ 82             │ rename                  │ sys_rename                  │\n");
    printf("│ 83             │ mkdir                   │ sys_mkdir                   │\n");
    printf("│ 84             │ rmdir                   │ sys_rmdir                   │\n");
    printf("│ 85             │ creat                   │ sys_creat                   │\n");
    printf("│ 86             │ link                    │ sys_link                    │\n");
    printf("│ 87             │ unlink                  │ sys_unlink                  │\n");
    printf("│ 88             │ symlink                 │ sys_symlink                 │\n");
    printf("│ 89             │ readlink                │ sys_readlink                │\n");
    printf("│ 90             │ chmod                   │ sys_chmod                   │\n");
    printf("│ 91             │ fchmod                  │ sys_fchmod                  │\n");
    printf("│ 92             │ chown                   │ sys_chown                   │\n");
    printf("│ 93             │ fchown                  │ sys_fchown                  │\n");
    printf("│ 94             │ lchown                  │ sys_lchown                  │\n");
    printf("│ 95             │ umask                   │ sys_umask                   │\n");
    printf("│ 96             │ gettimeofday            │ sys_gettimeofday            │\n");
    printf("│ 97             │ getrlimit               │ sys_getrlimit               │\n");
    printf("│ 98             │ getrusage               │ sys_getrusage               │\n");
    printf("│ 99             │ sysinfo                 │ sys_sysinfo                 │\n");
    printf("│ 100            │ times                   │ sys_times                   │\n");
    printf("│ 101            │ ptrace                  │ sys_ptrace                  │\n");
    printf("│ 102            │ getuid                  │ sys_getuid                  │\n");
    printf("│ 103            │ syslog                  │ sys_syslog                  │\n");
    printf("│ 104            │ getgid                  │ sys_getgid                  │\n");
    printf("│ 105            │ setuid                  │ sys_setuid                  │\n");
    printf("│ 106            │ setgid                  │ sys_setgid                  │\n");
    printf("│ 107            │ geteuid                 │ sys_geteuid                 │\n");
    printf("│ 108            │ getegid                 │ sys_getegid                 │\n");
    printf("│ 109            │ setpgid                 │ sys_setpgid                 │\n");
    printf("│ 110            │ getppid                 │ sys_getppid                 │\n");
    printf("│ 111            │ getpgrp                 │ sys_getpgrp                 │\n");
    printf("│ 112            │ setsid                  │ sys_setsid                  │\n");
    printf("│ 113            │ setreuid                │ sys_setreuid                │\n");
    printf("│ 114            │ setregid                │ sys_setregid                │\n");
    printf("│ 115            │ getgroups               │ sys_getgroups               │\n");
    printf("│ 116            │ setgroups               │ sys_setgroups               │\n");
    printf("│ 117            │ setresuid               │ sys_setresuid               │\n");
    printf("│ 118            │ getresuid               │ sys_getresuid               │\n");
    printf("│ 119            │ setresgid               │ sys_setresgid               │\n");
    printf("│ 120            │ getresgid               │ sys_getresgid               │\n");
    printf("│ 121            │ getpgid                 │ sys_getpgid                 │\n");
    printf("│ 122            │ setfsuid                │ sys_setfsuid                │\n");
    printf("│ 123            │ setfsgid                │ sys_setfsgid                │\n");
    printf("│ 124            │ getsid                  │ sys_getsid                  │\n");
    printf("│ 125            │ capget                  │ sys_capget                  │\n");
    printf("│ 126            │ capset                  │ sys_capset                  │\n");
    printf("│ 127            │ rt_sigpending           │ sys_rt_sigpending           │\n");
    printf("│ 128            │ rt_sigtimedwait         │ sys_rt_sigtimedwait         │\n");
    printf("│ 129            │ rt_sigqueueinfo         │ sys_rt_sigqueueinfo         │\n");
    printf("│ 130            │ rt_sigsuspend           │ sys_rt_sigsuspend           │\n");
    printf("│ 131            │ sigaltstack             │ sys_sigaltstack             │\n");
    printf("│ 132            │ utime                   │ sys_utime                   │\n");
    printf("│ 133            │ mknod                   │ sys_mknod                   │\n");
    printf("│ 134            │ uselib                  │                             │\n");
    printf("│ 135            │ personality             │ sys_personality             │\n");
    printf("│ 136            │ ustat                   │ sys_ustat                   │\n");
    printf("│ 137            │ statfs                  │ sys_statfs                  │\n");
    printf("│ 138            │ fstatfs                 │ sys_fstatfs                 │\n");
    printf("│ 139            │ sysfs                   │ sys_sysfs                   │\n");
    printf("│ 140            │ getpriority             │ sys_getpriority             │\n");
    printf("│ 141            │ setpriority             │ sys_setpriority             │\n");
    printf("│ 142            │ sched_setparam          │ sys_sched_setparam          │\n");
    printf("│ 143            │ sched_getparam          │ sys_sched_getparam          │\n");
    printf("│ 144            │ sched_setscheduler      │ sys_sched_setscheduler      │\n");
    printf("│ 145            │ sched_getscheduler      │ sys_sched_getscheduler      │\n");
    printf("│ 146            │ sched_get_priority_max  │ sys_sched_get_priority_max  │\n");
    printf("│ 147            │ sched_get_priority_min  │ sys_sched_get_priority_min  │\n");
    printf("│ 148            │ sched_rr_get_interval   │ sys_sched_rr_get_interval   │\n");
    printf("│ 149            │ mlock                   │ sys_mlock                   │\n");
    printf("│ 150            │ munlock                 │ sys_munlock                 │\n");
    printf("│ 151            │ mlockall                │ sys_mlockall                │\n");
    printf("│ 152            │ munlockall              │ sys_munlockall              │\n");
    printf("│ 153            │ vhangup                 │ sys_vhangup                 │\n");
    printf("│ 154            │ modify_ldt              │ sys_modify_ldt              │\n");
    printf("│ 155            │ pivot_root              │ sys_pivot_root              │\n");
    printf("│ 156            │ _sysctl                 │ sys_ni_syscall              │\n");
    printf("│ 157            │ prctl                   │ sys_prctl                   │\n");
    printf("│ 158            │ arch_prctl              │ sys_arch_prctl              │\n");
    printf("│ 159            │ adjtimex                │ sys_adjtimex                │\n");
    printf("│ 160            │ setrlimit               │ sys_setrlimit               │\n");
    printf("│ 161            │ chroot                  │ sys_chroot                  │\n");
    printf("│ 162            │ sync                    │ sys_sync                    │\n");
    printf("│ 163            │ acct                    │ sys_acct                    │\n");
    printf("│ 164            │ settimeofday            │ sys_settimeofday            │\n");
    printf("│ 165            │ mount                   │ sys_mount                   │\n");
    printf("│ 166            │ umount2                 │ sys_umount                  │\n");
    printf("│ 167            │ swapon                  │ sys_swapon                  │\n");
    printf("│ 168            │ swapoff                 │ sys_swapoff                 │\n");
    printf("│ 169            │ reboot                  │ sys_reboot                  │\n");
    printf("│ 170            │ sethostname             │ sys_sethostname             │\n");
    printf("│ 171            │ setdomainname           │ sys_setdomainname           │\n");
    printf("│ 172            │ iopl                    │ sys_iopl                    │\n");
    printf("│ 173            │ ioperm                  │ sys_ioperm                  │\n");
    printf("│ 174            │ create_module           │                             │\n");
    printf("│ 175            │ init_module             │ sys_init_module             │\n");
    printf("│ 176            │ delete_module           │ sys_delete_module           │\n");
    printf("│ 177            │ get_kernel_syms         │                             │\n");
    printf("│ 178            │ query_module            │                             │\n");
    printf("│ 179            │ quotactl                │ sys_quotactl                │\n");
    printf("│ 180            │ nfsservctl              │                             │\n");
    printf("│ 181            │ getpmsg                 │                             │\n");
    printf("│ 182            │ putpmsg                 │                             │\n");
    printf("│ 183            │ afs_syscall             │                             │\n");
    printf("│ 184            │ tuxcall                 │                             │\n");
    printf("│ 185            │ security                │                             │\n");
    printf("│ 186            │ gettid                  │ sys_gettid                  │\n");
    printf("│ 187            │ readahead               │ sys_readahead               │\n");
    printf("│ 188            │ setxattr                │ sys_setxattr                │\n");
    printf("│ 189            │ lsetxattr               │ sys_lsetxattr               │\n");
    printf("│ 190            │ fsetxattr               │ sys_fsetxattr               │\n");
    printf("│ 191            │ getxattr                │ sys_getxattr                │\n");
    printf("│ 192            │ lgetxattr               │ sys_lgetxattr               │\n");
    printf("│ 193            │ fgetxattr               │ sys_fgetxattr               │\n");
    printf("│ 194            │ listxattr               │ sys_listxattr               │\n");
    printf("│ 195            │ llistxattr              │ sys_llistxattr              │\n");
    printf("│ 196            │ flistxattr              │ sys_flistxattr              │\n");
    printf("│ 197            │ removexattr             │ sys_removexattr             │\n");
    printf("│ 198            │ lremovexattr            │ sys_lremovexattr            │\n");
    printf("│ 199            │ fremovexattr            │ sys_fremovexattr            │\n");
    printf("│ 200            │ tkill                   │ sys_tkill                   │\n");
    printf("│ 201            │ time                    │ sys_time                    │\n");
    printf("│ 202            │ futex                   │ sys_futex                   │\n");
    printf("│ 203            │ sched_setaffinity       │ sys_sched_setaffinity       │\n");
    printf("│ 204            │ sched_getaffinity       │ sys_sched_getaffinity       │\n");
    printf("│ 205            │ set_thread_area         │                             │\n");
    printf("│ 206            │ io_setup                │ sys_io_setup                │\n");
    printf("│ 207            │ io_destroy              │ sys_io_destroy              │\n");
    printf("│ 208            │ io_getevents            │ sys_io_getevents            │\n");
    printf("│ 209            │ io_submit               │ sys_io_submit               │\n");
    printf("│ 210            │ io_cancel               │ sys_io_cancel               │\n");
    printf("│ 211            │ get_thread_area         │                             │\n");
    printf("│ 212            │ lookup_dcookie          │                             │\n");
    printf("│ 213            │ epoll_create            │ sys_epoll_create            │\n");
    printf("│ 214            │ epoll_ctl_old           │                             │\n");
    printf("│ 215            │ epoll_wait_old          │                             │\n");
    printf("│ 216            │ remap_file_pages        │ sys_remap_file_pages        │\n");
    printf("│ 217            │ getdents64              │ sys_getdents64              │\n");
    printf("│ 218            │ set_tid_address         │ sys_set_tid_address         │\n");
    printf("│ 219            │ restart_syscall         │ sys_restart_syscall         │\n");
    printf("│ 220            │ semtimedop              │ sys_semtimedop              │\n");
    printf("│ 221            │ fadvise64               │ sys_fadvise64               │\n");
    printf("│ 222            │ timer_create            │ sys_timer_create            │\n");
    printf("│ 223            │ timer_settime           │ sys_timer_settime           │\n");
    printf("│ 224            │ timer_gettime           │ sys_timer_gettime           │\n");
    printf("│ 225            │ timer_getoverrun        │ sys_timer_getoverrun        │\n");
    printf("│ 226            │ timer_delete            │ sys_timer_delete            │\n");
    printf("│ 227            │ clock_settime           │ sys_clock_settime           │\n");
    printf("│ 228            │ clock_gettime           │ sys_clock_gettime           │\n");
    printf("│ 229            │ clock_getres            │ sys_clock_getres            │\n");
    printf("│ 230            │ clock_nanosleep         │ sys_clock_nanosleep         │\n");
    printf("│ 231            │ exit_group              │ sys_exit_group              │\n");
    printf("│ 232            │ epoll_wait              │ sys_epoll_wait              │\n");
    printf("│ 233            │ epoll_ctl               │ sys_epoll_ctl               │\n");
    printf("│ 234            │ tgkill                  │ sys_tgkill                  │\n");
    printf("│ 235            │ utimes                  │ sys_utimes                  │\n");
    printf("│ 236            │ vserver                 │                             │\n");
    printf("│ 237            │ mbind                   │ sys_mbind                   │\n");
    printf("│ 238            │ set_mempolicy           │ sys_set_mempolicy           │\n");
    printf("│ 239            │ get_mempolicy           │ sys_get_mempolicy           │\n");
    printf("│ 240            │ mq_open                 │ sys_mq_open                 │\n");
    printf("│ 241            │ mq_unlink               │ sys_mq_unlink               │\n");
    printf("│ 242            │ mq_timedsend            │ sys_mq_timedsend            │\n");
    printf("│ 243            │ mq_timedreceive         │ sys_mq_timedreceive         │\n");
    printf("│ 244            │ mq_notify               │ sys_mq_notify               │\n");
    printf("│ 245            │ mq_getsetattr           │ sys_mq_getsetattr           │\n");
    printf("│ 246            │ kexec_load              │ sys_kexec_load              │\n");
    printf("│ 247            │ waitid                  │ sys_waitid                  │\n");
    printf("│ 248            │ add_key                 │ sys_add_key                 │\n");
    printf("│ 249            │ request_key             │ sys_request_key             │\n");
    printf("│ 250            │ keyctl                  │ sys_keyctl                  │\n");
    printf("│ 251            │ ioprio_set              │ sys_ioprio_set              │\n");
    printf("│ 252            │ ioprio_get              │ sys_ioprio_get              │\n");
    printf("│ 253            │ inotify_init            │ sys_inotify_init            │\n");
    printf("│ 254            │ inotify_add_watch       │ sys_inotify_add_watch       │\n");
    printf("│ 255            │ inotify_rm_watch        │ sys_inotify_rm_watch        │\n");
    printf("│ 256            │ migrate_pages           │ sys_migrate_pages           │\n");
    printf("│ 257            │ openat                  │ sys_openat                  │\n");
    printf("│ 258            │ mkdirat                 │ sys_mkdirat                 │\n");
    printf("│ 259            │ mknodat                 │ sys_mknodat                 │\n");
    printf("│ 260            │ fchownat                │ sys_fchownat                │\n");
    printf("│ 261            │ futimesat               │ sys_futimesat               │\n");
    printf("│ 262            │ newfstatat              │ sys_newfstatat              │\n");
    printf("│ 263            │ unlinkat                │ sys_unlinkat                │\n");
    printf("│ 264            │ renameat                │ sys_renameat                │\n");
    printf("│ 265            │ linkat                  │ sys_linkat                  │\n");
    printf("│ 266            │ symlinkat               │ sys_symlinkat               │\n");
    printf("│ 267            │ readlinkat              │ sys_readlinkat              │\n");
    printf("│ 268            │ fchmodat                │ sys_fchmodat                │\n");
    printf("│ 269            │ faccessat               │ sys_faccessat               │\n");
    printf("│ 270            │ pselect6                │ sys_pselect6                │\n");
    printf("│ 271            │ ppoll                   │ sys_ppoll                   │\n");
    printf("│ 272            │ unshare                 │ sys_unshare                 │\n");
    printf("│ 273            │ set_robust_list         │ sys_set_robust_list         │\n");
    printf("│ 274            │ get_robust_list         │ sys_get_robust_list         │\n");
    printf("│ 275            │ splice                  │ sys_splice                  │\n");
    printf("│ 276            │ tee                     │ sys_tee                     │\n");
    printf("│ 277            │ sync_file_range         │ sys_sync_file_range         │\n");
    printf("│ 278            │ vmsplice                │ sys_vmsplice                │\n");
    printf("│ 279            │ move_pages              │ sys_move_pages              │\n");
    printf("│ 280            │ utimensat               │ sys_utimensat               │\n");
    printf("│ 281            │ epoll_pwait             │ sys_epoll_pwait             │\n");
    printf("│ 282            │ signalfd                │ sys_signalfd                │\n");
    printf("│ 283            │ timerfd_create          │ sys_timerfd_create          │\n");
    printf("│ 284            │ eventfd                 │ sys_eventfd                 │\n");
    printf("│ 285            │ fallocate               │ sys_fallocate               │\n");
    printf("│ 286            │ timerfd_settime         │ sys_timerfd_settime         │\n");
    printf("│ 287            │ timerfd_gettime         │ sys_timerfd_gettime         │\n");
    printf("│ 288            │ accept4                 │ sys_accept4                 │\n");
    printf("│ 289            │ signalfd4               │ sys_signalfd4               │\n");
    printf("│ 290            │ eventfd2                │ sys_eventfd2                │\n");
    printf("│ 291            │ epoll_create1           │ sys_epoll_create1           │\n");
    printf("│ 292            │ dup3                    │ sys_dup3                    │\n");
    printf("│ 293            │ pipe2                   │ sys_pipe2                   │\n");
    printf("│ 294            │ inotify_init1           │ sys_inotify_init1           │\n");
    printf("│ 295            │ preadv                  │ sys_preadv                  │\n");
    printf("│ 296            │ pwritev                 │ sys_pwritev                 │\n");
    printf("│ 297            │ rt_tgsigqueueinfo       │ sys_rt_tgsigqueueinfo       │\n");
    printf("│ 298            │ perf_event_open         │ sys_perf_event_open         │\n");
    printf("│ 299            │ recvmmsg                │ sys_recvmmsg                │\n");
    printf("│ 300            │ fanotify_init           │ sys_fanotify_init           │\n");
    printf("│ 301            │ fanotify_mark           │ sys_fanotify_mark           │\n");
    printf("│ 302            │ prlimit64               │ sys_prlimit64               │\n");
    printf("│ 303            │ name_to_handle_at       │ sys_name_to_handle_at       │\n");
    printf("│ 304            │ open_by_handle_at       │ sys_open_by_handle_at       │\n");
    printf("│ 305            │ clock_adjtime           │ sys_clock_adjtime           │\n");
    printf("│ 306            │ syncfs                  │ sys_syncfs                  │\n");
    printf("│ 307            │ sendmmsg                │ sys_sendmmsg                │\n");
    printf("│ 308            │ setns                   │ sys_setns                   │\n");
    printf("│ 309            │ getcpu                  │ sys_getcpu                  │\n");
    printf("│ 310            │ process_vm_readv        │ sys_process_vm_readv        │\n");
    printf("│ 311            │ process_vm_writev       │ sys_process_vm_writev       │\n");
    printf("│ 312            │ kcmp                    │ sys_kcmp                    │\n");
    printf("│ 313            │ finit_module            │ sys_finit_module            │\n");
    printf("│ 314            │ sched_setattr           │ sys_sched_setattr           │\n");
    printf("│ 315            │ sched_getattr           │ sys_sched_getattr           │\n");
    printf("│ 316            │ renameat2               │ sys_renameat2               │\n");
    printf("│ 317            │ seccomp                 │ sys_seccomp                 │\n");
    printf("│ 318            │ getrandom               │ sys_getrandom               │\n");
    printf("│ 319            │ memfd_create            │ sys_memfd_create            │\n");
    printf("│ 320            │ kexec_file_load         │ sys_kexec_file_load         │\n");
    printf("│ 321            │ bpf                     │ sys_bpf                     │\n");
    printf("│ 322            │ execveat                │ sys_execveat                │\n");
    printf("│ 323            │ userfaultfd             │ sys_userfaultfd             │\n");
    printf("│ 324            │ membarrier              │ sys_membarrier              │\n");
    printf("│ 325            │ mlock2                  │ sys_mlock2                  │\n");
    printf("│ 326            │ copy_file_range         │ sys_copy_file_range         │\n");
    printf("│ 327            │ preadv2                 │ sys_preadv2                 │\n");
    printf("│ 328            │ pwritev2                │ sys_pwritev2                │\n");
    printf("│ 329            │ pkey_mprotect           │ sys_pkey_mprotect           │\n");
    printf("│ 330            │ pkey_alloc              │ sys_pkey_alloc              │\n");
    printf("│ 331            │ pkey_free               │ sys_pkey_free               │\n");
    printf("│ 332            │ statx                   │ sys_statx                   │\n");
    printf("│ 333            │ io_pgetevents           │ sys_io_pgetevents           │\n");
    printf("│ 334            │ rseq                    │ sys_rseq                    │\n");
    printf("│ 424            │ pidfd_send_signal       │ sys_pidfd_send_signal       │\n");
    printf("│ 425            │ io_uring_setup          │ sys_io_uring_setup          │\n");
    printf("│ 426            │ io_uring_enter          │ sys_io_uring_enter          │\n");
    printf("│ 427            │ io_uring_register       │ sys_io_uring_register       │\n");
    printf("│ 428            │ open_tree               │ sys_open_tree               │\n");
    printf("│ 429            │ move_mount              │ sys_move_mount              │\n");
    printf("│ 430            │ fsopen                  │ sys_fsopen                  │\n");
    printf("│ 431            │ fsconfig                │ sys_fsconfig                │\n");
    printf("│ 432            │ fsmount                 │ sys_fsmount                 │\n");
    printf("│ 433            │ fspick                  │ sys_fspick                  │\n");
    printf("│ 434            │ pidfd_open              │ sys_pidfd_open              │\n");
    printf("│ 435            │ clone3                  │ sys_clone3                  │\n");
    printf("│ 436            │ close_range             │ sys_close_range             │\n");
    printf("│ 437            │ openat2                 │ sys_openat2                 │\n");
    printf("│ 438            │ pidfd_getfd             │ sys_pidfd_getfd             │\n");
    printf("│ 439            │ faccessat2              │ sys_faccessat2              │\n");
    printf("│ 440            │ process_madvise         │ sys_process_madvise         │\n");
    printf("│ 441            │ epoll_pwait2            │ sys_epoll_pwait2            │\n");
    printf("│ 442            │ mount_setattr           │ sys_mount_setattr           │\n");
    printf("│ 443            │ quotactl_fd             │ sys_quotactl_fd             │\n");
    printf("│ 444            │ landlock_create_ruleset │ sys_landlock_create_ruleset │\n");
    printf("│ 445            │ landlock_add_rule       │ sys_landlock_add_rule       │\n");
    printf("│ 446            │ landlock_restrict_self  │ sys_landlock_restrict_self  │\n");
    printf("│ 447            │ memfd_secret            │ sys_memfd_secret            │\n");
    printf("│ 448            │ process_mrelease        │ sys_process_mrelease        │\n");
    printf("│ 449            │ futex_waitv             │ sys_futex_waitv             │\n");
    printf("│ 450            │ set_mempolicy_home_node │ sys_set_mempolicy_home_node │\n");
    printf("│ 451            │ cachestat               │ sys_cachestat               │\n");
    printf("│ 452            │ fchmodat2               │ sys_fchmodat2               │\n");
    printf("│ 453            │ map_shadow_stack        │ sys_map_shadow_stack        │\n");
    printf("│ 454            │ futex_wake              │ sys_futex_wake              │\n");
    printf("│ 455            │ futex_wait              │ sys_futex_wait              │\n");
    printf("│ 456            │ futex_requeue           │ sys_futex_requeue           │\n");
    printf("└────────────────┴─────────────────────────┴─────────────────────────────┘\n");
    exit(EXIT_SUCCESS);
}


// handle signals gracefully
void handleSignal(int sig) {
    printf("\nCaught signal %d, detaching from the target process...\n", sig);
    // Detach safely from the target process
    exit(EXIT_FAILURE);
}


// verify if a process with the given PID exists
int isProcessRunning(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0;
}


// attach to a process and inject a syscall
void injectSyscall(pid_t targetPid, long syscallNumber) {
    struct user_regs_struct regs, original_regs;
    int status;

    // attach to the target process
    CHECKERROR(ptrace(PTRACE_ATTACH, targetPid, NULL, NULL) == -1, "PTRACE_ATTACH");
    waitpid(targetPid, &status, 0);
    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Attached to process %d\n", targetPid);

    // get the current state of the registers
    CHECKERROR(ptrace(PTRACE_GETREGS, targetPid, NULL, &regs) == -1, "PTRACE_GETREGS");
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));

    // modify the registers to inject the syscall
    regs.orig_rax = syscallNumber;
    regs.rax = syscallNumber;
    regs.rip = regs.rip;

    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Injecting system call number %ld\n", syscallNumber);

    // set the modified registers
    CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &regs) == -1, "PTRACE_SETREGS");

    // execute the syscall
    CHECKERROR(ptrace(PTRACE_SYSCALL, targetPid, NULL, NULL) == -1, "PTRACE_SYSCALL");
    waitpid(targetPid, &status, 0);

    // get the return value from the syscall
    CHECKERROR(ptrace(PTRACE_GETREGS, targetPid, NULL, &regs) == -1, "PTRACE_GETREGS");
    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m System call return value: %ld\n", regs.rax);

    // restore the original registers
    CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &original_regs) == -1, "PTRACE_SETREGS");

    // detach from the process
    CHECKERROR(ptrace(PTRACE_DETACH, targetPid, NULL, NULL) == -1, "PTRACE_DETACH");
    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Detached from process %d\n", targetPid);
}


// main function
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: inject [options] <pid> <syscall_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // handle signals
    signal(SIGINT, handleSignal);

    // call help function if -h is used
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        showHelp();
    }

    // call version function if -v is used
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        showVersion();
    }

    // call syscall table if -st is used
    if (strcmp(argv[1], "-st") == 0 || strcmp(argv[1], "--syscall-table") == 0) {
        syscallTable();
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: inject [options] <pid> <syscall_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // parse pid and syscall number
    char *endptr;
    pid_t targetPid = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m-\033[0m\033[1;37m]\033[0m Invalid PID: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    long syscallNumber = strtol(argv[2], &endptr, 10);
    if (*endptr != '\0' || syscallNumber <= 0 || syscallNumber >= 456) {
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m-\033[0m\033[1;37m]\033[0m Invalid syscall number: %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    // check if the target process exists
    if (!isProcessRunning(targetPid)) {
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m-\033[0m\033[1;37m]\033[0m Target process with PID %d does not exist.\n", targetPid);
        exit(EXIT_FAILURE);
    }

    // call injectSyscall function
    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Injecting system call %ld into process %d...\n", syscallNumber, targetPid);
    injectSyscall(targetPid, syscallNumber);

    return 0;
}
