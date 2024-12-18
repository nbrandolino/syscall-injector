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

// error checking macro
#define CHECKERROR(cond, msg) \
    if (cond) { perror(msg); exit(EXIT_FAILURE); }


// display help information
void showHelp() {
    printf("Usage: inject [options] <pid> <syscall_number>\n");
    printf("\n");
    printf("Options:\n");
    printf("    -h, --help              Display this help message.\n");
    printf("    -v, --version           Display version information.\n");
    printf("\n");
    printf("Arguments:\n");
    printf("    <pid>                   The process ID of the target process.\n");
    printf("    <syscall_number>        The syscall number to inject into the process.\n");
    printf("\n");
    printf("Example:\n");
    printf("    $ inject 1234 60\n");
    exit(EXIT_SUCCESS);
}


// display version information
void showVersion() {
    printf("Linux Syscall Injector Version 1.0\n");
    printf("Licensed under the terms of the GNU General Public License.\n");
    exit(EXIT_SUCCESS);
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

    // call help function
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        showHelp();
    }

    // call version function
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        showVersion();
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: inject [options] <pid> <syscall_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t targetPid = atoi(argv[1]);
    long syscallNumber = atol(argv[2]);

    if (targetPid <= 0 || syscallNumber <= 0) {
        fprintf(stderr, "\033[1;37m[\033[0m\033[1;31m-\033[0m\033[1;37m]\033[0m Invalid PID or system call number\n");
        exit(EXIT_FAILURE);
    }

    printf("\033[1;37m[\033[0m\033[1;32m+\033[0m\033[1;37m]\033[0m Injecting system call %ld into process %d...\n", syscallNumber, targetPid);
    injectSyscall(targetPid, syscallNumber);

    return 0;
}
