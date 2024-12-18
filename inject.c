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
