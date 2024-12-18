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

// attach to a process and inject a syscall
void injectSyscall(pid_t targetPid, long syscallNumber) {
    struct user_regs_struct regs, original_regs;
    int status;

    // attach to the target process
    CHECKERROR(ptrace(PTRACE_ATTACH, targetPid, NULL, NULL) == -1, "PTRACE_ATTACH");
    waitpid(targetPid, &status, 0);
    printf("[+] Attached to process %d\n", targetPid);

    // get the current state of the registers
    CHECKERROR(ptrace(PTRACE_GETREGS, targetPid, NULL, &regs) == -1, "PTRACE_GETREGS");
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));

    // Modify the registers to inject the syscall
    regs.orig_rax = syscallNumber;  // Specify the syscall number (e.g., SYS_getpid)
    regs.rax = syscallNumber;       // rax holds the syscall number
    regs.rip = regs.rip;             // Ensure RIP points to the current instruction

    printf("[+] Injecting syscall number %ld\n", syscallNumber);

    // Set the modified registers
    CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &regs) == -1, "PTRACE_SETREGS");

    // Execute the syscall
    CHECKERROR(ptrace(PTRACE_SYSCALL, targetPid, NULL, NULL) == -1, "PTRACE_SYSCALL");
    waitpid(targetPid, &status, 0);

    // Restore the original registers
    CHECKERROR(ptrace(PTRACE_SETREGS, targetPid, NULL, &original_regs) == -1, "PTRACE_SETREGS");

    // Detach from the process
    CHECKERROR(ptrace(PTRACE_DETACH, targetPid, NULL, NULL) == -1, "PTRACE_DETACH");
    printf("[+] Detached from process %d\n", targetPid);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <syscallNumber>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t targetPid = atoi(argv[1]);
    long syscallNumber = atol(argv[2]);

    if (targetPid <= 0 || syscallNumber <= 0) {
        fprintf(stderr, "Invalid PID or syscall number.\n");
        exit(EXIT_FAILURE);
    }

    printf("[*] Injecting syscall %ld into process %d...\n", syscallNumber, targetPid);
    injectSyscall(targetPid, syscallNumber);

    return 0;
}
