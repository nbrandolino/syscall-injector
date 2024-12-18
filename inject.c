#include <sys/ptrace.h>
#include <sys/user.h> // For user_regs_struct
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>

// Error checking macro
#define CHECK_ERROR(cond, msg) \
    if (cond) { perror(msg); exit(EXIT_FAILURE); }

// Function to attach to a process and inject a syscall
void inject_syscall(pid_t target_pid, long syscall_number) {
    struct user_regs_struct regs, original_regs;
    int status;

    // Attach to the target process
    CHECK_ERROR(ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1, "PTRACE_ATTACH");
    waitpid(target_pid, &status, 0);
    printf("[+] Attached to process %d\n", target_pid);

    // Get the current state of the registers
    CHECK_ERROR(ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1, "PTRACE_GETREGS");
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));

    // Modify the registers to inject the syscall
    regs.orig_rax = syscall_number;  // Specify the syscall number (e.g., SYS_getpid)
    regs.rax = syscall_number;       // rax holds the syscall number
    regs.rip = regs.rip;             // Ensure RIP points to the current instruction

    printf("[+] Injecting syscall number %ld\n", syscall_number);

    // Set the modified registers
    CHECK_ERROR(ptrace(PTRACE_SETREGS, target_pid, NULL, &regs) == -1, "PTRACE_SETREGS");

    // Execute the syscall
    CHECK_ERROR(ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL) == -1, "PTRACE_SYSCALL");
    waitpid(target_pid, &status, 0);

    // Restore the original registers
    CHECK_ERROR(ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs) == -1, "PTRACE_SETREGS");

    // Detach from the process
    CHECK_ERROR(ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1, "PTRACE_DETACH");
    printf("[+] Detached from process %d\n", target_pid);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <syscall_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t target_pid = atoi(argv[1]);
    long syscall_number = atol(argv[2]);

    if (target_pid <= 0 || syscall_number <= 0) {
        fprintf(stderr, "Invalid PID or syscall number.\n");
        exit(EXIT_FAILURE);
    }

    printf("[*] Injecting syscall %ld into process %d...\n", syscall_number, target_pid);
    inject_syscall(target_pid, syscall_number);

    return 0;
}

