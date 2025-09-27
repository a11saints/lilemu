#include <string.h>

#include "unicorn/unicorn.h"

// #define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A \x49\x0F\xC9 \x90
//\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9" //
//<== still crash #define X86_CODE64
//"\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9"
#define X86_CODE64                                                             \
    "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90" \
    "\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A" \
    "\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5" \
    "\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E" \
    "\x09\x3C\x59"
#define X86_CODE64_SYSCALL "\x0f\x05" // SYSCALL

 // memory address where emulation starts
#define ADDRESS 0x1000000

// callback for tracing basic blocks
static void hook_block(uc_engine* uc, uint64_t address, uint32_t size,
    void* user_data)
{
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
        address, size);
}

// callback for tracing instruction
static void hook_code(uc_engine* uc, uint64_t address, uint32_t size,
    void* user_data)
{
    int eflags;
    printf(">>> Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n", address, size);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    printf(">>> --- EFLAGS is 0x%x\n", eflags);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

// callback for tracing instruction
static void hook_code64(uc_engine* uc, uint64_t address, uint32_t size,
    void* user_data)
{
    uint64_t rip;

    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    printf(">>> Tracing instruction at 0x%" PRIx64
        ", instruction size = 0x%x\n",
        address, size);
    printf(">>> RIP is 0x%" PRIx64 "\n", rip);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

static void hook_mem64(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void* user_data)
{
    switch (type) {
    default:
        break;
    case UC_MEM_READ:
        printf(">>> Memory is being READ at 0x%" PRIx64 ", data size = %u\n",
            address, size);
        break;
    case UC_MEM_WRITE:
        printf(">>> Memory is being WRITE at 0x%" PRIx64
            ", data size = %u, data value = 0x%" PRIx64 "\n",
            address, size, value);
        break;
    }
}

// callback for IN instruction (X86).
// this returns the data read from the port
static uint32_t hook_in(uc_engine* uc, uint32_t port, int size, void* user_data)
{
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("--- reading from port 0x%x, size: %u, address: 0x%x\n", port, size,
        eip);

    switch (size) {
    default:
        return 0; // should never reach this
    case 1:
        // read 1 byte to AL
        return 0xf1;
    case 2:
        // read 2 byte to AX
        return 0xf2;
        break;
    case 4:
        // read 4 byte to EAX
        return 0xf4;
    }
}

// callback for SYSCALL instruction (X86).
static void hook_syscall(uc_engine* uc, void* user_data)
{
    uint64_t rax;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    if (rax == 0x100) {
        rax = 0x200;
        uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    }
    else
        printf("ERROR: was not expecting rax=0x%" PRIx64 " in syscall\n", rax);
}




static void test_x86_64(void)
{
    uc_engine* uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    int64_t rax = 0x71f3029efd49d41d;
    int64_t rbx = 0xd87b45277f133ddb;
    int64_t rcx = 0xab40d1ffd8afc461;
    int64_t rdx = 0x919317b4a733f01;
    int64_t rsi = 0x4c24e753a17ea358;
    int64_t rdi = 0xe509a57d2571ce96;
    int64_t r8 = 0xea5b108cc2b9ab1f;
    int64_t r9 = 0x19ec097c8eb618c1;
    int64_t r10 = 0xec45774f00c5f682;
    int64_t r11 = 0xe17e9dbec8c074aa;
    int64_t r12 = 0x80f86a8dc0f6d457;
    int64_t r13 = 0x48288ca5671c5492;
    int64_t r14 = 0x595f72f6e4017f6e;
    int64_t r15 = 0x1efd97aea331cccc;

    int64_t rsp = ADDRESS + 0x200000;

    printf("Emulate x86_64 code\n");

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE64, sizeof(X86_CODE64) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_write(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_write(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_write(uc, UC_X86_REG_R8, &r8);
    uc_reg_write(uc, UC_X86_REG_R9, &r9);
    uc_reg_write(uc, UC_X86_REG_R10, &r10);
    uc_reg_write(uc, UC_X86_REG_R11, &r11);
    uc_reg_write(uc, UC_X86_REG_R12, &r12);
    uc_reg_write(uc, UC_X86_REG_R13, &r13);
    uc_reg_write(uc, UC_X86_REG_R14, &r14);
    uc_reg_write(uc, UC_X86_REG_R15, &r15);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions in the range [ADDRESS, ADDRESS+20]
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code64, NULL, ADDRESS,
        ADDRESS + 20);

    // tracing all memory WRITE access (with @begin > @end)
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1, 0);

    // tracing all memory READ access (with @begin > @end)
    uc_hook_add(uc, &trace4, UC_HOOK_MEM_READ, hook_mem64, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE64) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err,
            uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);

    printf(">>> RAX = 0x%" PRIx64 "\n", rax);
    printf(">>> RBX = 0x%" PRIx64 "\n", rbx);
    printf(">>> RCX = 0x%" PRIx64 "\n", rcx);
    printf(">>> RDX = 0x%" PRIx64 "\n", rdx);
    printf(">>> RSI = 0x%" PRIx64 "\n", rsi);
    printf(">>> RDI = 0x%" PRIx64 "\n", rdi);
    printf(">>> R8 = 0x%" PRIx64 "\n", r8);
    printf(">>> R9 = 0x%" PRIx64 "\n", r9);
    printf(">>> R10 = 0x%" PRIx64 "\n", r10);
    printf(">>> R11 = 0x%" PRIx64 "\n", r11);
    printf(">>> R12 = 0x%" PRIx64 "\n", r12);
    printf(">>> R13 = 0x%" PRIx64 "\n", r13);
    printf(">>> R14 = 0x%" PRIx64 "\n", r14);
    printf(">>> R15 = 0x%" PRIx64 "\n", r15);

    uc_close(uc);
}

static void test_x86_64_syscall(void)
{
    uc_engine* uc;
    uc_hook trace1;
    uc_err err;

    int64_t rax = 0x100;

    printf("Emulate x86_64 code with 'syscall' instruction\n");

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE64_SYSCALL,
        sizeof(X86_CODE64_SYSCALL) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // hook interrupts for syscall
    uc_hook_add(uc, &trace1, UC_HOOK_INSN, hook_syscall, NULL, 1, 0,
        UC_X86_INS_SYSCALL);

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE64_SYSCALL) - 1, 0,
        0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err,
            uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);

    printf(">>> RAX = 0x%" PRIx64 "\n", rax);

    uc_close(uc);
}



int main(int argc, char** argv, char** envp) {
    
    test_x86_64();
    printf("===================================\n");
    test_x86_64_syscall();
    return 0;
}