#include "ApiResolver.hpp"


uint64_t callbacks::crt::ios_base__width() {
	uint64_t rax;
	uint64_t rcx;
	emulator->ReadRegister(UC_X86_REG_RCX, &rcx);
	emulator->ReadMemory(rcx + 0x28, &rax, sizeof(rax));
	emulator->WriteRegister(UC_X86_REG_RAX, &rax);
	//__asm {
	//	mov rax, qword ptr ds : [rcx + 28] 
	//	ret 
	//}
	return 0;
}


bool utils::openProcessHandle(DWORD dwPID) {
	if (dwPID != 0) {
		HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 0, dwPID);
		if (hProcess) return true;
		else return false;
	}
	return false;
}
