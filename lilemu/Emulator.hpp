#pragma once
#include <unicorn/unicorn.h>
#include "IncludeMe.hpp"


class Emulator {
public:

	Emulator(uint64_t base,uint64_t size, std::vector<uint8_t> & buffer, uc_arch arch, uc_mode mode);

	~Emulator();

	void InitUC();
	
	void InitStack();

	void InitRegisters();

	void InitContext();

	void InitData();

	void ReadMemory(uint64_t address, void* buffer, size_t size);
	
	void WriteMemory(uint64_t address, void* buffer, size_t size);

	void MapMemory(uint64_t address, uint64_t size, uint32_t permissions);
	
	template <typename T>
	bool MapSections(std::vector<T>& buffer, uint32_t permissions);

	void AddHook(uc_hook* hook, int type, void* callback, void* user_data, uint64_t start, uint64_t end);

	void WriteRegister(const uc_x86_reg& reg_type, const uintptr_t* reg_val);

	void ReadRegister(const uc_x86_reg& reg_type, void* reg_val);

	uint64_t LogError(uc_err err) ;

	void StartEmulator(uint64_t begin, uint64_t until, uint64_t timeout, size_t count);

	uint64_t GetArg(int pos);

private:

	uc_arch arch_;

	uc_mode mode_;
	
	uc_engine* uc_; // Raw Unicorn engine instance
	
	uc_context* uc_ctxt_;
	
	static uc_x86_reg reg_table[];
	
	std::map<uc_x86_reg, std::uintptr_t> reg_table_state;
	
	std::vector<uint8_t>buffer_;
	
	uint64_t *stackBuffer;
	
	uint64_t base_;
	
	uint64_t size_; 

};

