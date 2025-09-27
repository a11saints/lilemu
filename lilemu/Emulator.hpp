#pragma once
#include <unicorn/unicorn.h>
#include "IncludeMe.hpp"


class Emulator {
public:

	Emulator(uint64_t base,uint64_t size, std::vector<uint8_t> & buffer, uc_arch arch, uc_mode mode);

	~Emulator();

	void init_uc();
	
	void init_stack();

	void init_reg_table();

	void init_ctxt();

	void init_data();

	void mem_read(uint64_t address, void* buffer, size_t size);
	
	void mem_write(uint64_t address, void* buffer, size_t size);

	void mem_map(uint64_t address, uint64_t size, uint32_t permissions);
	
	template <typename T>
	bool sections_map(std::vector<T>& buffer, uint32_t permissions);

	void hook_add(uc_hook* hook, int type, void* callback, void* user_data, uint64_t start, uint64_t end);

	void reg_write(const uc_x86_reg& reg_type, const uintptr_t* reg_val);

	void reg_read(const uc_x86_reg& reg_type, void* reg_val);

	int error_log(uc_err err) ;

	void emu_start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count);

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

