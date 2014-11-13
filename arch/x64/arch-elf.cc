/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * Copyright (C) 2014 Huawei Technologies Duesseldorf GmbH
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <osv/elf.hh>
#include <osv/debug.h>
#include <osv/align.hh>

#include <osv/demangle.hh>
#include <boost/algorithm/string/predicate.hpp>

extern char kernel_entry[];
extern uint64_t kernel_entry_info[];

__thread uint64_t return_address_p;
__thread uint64_t return_address[128];
__thread uint64_t return_addressr[128];
__thread uint64_t return_address_c;

namespace elf {

bool arch_init_reloc_dyn(struct init_table *t, u32 type, u32 sym,
                         void *addr, void *base, Elf64_Sxword addend)
{
    switch (type) {
    case R_X86_64_NONE:
        break;
    case R_X86_64_COPY: {
        const Elf64_Sym *st = t->dyn_tabs.lookup(sym);
        memcpy(addr, (void *)st->st_value, st->st_size);
        break;
    }
    case R_X86_64_64:
        *static_cast<u64*>(addr) = t->dyn_tabs.lookup(sym)->st_value + addend;
        break;
    case R_X86_64_RELATIVE:
        *static_cast<void**>(addr) = base + addend;
        break;
    case R_X86_64_JUMP_SLOT:
    case R_X86_64_GLOB_DAT:
        *static_cast<u64*>(addr) = t->dyn_tabs.lookup(sym)->st_value;
        break;
    case R_X86_64_DPTMOD64:
        abort();
        //*static_cast<u64*>(addr) = symbol_module(sym);
        break;
    case R_X86_64_DTPOFF64:
        *static_cast<u64*>(addr) = t->dyn_tabs.lookup(sym)->st_value;
        break;
    case R_X86_64_TPOFF64:
        // FIXME: assumes TLS segment comes before DYNAMIC segment
        *static_cast<u64*>(addr) = t->dyn_tabs.lookup(sym)->st_value - t->tls.size;
        break;
    case R_X86_64_IRELATIVE:
        *static_cast<void**>(addr) = reinterpret_cast<void *(*)()>(base + addend)();
        break;
    default:
        return false;
    }
    return true;
}

bool object::arch_relocate_rela(u32 type, u32 sym, void *addr,
                                Elf64_Sxword addend)
{
    switch (type) {
    case R_X86_64_NONE:
        break;
    case R_X86_64_COPY: {
        symbol_module sm = symbol(sym);
        memcpy(addr, sm.relocated_addr(), sm.size());
        break;
    }
    case R_X86_64_64:
        *static_cast<void**>(addr) = symbol(sym).relocated_addr() + addend;
        break;
    case R_X86_64_RELATIVE:
        *static_cast<void**>(addr) = _base + addend;
        break;
    case R_X86_64_JUMP_SLOT:
    case R_X86_64_GLOB_DAT:
        *static_cast<void**>(addr) = symbol(sym).relocated_addr();
        break;
    case R_X86_64_DPTMOD64:
        if (sym == STN_UNDEF) {
            *static_cast<u64*>(addr) = _module_index;
        } else {
            *static_cast<u64*>(addr) = symbol(sym).obj->_module_index;
        }
        break;
    case R_X86_64_DTPOFF64:
        *static_cast<u64*>(addr) = symbol(sym).symbol->st_value;
        break;
    case R_X86_64_TPOFF64:
        abort();
        if (sym)
            *static_cast<u64*>(addr) = symbol(sym).symbol->st_value - get_tls_size();
        else
            *static_cast<void**>(addr) = _base + addend - get_tls_size();
        break;
    default:
        return false;
    }

    return true;
}

class entry_trampoline {
public:
    entry_trampoline(void* addr) {
        auto offset = kernel_entry_info[0];
        auto size = kernel_entry_info[1];

        _code = new char[size];
        memcpy(_code, kernel_entry, size);
        auto real_addr = reinterpret_cast<void**>(_code + offset + 2);
        *real_addr = addr;
    }
    ~entry_trampoline() {
        delete[] _code;
    }
    void* addr() const {
        return _code;
    }
private:
    char* _code;
};

static mutex tramplines_mutex;
static std::map<void*, entry_trampoline> trampolines;

static std::string demangle(const char *name) {
    auto demangled = osv::demangle(name);
    std::string ret;
    if (demangled) {
        ret += demangled.get();
    }
    return ret;
}

static inline bool lib_name(const char* name)
{
    auto dem = demangle(name);
    if (boost::starts_with(dem, "boost::")) {
        return true;
    }
    if (boost::starts_with(dem, "std::")) {
        return true;
    }
    return false;
}

bool object::arch_relocate_jump_slot(u32 sym, void *addr, Elf64_Sxword addend)
{
    auto s = symbol(sym);
    auto func = s.relocated_addr();
    if (s.obj->module_index() == program::core_module_index && !lib_name(symbol_nm(sym))) {
        WITH_LOCK(tramplines_mutex) {
            auto it = trampolines.find(func);
            if (it == trampolines.end()) {
                debug_ll("trampoline: %s\n", symbol_nm(sym));
                it = trampolines.emplace(func, func).first;
                debug_ll("trampoline_add: %p\n", it->second.addr());
            }
            *static_cast<void**>(addr) = it->second.addr();
        }
    } else {
        *static_cast<void**>(addr) = func;
   }
    return true;
}

}

#include <unwind.h>

extern "C" _Unwind_Reason_Code kernel_entry_personality(int version,
    _Unwind_Action actions, uint64_t exceptionClass,
    _Unwind_Exception* unwind_exception, _Unwind_Context* context)
{
    abort();

    if (actions & _UA_SEARCH_PHASE) {
        debug_ll("search phase\n");
        return _URC_CONTINUE_UNWIND;
    }
    if (actions & _UA_CLEANUP_PHASE) {
        auto rip = kernel_entry_info[2];
        auto crip = _Unwind_GetIP(context);
        if (crip > rip) {
            assert(!(actions & _UA_HANDLER_FRAME));
            return _URC_CONTINUE_UNWIND;
        }

        debug_ll("return to %lx, %p %p\n", rip, unwind_exception, context);
        int r0 = __builtin_eh_return_data_regno(0);
        _Unwind_SetGR(context, r0, (uintptr_t)(unwind_exception));
        _Unwind_SetIP(context, rip);
        return _URC_INSTALL_CONTEXT;
    }
    abort();
}
