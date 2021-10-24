#include "env/syscall.hpp"
#include "engine.hpp"


namespace maat{
namespace env{
namespace emulated{

// ================= Syscall functions ==================
// int brk(void* addr)
FunctionCallback::return_t sys_linux_brk(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    addr_t addr = args[0]->as_uint(*engine.vars);
    addr_t end_heap, prev_end;
    addr_t extend_bytes = 0;

    std::cout << "DEBUG BRK address " << addr << std::endl;
    // throw std::exception();

    // Find the heap's end address
    auto heap = engine.mem->get_segment_by_name("Heap");
    if (heap == nullptr)
    {
        throw env_exception("Emulated brk(): didn't find 'Heap' segment!");
    }
    end_heap = heap->end+1;
    // Special behaviour for brk(NULL), return end of Heap
    if (addr == 0)
    {
        return (cst_t)(heap->end+1);
    }
    // Try to resize this segment
    else if (addr > heap->end +1)
    {
        // First check if memory is free for extending
        extend_bytes = addr - heap->end -1;
        if (not engine.mem->is_free(heap->end+1, heap->end+1+extend_bytes))
        {
            return -1; // Memory not free
        }
        // Then extend
        prev_end = heap->end+1;
        heap->extend_after(extend_bytes);
        end_heap = heap->end+1;
        // Mark new memory as RW
        engine.mem->page_manager.set_flags(prev_end, end_heap, maat::mem_flag_rw);
        return 0; // Success
    }

    return 0; // Success
}

// int arch_prctl(struct task_struct *task, int code, unsigned long* addr)
FunctionCallback::return_t sys_linux_arch_prctl(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    /* Function codes
        #define ARCH_SET_GS		0x1001
        #define ARCH_SET_FS		0x1002
        #define ARCH_GET_FS		0x1003
        #define ARCH_GET_GS		0x1004

        #define ARCH_GET_CPUID		0x1011
        #define ARCH_SET_CPUID		0x1012

        #define ARCH_CET_STATUS		0x3001
        #define ARCH_CET_DISABLE	0x3002
        #define ARCH_CET_LOCK		0x3003
        #define ARCH_CET_EXEC		0x3004
        #define ARCH_CET_ALLOC_SHSTK	0x3005
        #define ARCH_CET_PUSH_SHSTK	0x3006
    */
    ucst_t code = args[0]->as_uint(*engine.vars);
    if (code == 0x1002) // Set FS
    {
        // HACK: in Maat we don't distinguish between segment selector
        // and the address their entry points to 
        engine.cpu.ctx().set(X64::FS, args[1]);
    }
    else if (code >= 0x3001 and code <= 0x3006)
    {
        // CET stuff, not supported but pretend everything went fine
        return 0; // Success
    }
    else
    {
        throw env_exception(
            Fmt() << "Emulated arch_prctl(): unsupported subfunction code: 0x"
            << std::hex << code
            >> Fmt::to_str
        );
    }

    return 0; // Success
}
// ================= Build the syscall maps =================
syscall_func_map_t linux_x86_syscall_map()
{
    syscall_func_map_t res
    {
        {45, Function("brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))}
    };
    return res;
}

syscall_func_map_t linux_x64_syscall_map()
{
    syscall_func_map_t res
    {
        {12, Function("brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))},
        {158, Function("arch_prctl", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_arch_prctl))}
    };
    return res;
}

} // namespace emulated
} // namespace env
} // namespace maat