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

    // Find the heap's end address
    auto heap = engine.mem->get_segment_by_name("Heap");
    if (heap == nullptr)
    {
        throw env_exception("Emulated brk(): didn't find 'Heap' segment!");
    }
    end_heap = heap->end+1;
    // Try to resize this segment
    if (addr > heap->end +1)
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
        {12, Function("brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))}
    };
    return res;
}

} // namespace emulated
} // namespace env
} // namespace maat