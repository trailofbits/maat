#include "maat/event.hpp"
#include "maat/engine.hpp"
#include "maat/ir.hpp"
#include "maat/varcontext.hpp"


namespace test
{
namespace events
{      
  
    using namespace maat;
    using namespace maat::event;

    unsigned int _assert(bool val, const std::string& msg)
    {
        if( !val)
        {
            std::cout << "\nFail: " << msg << std::endl; 
            throw test_exception();
        }
        return 1; 
    }
    
#define ADD_ASM_INST(addr, pcode_inst) \
asm_inst = ir::AsmInst(addr, 1); \
asm_inst.add_inst(pcode_inst); \
ir::get_ir_map(engine.mem->uid()).add(asm_inst);

#define ADD_ASM_INST_MULTIPLE(addr, pcode_inst_vec) \
asm_inst = ir::AsmInst(addr, 1); \
for (auto& pcode_inst : pcode_inst_vec) \
    asm_inst.add_inst(pcode_inst); \
ir::get_ir_map(engine.mem->uid()).add(asm_inst);

    unsigned int reg_events(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprcst(32, 0xf0),
                e1 = exprcst(32, 0xf1),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);
        
        ir::AsmInst asm_inst;

        // Register write

        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);

        ADD_ASM_INST(0, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(0, 31, 0)))
        ADD_ASM_INST(1, ir::Inst(ir::Op::COPY, ir::Reg(1, 31, 0), ir::Cst(1, 31, 0)))
        ADD_ASM_INST(2, ir::Inst(ir::Op::COPY, ir::Reg(2, 31, 0), ir::Cst(2, 31, 0)))
        ADD_ASM_INST(3, ir::Inst(ir::Op::COPY, ir::Reg(3, 31, 0), ir::Cst(3, 31, 0)))

        auto callback1 = [](MaatEngine& engine, void* data)
        {
            _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(0).as_uint() == 0xf0, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(1).as_uint() == 0xf1, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->reg == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->written == true, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->read == false, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->value.as_uint() == 0xf0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->new_value.as_uint() == 0x0, "MaatEngine: event hook failed");
            return event::Action::HALT;
        };

        auto callback2 = [](MaatEngine& engine, void* data)
        {
            _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(0).as_uint() == 0x0, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(1).as_uint() == 0xf1, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->reg == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->written == true, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->read == false, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->value.as_uint() == 0x0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->new_value.as_uint() == 0x0, "MaatEngine: event hook failed");
            return event::Action::CONTINUE;
        };

        engine.hooks.disable_all();
        engine.hooks.add(event::Event::REG_W, event::When::BEFORE , EventCallback(callback1), "reg_w_b");
        engine.hooks.add(event::Event::REG_W, event::When::AFTER , EventCallback(callback2), "reg_w_a");
        engine.run_from(0, 3);
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 1, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0, "MaatEngine: event hook failed");


        // Register read
        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        
        ADD_ASM_INST(0x100, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(0, 31, 0)))
        ADD_ASM_INST(0x101, ir::Inst(ir::Op::COPY, ir::Reg(3, 31, 0), ir::Reg(2, 31, 0)))
        ADD_ASM_INST(0x102, ir::Inst(ir::Op::COPY, ir::Reg(3, 31, 0), ir::Cst(42, 31, 0)))
        ADD_ASM_INST(0x103, ir::Inst(ir::Op::COPY, ir::Reg(3, 31, 0), ir::Cst(41, 31, 0)))

        auto callback3 = [](MaatEngine& engine, void* data)
        {
            _assert(engine.cpu.ctx().get(0).as_uint() == 0x0, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(3).as_uint() == 0xf3, "MaatEngine: event hook failed");
            _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0x101, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->reg == 2, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->written == false, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->read == true, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->value.as_uint() == 0xf2, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->new_value.as_uint() == 0xf2, "MaatEngine: event hook failed");
            return event::Action::CONTINUE;
        };

        auto callback4 = [](MaatEngine& engine, void* data)
        {
            if (engine.info.reg_access->read)
            {
                _assert(engine.cpu.ctx().get(0).as_uint() == 0x0, "MaatEngine: event hook failed");
                _assert(engine.cpu.ctx().get(3).as_uint() == 0xf3, "MaatEngine: event hook failed");
                _assert(*engine.info.addr == 0x101, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->reg == 2, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->written == false, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->read == true, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->value.as_uint() == 0xf2, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->new_value.as_uint() == 0xf2, "MaatEngine: event hook failed");
            }
            return event::Action::CONTINUE;
        };

        engine.hooks.disable_all();
        engine.hooks.add(event::Event::REG_R, event::When::BEFORE, event::EventCallback(callback3), "reg_r_a");
        engine.hooks.add(event::Event::REG_RW, event::When::AFTER, event::EventCallback(callback4), "reg_r_b");
        engine.run_from(0x100, 3);
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x103, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::INST_COUNT, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x103, "MaatEngine: event hook failed");

        return nb;
    }

  
    // Some callbacks for tests
    event::Action _cb1_n(MaatEngine& engine, void* data)
    {
        engine.cpu.ctx().set(5, 0x12345678);
        return event::Action::CONTINUE;
    }
    event::EventCallback _cb1(_cb1_n);

    event::Action _cb2_n(MaatEngine& engine, void* data)
    {
        engine.cpu.ctx().set(5, 0xaaaaaaaa);
        return event::Action::HALT;
    }
    event::EventCallback _cb2(_cb2_n);
    
    event::Action _cb3_n(MaatEngine& engine, void* data)
    {
        engine.cpu.ctx().set(6, 0xcafebabe);
        return event::Action::CONTINUE;
    }
    event::EventCallback _cb3(_cb3_n);

    unsigned int mem_events(MaatEngine& engine)
    {
        unsigned int nb = 0;
        ir::AsmInst asm_inst;

        Expr    e0 = exprcst(32, 0xf0),
                e1 = exprcst(32, 0xf1),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);
        
        ADD_ASM_INST(0x200, ir::Inst(ir::Op::LOAD, ir::Reg(2, 31, 0), ir::Param::None(), ir::Reg(0, 31, 0)))
        ADD_ASM_INST(0x201, ir::Inst(ir::Op::COPY, ir::Addr(0x61000, 32), ir::Reg(3, 31, 0)))
        ADD_ASM_INST(0x202, ir::Inst(ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(0, 31, 0), ir::Cst(2, 31, 0)))
        ADD_ASM_INST(0x203, ir::Inst(ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(1, 31, 0), ir::Cst(42, 31, 0)))
        
        // Memory read 
        engine.mem->write(0x60000, exprcst(32, 0xaaaabbbb));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);

        auto callback1 = [](MaatEngine& engine, void* data)
        {
            _assert(engine.cpu.ctx().get(2).as_uint() == 0xf2, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(3).as_uint() == 0xf3, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->addr.as_uint() == 0x60000, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->value.is_none(), "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->written == false, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->read == true, "MaatEngine: event hook failed");
            return event::Action::CONTINUE;
        };

        auto callback2 = [](MaatEngine& engine, void* data)
        {
            _assert(engine.cpu.ctx().get(2).as_uint() == 0xf2, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(3).as_uint() == 0xf3, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->addr.as_uint() == 0x60000, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->value.as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->written == false, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->read == true, "MaatEngine: event hook failed");
            return event::Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(event::Event::MEM_R, event::When::BEFORE, {EventCallback(callback1), _cb1}, "mem_r_b", event::AddrFilter(0x60000));
        engine.hooks.add(event::Event::MEM_RW, event::When::AFTER, {EventCallback(callback2), _cb2}, "mem_r_a", event::AddrFilter(0x60000));
        engine.run_from(0x200);
        // cb2 halts execution
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x201, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(5).as_uint() == 0xaaaaaaaa, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(2).as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");

        // Memory read/write
        engine.mem->write(0x60000, exprcst(32, 0xccccaaaa));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);

        auto callback3 = [](MaatEngine& engine, void* data)
        {
            _assert(engine.info.addr == 0x200 or engine.info.addr == 0x202, "MaatEngine: event hook failed");
            if (engine.info.addr == 0x200)
            {
                _assert(engine.cpu.ctx().get(2).as_uint() == 0xf2, "MaatEngine: event hook failed");
                _assert(engine.cpu.ctx().get(3).as_uint() == 0xf3, "MaatEngine: event hook failed");
                _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->addr.as_uint() == 0x60000, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->written == false, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->read == true, "MaatEngine: event hook failed");
            }
            else
            {
                _assert(engine.cpu.ctx().get(3).as_uint() == 0xf3, "MaatEngine: event hook failed");
                _assert(*engine.info.addr == 0x202, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->addr.as_uint() == 0x60000, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->written == true, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->read == false, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->value.as_uint() == 0x2, "MaatEngine: event hook failed");
            }
            return event::Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(event::Event::MEM_RW, event::When::BEFORE, {event::EventCallback(callback3), _cb3},  "mem_rw", AddrFilter(0x60001,0x60002));
        engine.run_from(0x200);
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x201, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(6).as_uint() == 0xcafebabe, "MaatEngine: event hook failed");
        engine.run();
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x202, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x203, "MaatEngine: event hook failed");

        return nb;
    }

 
    unsigned int exec_event(MaatEngine& engine)
    {
        unsigned int nb = 0;
        ir::AsmInst asm_inst;

        ADD_ASM_INST(0x200, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(10, 31, 0)))
        ADD_ASM_INST(0x201, ir::Inst(ir::Op::COPY, ir::Reg(1, 31, 0), ir::Cst(11, 31, 0)))
        ADD_ASM_INST(0x202, ir::Inst(ir::Op::COPY, ir::Reg(2, 31, 0), ir::Cst(12, 31, 0)))
        ADD_ASM_INST(0x203, ir::Inst(ir::Op::COPY, ir::Reg(10, 31, 0), ir::Cst(42, 31, 0)))

        engine.hooks.disable_all();
        engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x200));
        engine.hooks.add(Event::EXEC, When::AFTER, {_cb3, _cb2}, "", AddrFilter(0x201));
        engine.cpu.ctx().set(0, 0x0);
        engine.cpu.ctx().set(1, 0x0);
        engine.cpu.ctx().set(6, 0x0);
        engine.run_from(0x200);
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x200, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(0).as_uint() == 0, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
        engine.run();
        nb += _assert(engine.cpu.ctx().get(6).as_uint() == 0xcafebabe, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x202, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(1).as_uint() == 11, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: event hook failed");

        return nb;
    }

    unsigned int branch_events(MaatEngine& engine)
    {
        unsigned int nb = 0;
        ir::AsmInst asm_inst;

        Expr    e0 = exprvar(32, "e0"),
                e1 = exprvar(32, "e1"),
                e2 = exprvar(32, "e2");

        // Native branch
        ADD_ASM_INST(0x200, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(1, 31, 0)))
        ADD_ASM_INST(0x201, ir::Inst(ir::Op::BRANCH, std::nullopt, ir::Reg(1, 31, 0)))
        ADD_ASM_INST(0x202, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(2, 31, 0)))

        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, 0x123456);
        engine.cpu.ctx().set(2, e2);

        auto callback1 = [](MaatEngine& engine, void* data)
        {
            _assert(*engine.info.addr == 0x201, "MaatEngine: event hook failed");
            _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
            _assert(engine.info.branch->target.as_uint() == 0x123456, "MaatEngine: event hook failed");
            _assert(engine.info.branch->next.as_uint() == 0x202, "MaatEngine: event hook failed");
            _assert(engine.info.branch->cond == nullptr, "MaatEngine: event hook failed");
            return Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(Event::BRANCH, When::BEFORE, {EventCallback(callback1), _cb1}, "branch");
        engine.run_from(0x200, 2);
        nb += _assert(engine.cpu.ctx().get(6).as_uint() == 0xcafebabe, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x123456, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");

    
        // check that it doesn't trigger on pcode branch
        ADD_ASM_INST(0x300, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(0, 31, 0)))
        std::vector<ir::Inst> tmp_insts = {
            ir::Inst(ir::Op::BRANCH, std::nullopt, ir::Cst(1, 31, 0)),
            ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(0, 31, 0)),
            ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(0, 31, 0))
        };
        ADD_ASM_INST_MULTIPLE(
            0x301,
            tmp_insts   
        )
        ADD_ASM_INST(0x302, ir::Inst(ir::Op::BRANCH, std::nullopt, ir::Addr(0x123456, 32)))

        engine.cpu.ctx().set(0, 0xaaaaa);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, 0);
        
        auto callback2 = [](MaatEngine& engine, void* data)
        {
            _assert(*engine.info.addr == 0x302, "MaatEngine: event hook failed");
            _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
            _assert(engine.info.branch->target.as_uint() == 0x123456, "MaatEngine: event hook failed");
            _assert(engine.info.branch->next.as_uint() == 0x303, "MaatEngine: event hook failed");
            _assert(engine.info.branch->cond == nullptr, "MaatEngine: event hook failed");
            return Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(Event::BRANCH, When::BEFORE, EventCallback(callback2));
        engine.run_from(0x300);


        // conditional branch (taken)
        ADD_ASM_INST(0x400, ir::Inst(ir::Op::COPY, ir::Reg(2, 31, 0), ir::Reg(2, 31, 0), std::nullopt, std::nullopt))
        ADD_ASM_INST(0x401, ir::Inst(ir::Op::CBRANCH, std::nullopt, ir::Reg(0, 31, 0), ir::Reg(1, 31, 0), std::nullopt))
        ADD_ASM_INST(0x402, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(2, 31, 0), std::nullopt, std::nullopt))

        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, 0x1);
        engine.cpu.ctx().set(2, e2);
        
        auto callback3 = [](MaatEngine& engine, void* data)
        {
            _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
            _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
            _assert(engine.info.branch->target.as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
            _assert(engine.info.branch->next.as_uint() == 0x402, "MaatEngine: event hook failed");
            _assert(engine.info.branch->cond != nullptr, "MaatEngine: event hook failed");
            return Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(Event::BRANCH, When::AFTER, EventCallback(callback3));
        engine.run_from(0x400);

        // conditional branch (not taken)
        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, e2);

        auto callback4 = [](MaatEngine& engine, void* data)
        {
            _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
            _assert(*engine.info.branch->taken == false, "MaatEngine: event hook failed");
            _assert(engine.info.branch->target.as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
            _assert(engine.info.branch->next.as_uint() == 0x402, "MaatEngine: event hook failed");
            _assert(engine.info.branch->cond != nullptr, "MaatEngine: event hook failed");
            return Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(Event::BRANCH, When::AFTER, EventCallback(callback4));
        engine.run_from(0x400);

        return nb;
    }
    
 
    unsigned int path_event(MaatEngine& engine)
    {
        unsigned int nb = 0;
        ir::AsmInst asm_inst;

        Expr    e0 = exprvar(32, "e0"),
                e1 = exprvar(32, "e1"),
                e2 = exprvar(32, "e2");

        // concolic path constraint
        ADD_ASM_INST(0x400, ir::Inst(ir::Op::INT_ADD, ir::Reg(2, 31, 0), ir::Reg(2, 31, 0), ir::Cst(1, 31, 0)))
        ADD_ASM_INST(0x401, ir::Inst(ir::Op::CBRANCH, std::nullopt, ir::Reg(0, 31, 0), ir::Reg(1, 31, 0)))
        ADD_ASM_INST(0x402, ir::Inst(ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(2, 31, 0)))

        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, e0);
        engine.cpu.ctx().set(2, 0x0);
        engine.vars->set("e0", 0x12);

        auto callback1 = [](MaatEngine& engine, void* data)
        {
            _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
            _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
            _assert(engine.info.branch->target.as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
            _assert(engine.info.branch->next.as_uint() == 0x402, "MaatEngine: event hook failed");
            _assert(engine.info.branch->cond != nullptr , "MaatEngine: event hook failed");
            return Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(Event::PATH, When::AFTER, EventCallback(callback1));
        engine.run_from(0x400);
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");

        // symbolic path constraint
        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, 0);
        engine.vars->remove("e1");
        
        auto callback2 = [](MaatEngine& engine, void* data)
        {
            _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
            _assert(not engine.info.branch->taken.has_value(), "MaatEngine: event hook failed");
            _assert(engine.info.branch->target.as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
            _assert(engine.info.branch->next.as_uint() == 0x402, "MaatEngine: event hook failed");
            _assert(engine.info.branch->cond != nullptr , "MaatEngine: event hook failed");
            engine.info.branch->taken = false;
            return Action::HALT;
        };

        engine.hooks.disable_all();
        engine.hooks.add(Event::PATH, When::BEFORE, EventCallback(callback2));
        engine.run_from(0x400);
        nb += _assert(engine.info.stop == info::Stop::HOOK, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc()).as_uint() == 0x402, "MaatEngine: event hook failed");

        return nb;
    }


} // namespace events
} // namespace test



using namespace test::events;


// All unit tests 
void test_events()
{
    maat::MaatEngine engine(maat::Arch::Type::NONE);
    engine.mem->map(0x60000, 0x70000);
    engine.mem->map(0x120000, 0x124000);
    engine.mem->map(0x0, 0x2000);

    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing event hooks... " << std::flush;

    total += reg_events(engine);
    total += mem_events(engine);
    total += exec_event(engine);
    total += branch_events(engine);
    total += path_event(engine);

    std::cout   << "\t\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;
}

