#include "breakpoint.hpp"
#include "engine.hpp"
#include "ir.hpp"


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
    
    unsigned int reg_events(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprcst(32, 0xf0),
                e1 = exprcst(32, 0xf1),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);
        
        // Register write
        auto block = std::make_shared<ir::Block>("0x0", 0, 0xff);

        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        block->add_inst(ir::Inst(0 , ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(0, 31, 0)));
        block->add_inst(ir::Inst(1, ir::Op::COPY, ir::Reg(1, 31, 0), ir::Cst(1, 31, 0)));
        block->add_inst(ir::Inst(2, ir::Op::COPY, ir::Reg(2, 31, 0), ir::Cst(2, 31, 0)));
        block->add_inst(ir::Inst(3, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Cst(3, 31, 0)));
        engine.ir_blocks->add(block);

        auto callback1 = [](MaatEngine& engine)
        {
            _assert(engine.info.stop == info::Stop::NONE, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(0)->as_uint() == 0xf0, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(1)->as_uint() == 0xf1, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->reg == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->written == true, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->read == false, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->value->as_uint() == 0xf0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->new_value->as_uint() == 0x0, "MaatEngine: event hook failed");
            return event::Action::HALT;
        };

        auto callback2 = [](MaatEngine& engine)
        {
            _assert(engine.info.stop == info::Stop::NONE, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(0)->as_uint() == 0x0, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(1)->as_uint() == 0xf1, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->reg == 0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->written == true, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->read == false, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->value->as_uint() == 0x0, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->new_value->as_uint() == 0x0, "MaatEngine: event hook failed");
            return event::Action::CONTINUE;
        };

        engine.events.disable_all();
        engine.events.hook(event::Event::REG_W, event::When::BEFORE , EventCallback(callback1), "reg_w_b");
        engine.events.hook(event::Event::REG_W, event::When::AFTER , EventCallback(callback2), "reg_w_a");
        engine.run_from(0, 3);
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc())->as_uint() == 1, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::EVENT, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0, "MaatEngine: event hook failed");


        // Register read
        block = std::make_shared<ir::Block>("0x100", 0x100, 0x1ff);

        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        block->add_inst(ir::Inst(0x100 , ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(0, 31, 0)));
        block->add_inst(ir::Inst(0x101, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Reg(2, 31, 0)));
        block->add_inst(ir::Inst(0x102, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Cst(42, 31, 0)));
        block->add_inst(ir::Inst(0x103, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Cst(41, 31, 0)));
        engine.ir_blocks->add(block);

        auto callback3 = [](MaatEngine& engine)
        {
            _assert(engine.cpu.ctx().get(0)->as_uint() == 0x0, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(3)->as_uint() == 0xf3, "MaatEngine: event hook failed");
            _assert(engine.info.stop == info::Stop::NONE, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0x101, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->reg == 2, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->written == false, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->read == true, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->value->as_uint() == 0xf2, "MaatEngine: event hook failed");
            _assert(engine.info.reg_access->new_value->as_uint() == 0xf2, "MaatEngine: event hook failed");
            return event::Action::CONTINUE;
        };

        auto callback4 = [](MaatEngine& engine)
        {
            if (engine.info.reg_access->read)
            {
                _assert(engine.cpu.ctx().get(0)->as_uint() == 0x0, "MaatEngine: event hook failed");
                _assert(engine.cpu.ctx().get(3)->as_uint() == 0xf3, "MaatEngine: event hook failed");
                _assert(*engine.info.addr == 0x101, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->reg == 2, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->written == false, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->read == true, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->value->as_uint() == 0xf2, "MaatEngine: event hook failed");
                _assert(engine.info.reg_access->new_value->as_uint() == 0xf2, "MaatEngine: event hook failed");
            }
            return event::Action::CONTINUE;
        };

        engine.events.disable_all();
        engine.events.hook(event::Event::REG_R, event::When::BEFORE, event::EventCallback(callback3), "reg_r_a");
        engine.events.hook(event::Event::REG_RW, event::When::AFTER, event::EventCallback(callback4), "reg_r_b");
        engine.run_from(0x100, 3);
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc())->as_uint() == 0x103, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::INST_COUNT, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x103, "MaatEngine: event hook failed");

        return nb;
    }

  
    // Some callbacks for tests
    event::Action _cb1_n(MaatEngine& engine)
    {
        engine.cpu.ctx().set(5, 0x12345678);
        return event::Action::CONTINUE;
    }
    event::EventCallback _cb1(_cb1_n);

    event::Action _cb2_n(MaatEngine& engine)
    {
        engine.cpu.ctx().set(5, 0xaaaaaaaa);
        return event::Action::HALT;
    }
    event::EventCallback _cb2(_cb2_n);
    
    event::Action _cb3_n(MaatEngine& engine)
    {
        engine.cpu.ctx().set(6, 0xcafebabe);
        return event::Action::CONTINUE;
    }
    event::EventCallback _cb3(_cb3_n);

    unsigned int mem_events(MaatEngine& engine)
    {
        unsigned int nb = 0;
        
        Expr    e0 = exprcst(32, 0xf0),
                e1 = exprcst(32, 0xf1),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);
        
        auto block = std::make_shared<ir::Block>("at_0x200", 0x200, 0x2ff);
        block->add_inst(ir::Inst(0x200, ir::Op::LOAD, ir::Reg(2, 31, 0), ir::Param::None(), ir::Reg(0, 31, 0)));
        block->add_inst(ir::Inst(0x201, ir::Op::COPY, ir::Addr(0x61000, 32), ir::Reg(3, 31, 0)));
        block->add_inst(ir::Inst(0x202, ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(0, 31, 0), ir::Cst(2, 31, 0)));
        block->add_inst(ir::Inst(0x203, ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(1, 31, 0), ir::Cst(42, 31, 0)));
        
        engine.ir_blocks->add(block);
        
        // Memory read 
        engine.mem->write(0x60000, exprcst(32, 0xaaaabbbb));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);

        auto callback1 = [](MaatEngine& engine)
        {
            _assert(engine.cpu.ctx().get(2)->as_uint() == 0xf2, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(3)->as_uint() == 0xf3, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
            _assert(not engine.info.mem_access->value, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->written == false, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->read == true, "MaatEngine: event hook failed");
            return event::Action::CONTINUE;
        };

        auto callback2 = [](MaatEngine& engine)
        {
            _assert(engine.cpu.ctx().get(2)->as_uint() == 0xf2, "MaatEngine: event hook failed");
            _assert(engine.cpu.ctx().get(3)->as_uint() == 0xf3, "MaatEngine: event hook failed");
            _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->value->as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->written == false, "MaatEngine: event hook failed");
            _assert(engine.info.mem_access->read == true, "MaatEngine: event hook failed");
            return event::Action::HALT;
        };

        engine.events.disable_all();
        engine.events.hook(event::Event::MEM_R, event::When::BEFORE, {EventCallback(callback1), _cb1}, "mem_r_b", event::AddrFilter(0x60000));
        engine.events.hook(event::Event::MEM_RW, event::When::AFTER, {EventCallback(callback2), _cb2}, "mem_r_a", event::AddrFilter(0x60000));
        engine.run_from(0x200);
        // cb2 halts execution
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc())->as_uint() == 0x201, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::EVENT, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(5)->as_uint() == 0xaaaaaaaa, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(2)->as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");

        // Memory read/write
        engine.mem->write(0x60000, exprcst(32, 0xccccaaaa));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);

        auto callback3 = [](MaatEngine& engine)
        {
            _assert(engine.info.addr == 0x200 or engine.info.addr == 0x202, "MaatEngine: event hook failed");
            if (engine.info.addr == 0x200)
            {
                _assert(engine.cpu.ctx().get(2)->as_uint() == 0xf2, "MaatEngine: event hook failed");
                _assert(engine.cpu.ctx().get(3)->as_uint() == 0xf3, "MaatEngine: event hook failed");
                _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->written == false, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->read == true, "MaatEngine: event hook failed");
            }
            else
            {
                _assert(engine.cpu.ctx().get(3)->as_uint() == 0xf3, "MaatEngine: event hook failed");
                _assert(*engine.info.addr == 0x202, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->size == 4, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->written == true, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->read == false, "MaatEngine: event hook failed");
                _assert(engine.info.mem_access->value->as_uint() == 0x2, "MaatEngine: event hook failed");
            }
            return event::Action::HALT;
        };

        engine.events.disable_all();
        engine.events.hook(event::Event::MEM_RW, event::When::BEFORE, {event::EventCallback(callback3), _cb3},  "mem_rw", AddrFilter(0x60001,0x60002));
        engine.run_from(0x200);
        nb += _assert(engine.info.stop == info::Stop::EVENT, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc())->as_uint() == 0x201, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(6)->as_uint() == 0xcafebabe, "MaatEngine: event hook failed");
        engine.run();
        nb += _assert(engine.info.stop == info::Stop::EVENT, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x202, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(engine.arch->pc())->as_uint() == 0x203, "MaatEngine: event hook failed");

        return nb;
    }

/* 
    unsigned int addr_breakpoints(MaatEngine& engine)
    {
        unsigned int nb = 0;

        auto block = std::make_shared<ir::Block>("at_0x200", 0x200, 0x2ff);
        block->add_inst(ir::Inst(0x200, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(10, 31, 0)));
        block->add_inst(ir::Inst(0x201, ir::Op::COPY, ir::Reg(1, 31, 0), ir::Cst(11, 31, 0)));
        block->add_inst(ir::Inst(0x202, ir::Op::COPY, ir::Reg(2, 31, 0), ir::Cst(12, 31, 0)));
        engine.ir_blocks->add(block);

        // Break on address
        engine.bp_manager.disable_all();
        engine.bp_manager.add_addr_bp(0x200, "a1");
        engine.bp_manager.add_addr_bp(0x201, "a2");
        engine.cpu.ctx().set(0, 0x0);
        engine.cpu.ctx().set(1, 0x0);
        engine.run_from(0x200);

        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 0, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "a1", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: event hook failed");

        engine.run();
        
        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 10, "MaatEngine: event hook failed");
        nb += _assert(engine.cpu.ctx().get(1)->as_uint() == 0, "MaatEngine: event hook failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "a2", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: event hook failed");

        engine.bp_manager.disable_all();
        return nb;
    }

    unsigned int branch_breakpoints(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprvar(32, "e0"),
                e1 = exprvar(32, "e1"),
                e2 = exprvar(32, "e2");

        // Native branch
        auto block = std::make_shared<ir::Block>("at_0x200", 0x200, 0x2ff);
        block->add_inst(ir::Inst(0x200, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(1, 31, 0)));
        block->add_inst(ir::Inst(0x201, ir::Op::BRANCH, std::nullopt, ir::Reg(1, 31, 0)));
        block->add_inst(ir::Inst(0x202, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(2, 31, 0)));
        engine.ir_blocks->add(block);

        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, 0x123456);
        engine.cpu.ctx().set(2, e2);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(event::Event::BRANCH, "branch");
        engine.run_from(0x200);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "branch", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0x123456, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->next == nullptr, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->cond == nullptr, "MaatEngine: event hook failed");
        
        // check that it doesn't trigger on pcode branch
        block = std::make_shared<ir::Block>("at_0x400", 0x300, 0x3ff);
        block->add_inst(ir::Inst(0x300, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(0, 31, 0)));
        block->add_inst(ir::Inst(0x301, ir::Op::BRANCH, std::nullopt, ir::Cst(2, 31, 0)));
        block->add_inst(ir::Inst(0x301, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(0, 31, 0)));
        block->add_inst(ir::Inst(0x301, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(0, 31, 0)));
        block->add_inst(ir::Inst(0x302, ir::Op::BRANCH, std::nullopt, ir::Addr(0x123456, 32)));
        engine.ir_blocks->add(block);

        engine.cpu.ctx().set(0, 0xaaaaa);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, 0);
        engine.run_from(0x300);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "branch", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x302, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0x123456, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->next == nullptr, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->cond == nullptr, "MaatEngine: event hook failed");

        // conditional branch (taken)
        block = std::make_shared<ir::Block>("at_0x400", 0x400, 0x4ff);
        block->add_inst(ir::Inst(0x400, ir::Op::COPY, ir::Reg(2, 31, 0), ir::Reg(2, 31, 0), std::nullopt, std::nullopt, 1));
        block->add_inst(ir::Inst(0x401, ir::Op::CBRANCH, std::nullopt, ir::Reg(0, 31, 0), ir::Reg(1, 31, 0), std::nullopt, 1 ));
        block->add_inst(ir::Inst(0x402, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(2, 31, 0), std::nullopt, std::nullopt, 1));
        engine.ir_blocks->add(block);

        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, 0x1);
        engine.cpu.ctx().set(2, e2);
        engine.run_from(0x400);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "branch", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x402, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: event hook failed"); 

        // conditional branch (not taken)
        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, e2);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(event::Event::CBRANCH, "cbranch");
        engine.run_from(0x400);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "cbranch", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.branch->taken == false, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x402, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: event hook failed");

        return nb;
    }
    
 

    unsigned int path_breakpoint(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprvar(32, "e0"),
                e1 = exprvar(32, "e1"),
                e2 = exprvar(32, "e2");

        // concolic path constraint
        auto block = std::make_shared<ir::Block>("at_0x400", 0x400, 0x4ff);
        block->add_inst(ir::Inst(0x400, ir::Op::INT_ADD, ir::Reg(2, 31, 0), ir::Reg(2, 31, 0), ir::Cst(1, 31, 0), std::nullopt, 1));
        block->add_inst(ir::Inst(0x401, ir::Op::CBRANCH, std::nullopt, ir::Reg(0, 31, 0), ir::Reg(1, 31, 0), std::nullopt, 2 ));
        block->add_inst(ir::Inst(0x403, ir::Op::COPY, ir::Reg(0, 31, 0), ir::Reg(2, 31, 0), std::nullopt, std::nullopt, 1));
        engine.ir_blocks->add(block);
        // Add another block because we test on Arch::NONE so if we branch to 0xaaaabbbb 
        // it will try to lift it and crash (because no lifters for the NONE arch). So
        // we add it manually
        block = std::make_shared<ir::Block>("at_0xaaaabbbb", 0xaaaabbbb, 0xaaaabbbf);
        block->add_inst(ir::Inst(0xaaaabbbb, ir::Op::COPY, ir::Reg(0, 32), ir::Reg(0, 32)));
        engine.ir_blocks->add(block);

        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, e0);
        engine.cpu.ctx().set(2, 0x0);
        engine.vars->set("e0", 0x12);
        engine.bp_manager.add_bp(event::Event::PATH, "path");
        engine.run_from(0x400);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "path", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x403, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: event hook failed"); 
        
        // Finish to run the instruction
        engine.run(1);
        nb += _assert(engine.info.stop == info::Stop::INST_COUNT, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0xaaaabbbb, "MaatEngine: event hook failed");


        // symbolic path constraint
        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, 0);
        engine.vars->remove("e1");
        engine.run_from(0x400);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: event hook failed");
        nb += _assert(*engine.info.bp_name == "path", "MaatEngine: event hook failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: event hook failed");
        nb += _assert(!engine.info.branch->taken.has_value(), "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x403, "MaatEngine: event hook failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: event hook failed");

        return nb;
    }


*/
} // namespace events
} // namespace test



using namespace test::events;


// All unit tests 
void test_events()
{
    maat::MaatEngine engine(maat::Arch::Type::NONE);
    engine.mem->new_segment(0x60000, 0x70000);
    engine.mem->new_segment(0x0, 0x2000);

    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing event hooks... " << std::flush;

    total += reg_events(engine);
    total += mem_events(engine);
    // total += addr_breakpoints(engine);
    // total += symptr_breakpoints(engine);
    // total += branch_breakpoints(engine);
    // total += tainted_reg_breakpoints(engine);
    // total += tainted_mem_breakpoints(engine);
    // total += path_breakpoint(engine);
    // total += callbacks(engine);

    std::cout   << "\t\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;
}

