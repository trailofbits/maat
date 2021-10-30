#include "breakpoint.hpp"
#include "engine.hpp"
#include "ir.hpp"

namespace test
{
namespace breakpoint
{        
    using namespace maat;

    unsigned int _assert(bool val, const std::string& msg)
    {
        if( !val)
        {
            std::cout << "\nFail: " << msg << std::endl; 
            throw test_exception();
        }
        return 1; 
    }
    
    unsigned int reg_breakpoints(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprcst(32, 0xf0),
                e1 = exprcst(32, 0xf1),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);
        
        // Break on register write
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

        engine.bp_manager.add_reg_bp(bp::Event::REG_W, (reg_t)0, "reg_w");
        engine.run_from(0);
        engine.bp_manager.disable_all();

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(1)->as_uint() == 0xf1, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "reg_w", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->reg == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->read == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->old_value->as_uint() == 0xf0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->new_value->as_uint() == 0, "MaatEngine: breakpoint failed");

        // Break on register read
        block = std::make_shared<ir::Block>("0x100", 0x100, 0x1ff);

        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        block->add_inst(ir::Inst(0x100 , ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(0, 31, 0)));
        block->add_inst(ir::Inst(0x101, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Reg(2, 31, 0)));
        block->add_inst(ir::Inst(0x102, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Reg(1, 31, 0)));
        engine.ir_blocks->add(block);

        engine.bp_manager.add_reg_bp(bp::Event::REG_R, (reg_t)2, "reg_r");
        engine.run_from(0x100);
        engine.bp_manager.disable_all();

        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(3)->eq(e2), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "reg_r", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x101, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->reg == 2, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->read == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->old_value->eq(e2), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->new_value->eq(e2), "MaatEngine: breakpoint failed");

        // Break on register read/write
        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);

        engine.bp_manager.add_reg_bp(bp::Event::REG_RW, (reg_t)1, "reg_rw");
        engine.run_from(0x0);

        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "reg_rw", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x1, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->reg == 1, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->read == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->old_value->as_uint() == 0xf1, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->new_value->as_uint() == 0x1, "MaatEngine: breakpoint failed");
        
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        engine.run_from(0x100);
        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(3)->eq(e1), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "reg_rw", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x102, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->reg == 1, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->read == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->old_value->eq(e1), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->new_value->eq(e1), "MaatEngine: breakpoint failed");

        engine.bp_manager.disable_all();
        return nb;
    }
    
    unsigned int mem_breakpoints(MaatEngine& engine)
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
        engine.ir_blocks->add(block);
        
        // Break on memory read 
        engine.mem->write(0x60000, exprcst(32, 0xaaaabbbb));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_mem_bp(bp::Event::MEM_R, 0x60000, 0x60000, "mem_r");
        engine.run_from(0x200);

        nb += _assert(engine.cpu.ctx().get(2)->as_uint() == 0xaaaabbbb, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(3)->eq(e3), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "mem_r", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->old_value->eq(exprcst(32, 0xaaaabbbb)), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->new_value->eq(exprcst(32, 0xaaaabbbb)), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == true, "MaatEngine: breakpoint failed");

        // Break on memory write
        engine.mem->write(0x61000, exprcst(32, 0x87654321));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_mem_bp(bp::Event::MEM_W, 0x61002, 0x61003, "mem_w");
        engine.run_from(0x200);

        nb += _assert(engine.cpu.ctx().get(3)->eq(e3), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "mem_w", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->as_uint() == 0x61000, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->new_value->eq(e3), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->old_value->as_uint() == 0x87654321, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == false, "MaatEngine: breakpoint failed");

        // Break on memory read/write
        engine.mem->write(0x60000, exprcst(32, 0xccccaaaa));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_mem_bp(bp::Event::MEM_RW, 0x60002, 0x60002, "mem_rw");

        engine.run_from(0x200);
        nb += _assert(engine.cpu.ctx().get(3)->eq(e3), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "mem_rw", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == true, "MaatEngine: breakpoint failed");

        engine.run();
        nb += _assert(engine.cpu.ctx().get(3)->eq(e3), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "mem_rw", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x202, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->new_value->as_uint() == 0x2, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->old_value->as_uint() == 0xccccaaaa, "MaatEngine: breakpoint failed");
        
        return nb;
    }
    
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

        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "a1", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: breakpoint failed");

        engine.run();
        
        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 10, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(1)->as_uint() == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "a2", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: breakpoint failed");

        engine.bp_manager.disable_all();
        return nb;
    }
    
    unsigned int symptr_breakpoints(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprvar(32, "e0"),
                e1 = exprvar(32, "e1"),
                e2 = exprvar(32, "e2");

        // Disable heavy symptr options
        engine.settings.symptr_refine_range = false;
        engine.settings.symptr_limit_range = true;
        engine.settings.symptr_max_range = 20;

        auto block = std::make_shared<ir::Block>("at_0x200", 0x200, 0x2ff);
        block->add_inst(ir::Inst(0x200, ir::Op::LOAD, ir::Reg(0, 31, 0), ir::Param::None(), ir::Reg(0, 31, 0)));
        block->add_inst(ir::Inst(0x201, ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(1, 31, 0), ir::Reg(2, 31, 0)));
        block->add_inst(ir::Inst(0x202, ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(2, 31, 0), ir::Cst(2, 31, 0)));
        engine.ir_blocks->add(block);

        // Break on symbolic pointer read 
        engine.mem->write(0x60000, exprcst(32, 0xaaaabbbb));
        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(bp::Event::SYMPTR_R, "sym_r");
        engine.run_from(0x200);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "sym_r", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->eq(e0), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->old_value->eq(engine.cpu.ctx().get(0)), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == true, "MaatEngine: breakpoint failed");

        // Break on concolic pointer write
        engine.cpu.ctx().set(0, exprcst(32, 0x42));
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, e2);
        engine.vars->set("e1", 0x60000);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(bp::Event::SYMPTR_W, "sym_w");
        engine.run_from(0x200);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "sym_w", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->eq(e1), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->new_value->eq(e2), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->old_value == nullptr, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == false, "MaatEngine: breakpoint failed");

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
        engine.bp_manager.add_bp(bp::Event::BRANCH, "branch");
        engine.run_from(0x200);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "branch", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0x123456, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->next == nullptr, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->cond == nullptr, "MaatEngine: breakpoint failed");
        
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

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "branch", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x302, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0x123456, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->next == nullptr, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->cond == nullptr, "MaatEngine: breakpoint failed");

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

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "branch", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x402, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: breakpoint failed"); 

        // conditional branch (not taken)
        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, e2);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(bp::Event::CBRANCH, "cbranch");
        engine.run_from(0x400);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "cbranch", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.branch->taken == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x402, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: breakpoint failed");

        return nb;
    }
    
    unsigned int tainted_reg_breakpoints(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprvar(32, "e0"),
                e1 = exprvar(32, "e1"),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);

        // Break on register write
        auto block = std::make_shared<ir::Block>("0x0", 0, 0xff);

        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, 0xf2);
        engine.cpu.ctx().set(3, 0xf3);
        block->add_inst(ir::Inst(0 , ir::Op::COPY, ir::Reg(2, 31, 0), ir::Cst(7, 31, 0)));
        block->add_inst(ir::Inst(1, ir::Op::COPY, ir::Reg(2, 31, 0), ir::Reg(0, 31, 0)));
        block->add_inst(ir::Inst(2, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Reg(1, 31, 0)));
        engine.ir_blocks->add(block);

        engine.bp_manager.add_bp(bp::Event::TAINTED_REG_W, "t_reg_w");
        engine.run_from(0);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "t_reg_w", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 1, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->reg == 2, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->read == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->old_value->as_uint() == 7, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->new_value->eq(e0), "MaatEngine: breakpoint failed");

        // Break on register read
        engine.cpu.ctx().set(0, e0);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, 0xf2);
        engine.cpu.ctx().set(3, 0xf3);

        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(bp::Event::TAINTED_REG_R, "t_reg_r");
        engine.run_from(0x0);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "t_reg_r", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x1, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->reg == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->read == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->old_value->eq(e0), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->new_value->eq(e0), "MaatEngine: breakpoint failed");

        engine.bp_manager.disable_all();
        return nb;
    }
    
    
    unsigned int tainted_mem_breakpoints(MaatEngine& engine)
    {
        unsigned int nb = 0;
        
        Expr    e0 = exprvar(32, "e0"),
                e1 = exprcst(32, 0xf1),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);

        auto block = std::make_shared<ir::Block>("at_0x200", 0x200, 0x2ff);
        block->add_inst(ir::Inst(0x200, ir::Op::LOAD, ir::Reg(2, 31, 0), ir::Param::None(), ir::Reg(0, 31, 0)));
        block->add_inst(ir::Inst(0x201, ir::Op::COPY, ir::Addr(0x61000, 32), ir::Reg(3, 31, 0)));
        block->add_inst(ir::Inst(0x202, ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(0, 31, 0), ir::Cst(2, 31, 0)));
        engine.ir_blocks->add(block);
        
        // Break on tainted memory read 
        engine.mem->write(0x60000, e0);
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e3);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(bp::Event::TAINTED_MEM_R, "t_mem_r");
        engine.run_from(0x200);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "t_mem_r", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x200, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->as_uint() == 0x60000, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->old_value->eq(e0), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->new_value->eq(e0), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == true, "MaatEngine: breakpoint failed");

        // Break on memory write
        engine.mem->write(0x61000, exprcst(32, 0x87654321));
        engine.cpu.ctx().set(0, exprcst(32, 0x60000));
        engine.cpu.ctx().set(1, exprcst(32, 0x61000));
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, e0);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_bp(bp::Event::TAINTED_MEM_W, "t_mem_w");
        engine.run_from(0x200);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "t_mem_w", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x201, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->addr->as_uint() == 0x61000, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->size == 4, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->new_value->eq(e0), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->old_value->as_uint() == 0x87654321, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->written == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.mem_access->read == false, "MaatEngine: breakpoint failed");

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
        engine.bp_manager.add_bp(bp::Event::PATH, "path");
        engine.run_from(0x400);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "path", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.branch->taken == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x403, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: breakpoint failed"); 
        
        // Finish to run the instruction
        engine.run(1);
        nb += _assert(engine.info.stop == info::Stop::INST_COUNT, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0xaaaabbbb, "MaatEngine: breakpoint failed");


        // symbolic path constraint
        engine.cpu.ctx().set(0, 0xaaaabbbb);
        engine.cpu.ctx().set(1, e1);
        engine.cpu.ctx().set(2, 0);
        engine.vars->remove("e1");
        engine.run_from(0x400);

        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "path", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x401, "MaatEngine: breakpoint failed");
        nb += _assert(!engine.info.branch->taken.has_value(), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->target->as_uint() == 0xaaaabbbb, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->next->as_uint() == 0x403, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.branch->cond != nullptr , "MaatEngine: breakpoint failed");

        return nb;
    }

    bp::Action _cb1_n(MaatEngine& engine)
    {
        engine.cpu.ctx().set(5, 0x12345678);
        return bp::Action::CONTINUE;
    }
    bp::BPCallback _cb1(_cb1_n);
    
    bp::Action _cb2_n(MaatEngine& engine)
    {
        engine.cpu.ctx().set(5, 0xaaaaaaaa);
        return bp::Action::HALT;
    }
    bp::BPCallback _cb2(_cb2_n);
    
    bp::Action _cb3_n(MaatEngine& engine)
    {
        engine.cpu.ctx().set(6, 0xcafebabe);
        return bp::Action::CONTINUE;
    }
    bp::BPCallback _cb3(_cb3_n);

    unsigned int callbacks(MaatEngine& engine)
    {
        unsigned int nb = 0;

        Expr    e0 = exprcst(32, 0xf0),
                e1 = exprcst(32, 0xf1),
                e2 = exprcst(32, 0xf2),
                e3 = exprcst(32, 0xf3);
        
        // Continue on AFTER (register write)
        auto block = std::make_shared<ir::Block>("0x0", 0, 0xff);

        block->add_inst(ir::Inst(0 , ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(0, 31, 0)));
        block->add_inst(ir::Inst(1, ir::Op::COPY, ir::Reg(1, 31, 0), ir::Cst(1, 31, 0)));
        block->add_inst(ir::Inst(2, ir::Op::COPY, ir::Reg(2, 31, 0), ir::Cst(2, 31, 0)));
        block->add_inst(ir::Inst(3, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Cst(3, 31, 0)));
        engine.ir_blocks->add(block);

        engine.cpu.ctx().set(0, 0);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, 0);
        engine.cpu.ctx().set(3, 0);
        engine.bp_manager.disable_all();
        engine.bp_manager.add_reg_bp(bp::Event::REG_W, _cb1, (reg_t)0);
        engine.run_from(0x0, 2);

        nb += _assert(engine.info.stop == info::Stop::INST_COUNT, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 2, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(5)->as_uint() == 0x12345678, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(1)->as_uint() == 0x1, "MaatEngine: breakpoint failed");
        

        // Halt on AFTER
        block = std::make_shared<ir::Block>("0x100", 0x100, 0x1ff);

        engine.cpu.ctx().set(0, 1);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, e2);
        engine.cpu.ctx().set(3, 0);

        block->add_inst(ir::Inst(0x100 , ir::Op::COPY, ir::Reg(0, 31, 0), ir::Cst(0, 31, 0)));
        block->add_inst(ir::Inst(0x101, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Reg(2, 31, 0)));
        block->add_inst(ir::Inst(0x102, ir::Op::COPY, ir::Reg(3, 31, 0), ir::Reg(1, 31, 0)));
        engine.ir_blocks->add(block);

        engine.bp_manager.disable_all();
        engine.bp_manager.add_reg_bp(bp::Event::REG_R, _cb2, (reg_t)2, "reg_r2");
        engine.run_from(0x100);

        nb += _assert(engine.cpu.ctx().get(0)->as_uint() == 0, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(3)->eq(e2), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::BP, "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.bp_name == "reg_r2", "MaatEngine: breakpoint failed");
        nb += _assert(*engine.info.addr == 0x101, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->reg == 2, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->written == false, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->read == true, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->old_value->eq(e2), "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.reg_access->new_value->eq(e2), "MaatEngine: breakpoint failed");

        // Several breakpoints on before
        engine.cpu.ctx().set(0, 0);
        engine.cpu.ctx().set(1, 0);
        engine.cpu.ctx().set(2, 0);
        engine.cpu.ctx().set(3, 0);
        engine.cpu.ctx().set(5, 0);
        engine.cpu.ctx().set(6, 0);

        std::vector<bp::BPCallback> cbs{_cb1, _cb3};
        engine.bp_manager.disable_all();
        engine.bp_manager.add_addr_bp(cbs, (addr_t)0x1);
        engine.run_from(0x0, 3);

        nb += _assert(engine.cpu.ctx().get(5)->as_uint() == 0x12345678, "MaatEngine: breakpoint failed");
        nb += _assert(engine.cpu.ctx().get(6)->as_uint() == 0xcafebabe, "MaatEngine: breakpoint failed");
        nb += _assert(engine.info.stop == info::Stop::INST_COUNT, "MaatEngine: breakpoint failed");
       
        engine.bp_manager.disable_all();
        return nb;
    }

} // namespace breakpoint
} // namespace test

using namespace test::breakpoint;
// All unit tests 
void test_breakpoints()
{
    MaatEngine engine(Arch::Type::NONE);
    engine.mem->new_segment(0x60000, 0x70000);
    engine.mem->new_segment(0x0, 0x2000);

    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing breakpoints... " << std::flush;

    total += reg_breakpoints(engine);
    total += mem_breakpoints(engine);
    total += addr_breakpoints(engine);
    total += symptr_breakpoints(engine);
    total += branch_breakpoints(engine);
    total += tainted_reg_breakpoints(engine);
    total += tainted_mem_breakpoints(engine);
    total += path_breakpoint(engine);
    total += callbacks(engine);

    std::cout   << "\t\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;
}

