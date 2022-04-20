#include "maat/arch.hpp"
#include "maat/engine.hpp"
#include "maat/exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include "maat/env/env_EVM.hpp"

using std::string;

namespace test{
    namespace archEVM{

        using namespace maat;
        using namespace maat::env::EVM;

        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl << std::flush; 
                throw test_exception();
            }
            return 1;
        }
 
        unsigned int _assert_bignum_eq(
            const Value& var,
            std::string expected_value,
            std::string error_msg,
            int base=10
        )
        {
            const Number& number = var.as_number();
            Number expected(number.size);
            expected.set_mpz(expected_value, base);
            if (not expected.equal_to(number))
            {
                std::stringstream ss;
                ss << var;
                std::cout << "\nFail: _assert_bignum_eq: " << ss.str() << " is not " << expected_value << std::endl;
                std::cout << "\nFail: " << error_msg << std::endl;
                throw test_exception(); 
            }
            return 1; 
        }

        void setup_dummy_contract(MaatEngine& engine)
        {
            engine.process->pid = get_ethereum(engine)->add_contract(
                std::make_shared<Contract>(
                    engine,
                    Value(256, "86984651684651a5a65665b65f", 16)
                )
            );
        }

        unsigned int reg_translation()
        {
            unsigned int nb = 0;
            reg_t reg;
            EVM::ArchEVM arch = EVM::ArchEVM();
            for (reg = 0; reg < EVM::NB_REGS; reg++)
            {
                nb += _assert( arch.reg_num(arch.reg_name(reg)) == reg , "ArchEVM: translation reg_num <-> reg_name failed");
            }
            nb += _assert(arch.pc() == EVM::PC, "ArchEVM: translation reg_num <-> reg_name failed");
            return nb;
        }

        void write_inst(MaatEngine& engine, addr_t addr, const std::string& code)
        {
            engine.mem->write_buffer(addr, (uint8_t*)code.c_str(), code.size());
            engine.mem->write(addr+code.size(), 0x0, 1);
        }

        unsigned int test_add(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x01", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "21", 10));
            contract->stack.push(Value(256, "7", 10));
            engine.run_from(0x10, 1);

            nb += _assert( contract->stack.get(0).as_uint() == 28,
                            "ArchEVM: failed to disassembly and/or execute ADD");

            return nb;
        }

        unsigned int test_div(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x04", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "3", 10));
            contract->stack.push(Value(256, "21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "7218217218218217217218488488368",
                "ArchEVM: failed to disassembly and/or execute DIV"
            );

            // Division by zero
            contract->stack.push(Value(256, "0", 10));
            contract->stack.push(Value(256, "21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute DIV"
            );

            return nb;
        }

        unsigned int test_sdiv(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x05", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "3", 10));
            contract->stack.push(Value(256, "-21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "-7218217218218217217218488488369",
                "ArchEVM: failed to disassembly and/or execute SDIV"
            );

            // Division by zero
            contract->stack.push(Value(256, "0", 10));
            contract->stack.push(Value(256, "-21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute DIV"
            );

            return nb;
        }

        unsigned int test_mod(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x06", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "3398479384739847938749387430947", 10));
            contract->stack.push(Value(256, "21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "1263775346215564019159140879423",
                "ArchEVM: failed to disassembly and/or execute MOD"
            );

            // Modulo by zero
            contract->stack.push(Value(256, "0", 10));
            contract->stack.push(Value(256, "21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute MOD"
            );

            return nb;
        }

        unsigned int test_smod(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x07", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "-3398479384739847938749387430947", 10));
            contract->stack.push(Value(256, "-21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "-1263775346215564019159140879423",
                "ArchEVM: failed to disassembly and/or execute SMOD"
            );

            contract->stack.push(Value(256, "3398479384739847938749387430947", 10));
            contract->stack.push(Value(256, "-21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "2134704038524283919590246551524",
                "ArchEVM: failed to disassembly and/or execute SMOD"
            );

            // Modulo by zero
            contract->stack.push(Value(256, "0", 10));
            contract->stack.push(Value(256, "-21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute SMOD"
            );

            return nb;
        }

        unsigned int test_addmod(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x08", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "-5", 10));
            contract->stack.push(Value(256, "6542513", 10));
            contract->stack.push(Value(256, "-1", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "6542517",
                "ArchEVM: failed to disassembly and/or execute ADDMOD"
            );

            // Modulo by zero
            contract->stack.push(Value(256, "0", 10));
            contract->stack.push(Value(256, "6542513", 10));
            contract->stack.push(Value(256, "21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute ADDMOD"
            );

            return nb;
        }

        unsigned int test_mulmod(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x09", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "-5", 10));
            contract->stack.push(Value(256, "6684746543", 10));
            contract->stack.push(Value(256, "000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "51173515919254644494219054947542675994107681307330243892244173046669980394647",
                "ArchEVM: failed to disassembly and/or execute MULMOD"
            );

            // Modulo by zero
            contract->stack.push(Value(256, "0", 10));
            contract->stack.push(Value(256, "564651451", 10));
            contract->stack.push(Value(256, "21654651654654651651655465465105", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute MULMOD"
            );

            return nb;
        }

        unsigned int test_signextend(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x0b", 1);
            write_inst(engine, 0x10, code);
            contract_t contract = get_contract_for_engine(engine);

            contract->stack.push(Value(256, "ffff", 16));
            contract->stack.push(Value(256, "1", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "-1",
                "ArchEVM: failed to disassembly and/or execute SIGNEXTEND"
            );

            contract->stack.push(Value(256, "ffff", 16));
            contract->stack.push(Value(256, "2", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "ffff",
                "ArchEVM: failed to disassembly and/or execute SIGNEXTEND",
                16
            );

            contract->stack.push(Value(256, "-23", 10));
            contract->stack.push(Value(256, "31", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "-23",
                "ArchEVM: failed to disassembly and/or execute SIGNEXTEND"
            );

            return nb;
        }

        unsigned int test_lt(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x10", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);

            contract->stack.push(Value(256, "658465465465465165165151654654654654654", 10));
            contract->stack.push(Value(256, "66847465436546516516546516516541", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "1",
                "ArchEVM: failed to disassembly and/or execute LT"
            );

            contract->stack.push(Value(256, "658465465465465165165151654654654654", 10));
            contract->stack.push(Value(256, "-1", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute LT"
            );

            return nb;
        }

        unsigned int test_sgt(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x13", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);

            contract->stack.push(Value(256, "658465465465465165165151654654654654654", 10));
            contract->stack.push(Value(256, "66847465436546516516546516516541", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute SGT"
            );

            contract->stack.push(Value(256, "658465465465465165165151654654654654", 10));
            contract->stack.push(Value(256, "-1", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "1",
                "ArchEVM: failed to disassembly and/or execute SGT"
            );

            return nb;
        }

        unsigned int test_iszero(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x15", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);

            contract->stack.push(Value(256, "1", 10)<<255);
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute ISZERO"
            );

            contract->stack.push(Value(256, "0", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "1",
                "ArchEVM: failed to disassembly and/or execute ISZERO"
            );

            return nb;
        }


        unsigned int test_byte(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x1a", 1);
            write_inst(engine, 0x10, code);
            contract_t contract = get_contract_for_engine(engine);

            contract->stack.push(Value(256, "ffff465135465868686514654846516586684646516168476847", 16));
            contract->stack.push(Value(256, "21", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "35",
                "ArchEVM: failed to disassembly and/or execute BYTE",
                16
            );

            contract->stack.push(Value(256, "-1", 10));
            contract->stack.push(Value(256, "32", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "0",
                "ArchEVM: failed to disassembly and/or execute BYTE"
            );

            contract->stack.push(Value(256, "65465165465165146351", 16));
            contract->stack.push(Value(256, "0", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "51",
                "ArchEVM: failed to disassembly and/or execute BYTE",
                16
            );

            return nb;
        }

        unsigned int test_mload(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x51", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            Value addr(256, "10", 10);

            contract->memory.write(addr, Value(256, "1234", 16));
            contract->stack.push(Value(256, "40", 10));
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "1234000000000000000000000000000000000000000000000000000000000000",
                "ArchEVM: failed to disassembly and/or execute MLOAD",
                16
            );

            return nb;
        }

        unsigned int test_mstore(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x52", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            Value addr(256, "60", 10);

            contract->stack.push(Value(256, "1234", 16));
            contract->stack.push(Value(256, "30", 10));
            engine.run_from(0x10, 1);

            nb += _assert(
                contract->memory.read(addr, 2).as_uint() == 0x1234,
                "ArchEVM: failed to disassembly and/or execute MSTORE"
            );

            return nb;
        }

        unsigned int test_mstore8(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x53", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            Value addr(256, "34", 10);

            contract->stack.push(Value(256, "1234", 16));
            contract->stack.push(addr);
            engine.run_from(0x10, 1);

            nb += _assert(
                contract->memory.read(addr, 1).as_uint() == 0x34,
                "ArchEVM: failed to disassembly and/or execute MSTORE8"
            );

            return nb;
        }

        unsigned int test_jump(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x56", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);

            contract->stack.push(Value(256, "888", 10));
            engine.run_from(0x10, 1);

            nb += _assert(
                engine.cpu.ctx().get(EVM::PC).as_uint() == 888,
                "ArchEVM: failed to disassembly and/or execute JUMP"
            );

            return nb;
        }

        unsigned int test_jumpi(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x57", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);

            contract->stack.push(Value(256, "8000000000000000000000000000000000000000000000", 16));
            contract->stack.push(Value(256, "888", 10));
            engine.run_from(0x10, 1);
            nb += _assert(
                engine.cpu.ctx().get(EVM::PC).as_uint() == 888,
                "ArchEVM: failed to disassembly and/or execute JUMPI"
            );

            contract->stack.push(Value(256, "0"));
            contract->stack.push(Value(256, "888", 10));
            engine.run_from(0x10, 1);
            nb += _assert(
                engine.cpu.ctx().get(EVM::PC).as_uint() == 0x11,
                "ArchEVM: failed to disassembly and/or execute JUMPI"
            );

            return nb;
        }

        unsigned int test_pc(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x58", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            engine.run_from(0x10, 1);

            nb += _assert( contract->stack.get(0).as_uint() == 0x10,
                            "ArchEVM: failed to disassembly and/or execute PC");

            return nb;
        }

        unsigned int test_msize(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x59", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->memory.write(Value(256, 0x10000), Value(8, 0));
            engine.run_from(0x10, 1);

            // Memory expanded by blocks of 32 bytes
            nb += _assert( contract->stack.get(0).as_uint() == 0x10020,
                            "ArchEVM: failed to disassembly and/or execute MSIZE");

            return nb;
        }

        unsigned int test_push(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x60\x42", 2); // push1
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            engine.run_from(0x10, 1);

            nb += _assert( contract->stack.get(0).as_uint() == 0x42,
                            "ArchEVM: failed to disassembly and/or execute PUSH1");
            nb += _assert( engine.cpu.ctx().get(EVM::PC).as_uint() == 0x12,
                            "ArchEVM: failed to disassembly and/or execute PUSH1");


            code = std::string("\x62\x42\x00\xff", 4); // push3
            write_inst(engine, 0x10, code);
            engine.run_from(0x10, 1);

            nb += _assert( contract->stack.get(0).as_uint() == 0x4200ff,
                            "ArchEVM: failed to disassembly and/or execute PUSH3");
            nb += _assert( engine.cpu.ctx().get(EVM::PC).as_uint() == 0x14,
                            "ArchEVM: failed to disassembly and/or execute PUSH3");

            code = std::string("\x7f""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 33); // push32
            write_inst(engine, 0x10, code);
            engine.run_from(0x10, 1);

            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "4141414141414141414141414141414141414141414141414141414141414141",
                "ArchEVM: failed to disassembly and/or execute PUSH32",
                16
            );
            nb += _assert( engine.cpu.ctx().get(EVM::PC).as_uint() == 0x31,
                            "ArchEVM: failed to disassembly and/or execute PUSH32");

            // Reset memory to valid opcodes
            write_inst(engine, 0x10, std::string(0x200, '\x00'));

            return nb;
        }

        unsigned int test_dup(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x80\x00", 2); // dup0
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            
            contract->stack.push(Value(256, 0x42));
            engine.run_from(0x10, 1);
            nb += _assert( contract->stack.get(0).as_uint() == 0x42,
                            "ArchEVM: failed to disassembly and/or execute DUP1");
            nb += _assert( contract->stack.get(1).as_uint() == 0x42,
                            "ArchEVM: failed to disassembly and/or execute DUP1");


            code = std::string("\x8f\x00", 2); // dup16
            write_inst(engine, 0x10, code);
            contract->stack.push(Value(256, 0xaaaaaaaaaaaa));
            for (int i = 0; i < 15; i++)
                contract->stack.push(Value(256, 0));
            engine.run_from(0x10, 1);
            nb += _assert( contract->stack.get(0).as_uint() == 0xaaaaaaaaaaaa,
                            "ArchEVM: failed to disassembly and/or execute DUP16");
            nb += _assert( contract->stack.get(16).as_uint() == 0xaaaaaaaaaaaa,
                            "ArchEVM: failed to disassembly and/or execute DUP16");

            return nb;
        }

        unsigned int test_swap(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            contract_t contract = get_contract_for_engine(engine);
            for (int i = 0; i < 17; i++)
                contract->stack.push(Value(256, i));


            code = std::string("\x90", 1); // swap1
            write_inst(engine, 0x10, code);
            engine.run_from(0x10, 1);
            nb += _assert( contract->stack.get(0).as_uint() == 15,
                            "ArchEVM: failed to disassembly and/or execute SWAP1");
            nb += _assert( contract->stack.get(1).as_uint() == 16,
                            "ArchEVM: failed to disassembly and/or execute SWAP1");

            code = std::string("\x9f", 1); // swap16
            write_inst(engine, 0x10, code);
            engine.run_from(0x10, 1);
            nb += _assert( contract->stack.get(0).as_uint() == 0,
                            "ArchEVM: failed to disassembly and/or execute SWAP16");
            nb += _assert( contract->stack.get(16).as_uint() == 15,
                            "ArchEVM: failed to disassembly and/or execute SWAP16");

            return nb;
        }

        unsigned int test_sload(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
            Value addr;
    
            contract_t contract = get_contract_for_engine(engine);
            code = std::string("\x54", 1); // sload
            write_inst(engine, 0x10, code);
            
            // Basic load at known address
            addr = Value(256, "af66d5f4b5c5d5b55e5e5f5ddeeefa655", 16);
            contract->stack.push(addr);
            contract->storage.write(
                addr,
                Value(256, 42),
                engine.settings
            );
            engine.run_from(0x10, 1);
            nb += _assert( contract->stack.get(0).as_uint() == 42,
                            "ArchEVM: failed to disassembly and/or execute SLOAD");

            // Load at unknown address -> 0
            contract->stack.push(Value(256, 368574691));
            engine.run_from(0x10, 1);
            nb += _assert( contract->stack.get(0).as_uint() == 0,
                            "ArchEVM: failed to disassembly and/or execute SLOAD");


            // Load at known symbolic address
            addr = Value(exprvar(256, "symbolic_address"));
            contract->stack.push(addr);
            contract->storage.write(
                addr,
                Value(256, 12345678),
                engine.settings
            );
            engine.run_from(0x10, 1);
            nb += _assert( contract->stack.get(0).as_uint() == 12345678,
                            "ArchEVM: failed to disassembly and/or execute SLOAD");

            return nb;
        }

        unsigned int test_sstore(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
            Value addr;
    
            contract_t contract = get_contract_for_engine(engine);
            code = std::string("\x55", 1); // sstore
            write_inst(engine, 0x10, code);

            // Basic store at known address
            addr = Value(256, "af66d5f4b5c5d5b55e5e5f5ddeeefa655", 16);
            contract->stack.push(Value(256, 1111));
            contract->stack.push(addr);
            engine.run_from(0x10, 1);
            nb += _assert( contract->storage.read(addr).as_uint() == 1111,
                            "ArchEVM: failed to disassembly and/or execute SSTORE");

            // Store at symbolic address
            addr = Value(exprvar(256, "symbolic_address"));
            contract->stack.push(Value(256, 2222));
            contract->stack.push(addr);
            engine.run_from(0x10, 1);
            nb += _assert( contract->storage.read(addr).as_uint() == 2222,
                            "ArchEVM: failed to disassembly and/or execute SSTORE");

            return nb;
        }

        unsigned int test_keccak_helper()
        {
            unsigned int res = 0;
            KeccakHelper helper;
            const char* s("abc");
            VarContext ctx;
            // Just try to hash "abc"
            Value src(24, 0x616263);
            Value v = helper.apply(ctx, src, (uint8_t*)s);
            return res;
        }

        unsigned int test_keccak(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
            Value addr;
    
            contract_t contract = get_contract_for_engine(engine);
            code = std::string("\x20", 1); // keccak
            write_inst(engine, 0x10, code);

            // Value equivalent to "abc"
            contract->memory.write(Value(256, 100), Value(24, 0x616263));
            contract->stack.push(Value(256, 3)); // len
            contract->stack.push(Value(256, 100)); // addr
            engine.run_from(0x10, 1);
            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
                "ArchEVM: failed to disassembly and/or execute KECCAK",
                16
            );

            // Value equivalent to "abc"
            contract->memory.write(Value(256, 100), Value(24, 0x616263));
            contract->stack.push(Value(256, 3)); // len
            contract->stack.push(Value(256, 100)); // addr
            engine.run_from(0x10, 1);
            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
                "ArchEVM: failed to disassembly and/or execute KECCAK",
                16
            );

            // Value equivalent to "a"*32
            std::string a(32, 'a');
            contract->memory.mem().write_buffer(0x0, (uint8_t*)a.c_str(), a.size());
            contract->stack.push(Value(256, 32)); // len
            contract->stack.push(Value(256, 0x0)); // addr
            engine.run_from(0x10, 1);
            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "47a01324181e85459310f8fb9b24dc09744323ebdcef26cbf98959effdc76e02",
                "ArchEVM: failed to disassembly and/or execute KECCAK",
                16
            );

            // Value equivalent to "b"*37
            std::string b(37, 'b');
            contract->memory.mem().write_buffer(0x0, (uint8_t*)b.c_str(), b.size());
            contract->stack.push(Value(256, b.size())); // len
            contract->stack.push(Value(256, 0x0)); // addr
            engine.run_from(0x10, 1);
            nb += _assert_bignum_eq(
                contract->stack.get(0),
                "c3b726a06a6a694c8e02952f7d5f37970b0eed410058dbf490084d6ceb56f14f",
                "ArchEVM: failed to disassembly and/or execute KECCAK",
                16
            );

            return nb;
        }

    }
}

using namespace test::archEVM; 
// All unit tests 
void test_archEVM()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";
    
    // Start testing
    std::cout << bold << "[" << green << "+" 
         << def << bold << "]" << def << std::left << std::setw(34)
         << " Testing arch EVM support... " << std::flush;

    MaatEngine engine(Arch::Type::EVM);
    engine.mem->map(0x0, 0xfff);
    setup_dummy_contract(engine);

    total += reg_translation();
    total += test_add(engine);
    total += test_div(engine);
    total += test_sdiv(engine);
    total += test_mod(engine);
    total += test_smod(engine);
    total += test_addmod(engine);
    total += test_mulmod(engine);
    total += test_signextend(engine);
    total += test_lt(engine);
    total += test_sgt(engine);
    total += test_iszero(engine);
    total += test_byte(engine);
    total += test_mload(engine);
    total += test_mstore(engine);
    total += test_mstore8(engine);
    total += test_jump(engine);
    total += test_jumpi(engine);
    total += test_pc(engine);
    total += test_msize(engine);
    total += test_push(engine);
    total += test_dup(engine);
    total += test_swap(engine);
    total += test_sload(engine);
    total += test_sstore(engine);
    total += test_keccak_helper();
    total += test_keccak(engine);

    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}
