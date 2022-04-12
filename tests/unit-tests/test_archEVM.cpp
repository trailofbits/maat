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
                std::make_shared<Contract>(Value(256, "86984651684651a5a65665b65f", 16))
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

    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}
