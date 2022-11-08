#include "maat/exception.hpp"
#include <string>
#include <cstring>
#include <iostream>
#include <exception>
#include <chrono>

void test_expression();
void test_simplification();
void test_memory();
void test_symbolic_memory();
void test_ir();
void test_archX86();
void test_archX64();
void test_events();
void test_snapshots();
void test_solver();
void test_loader();
void test_serialization();
void test_archEVM();
void test_archARM32();


int main(int argc, char ** argv)
{
    std::string bold = "\033[1m";
    std::string def = "\033[0m";
    std::string red = "\033[1;31m";
    std::string green = "\033[1;32m";
    std::chrono::steady_clock::time_point time_begin;
    std::chrono::steady_clock::time_point time_end;
    float time_total;

    std::cout << bold << "\nRunnning Maat unitary tests" << def << "\n"
                 <<   "===========================\n" << std::endl;

    time_begin = std::chrono::steady_clock::now(); 

    for(int i = 0; i < 1; i++)
    {
        try
        {
            if( argc == 1 )
            {
            /* If no args specified, test all */
                test_expression();
                test_simplification();            
                test_memory();
                test_symbolic_memory();
                test_ir();
                test_events();
                test_snapshots();
                test_archX86();
                test_archX64();
                test_archEVM();
                test_solver();
                test_loader();
                test_serialization();
                test_archARM32();
                
                /* TODO
                test_archARM64();
                test_env();
                 */
            }
            else
            {
            /* Iterate through all options */
                for( int i = 1; i < argc; i++)
                {
                    if( !strcmp(argv[i], "expr"))
                        test_expression();
                    else if (!strcmp(argv[i], "simp"))
                        test_simplification();
                    else if( !strcmp(argv[i], "mem"))
                        test_memory();
                    else if( !strcmp(argv[i], "symmem"))
                        test_symbolic_memory();
                    else if( !strcmp(argv[i], "ir"))
                        test_ir();
                    else if( !strcmp(argv[i], "X86"))
                        test_archX86();
                    else if( !strcmp(argv[i], "X64"))
                        test_archX64();
                    else if ( !strcmp(argv[i], "ARM32"))
                        test_archARM32();
                    else if( !strcmp(argv[i], "EVM"))
                        test_archEVM();
                    else if( !strcmp(argv[i], "event"))
                        test_events();
                    else if( !strcmp(argv[i], "snap"))
                        test_snapshots();
                    else if( !strcmp(argv[i], "solver"))
                        test_solver();
                    else if( !strcmp(argv[i], "loader"))
                        test_loader();
                    else if( !strcmp(argv[i], "serial"))
                        test_serialization();
                    /*
                    else if( !strcmp(argv[i], "ARM64"))
                        test_archARM64();
                    else if( !strcmp(argv[i], "env"))
                        test_env();
                    */
                    else
                        std::cout   << "[" << red << "!" << def 
                                    << "] Skipping unknown test: "
                                    << argv[i] << std::endl;
                }
            }
        }
        catch(maat::test_exception& e)
        {
            std::cout << red << "Failed: " << def << "Unit test failed" << def << "\n" << std::endl;
            return 1; 
        }
    }

    time_end = std::chrono::steady_clock::now();
    time_total = std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_begin).count();

    std::cout   <<  "\nSuccess. Total time: " << std::dec << bold 
                << time_total/1000 << "s" << def << "\n" << std::endl;

    return 0;
}
