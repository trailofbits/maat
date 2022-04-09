#include "maat/exception.hpp"
#include <string>
#include <cstring>
#include <iostream>
#include <exception>
#include <chrono>

using std::cout;
using std::endl;
using std::string;

void test_hash();
void test_code_coverage();
void test_solve_hash();
void test_solve_symbolic_ptr();
void test_adv_serialization();

int main(int argc, char ** argv)
{
    string bold = "\033[1m";
    string def = "\033[0m";
    string red = "\033[1;31m";
    string green = "\033[1;32m";
    std::chrono::steady_clock::time_point time_begin;
    std::chrono::steady_clock::time_point time_end;
    float time_total;
    
    cout << bold << "\nRunnning Maat advanced tests" << def << endl
                 <<   "============================" << endl << endl;
     
     time_begin = std::chrono::steady_clock::now(); 

     for(int i = 0; i < 1; i++)
     {
        try
        {
            if( argc == 1 )
            {
            /* If no args specified, test all */
                test_hash();
                test_code_coverage();
                test_adv_serialization();
                test_solve_hash();
                test_solve_symbolic_ptr();
            }
            else
            {
            /* Iterate through all options */
                for( int i = 1; i < argc; i++)
                {
                    if( !strcmp(argv[i], "hash"))
                        test_hash();
                    else if( !strcmp(argv[i], "cov"))
                        test_code_coverage();
                    else if( !strcmp(argv[i], "serial"))
                        test_adv_serialization();
                    else if( !strcmp(argv[i], "solve_hash") )
                        test_solve_hash();
                    else if( !strcmp(argv[i], "solve_symptr"))
                        test_solve_symbolic_ptr();
                    else
                        std::cout << "[" << red << "!" << def << "] Skipping unknown test: " << argv[i] << std::endl;
                }
            }
        }
        catch(maat::test_exception& e)
        {
            cout << red << "Failed: Advanced test failed" << def << endl << endl;
            return 1;
        }
    }

    time_end = std::chrono::steady_clock::now();
    time_total = std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_begin).count();

    cout << endl;
    cout <<  "Success. Total time: " << std::dec << bold << time_total/1000 << "s" << def << std::endl;
    cout << endl;

    return 0;
}
