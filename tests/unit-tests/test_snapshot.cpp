#include "expression.hpp"
#include "snapshot.hpp"
#include "engine.hpp"
#include "exception.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

namespace test
{
    namespace snapshot
    {        
        using namespace maat;
        using namespace maat::event;

        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }

        unsigned int basic()
        {
            Expr    e1 = exprvar(32, "var0"),
                    e2 = exprvar(64, "var1"),
                    c1 = exprcst(64, 0x12345678c0c0babe);
            MaatEngine engine = MaatEngine(Arch::Type::NONE);
            MaatEngine::snapshot_t s1, s2;
            unsigned int nb = 0;
            int nb_segments = 0;

            // Init 
            engine.vars->set("var0", 0x41414141);
            engine.cpu.ctx().set(0, e1);
            engine.cpu.ctx().set(1, e2);
            engine.mem->new_segment(0x2000, 0x2fff);
            engine.mem->write(0x21b4, e2);
            
            // Snapshot
            nb_segments = engine.mem->segments().size();
            s1 = engine.take_snapshot();
            // Do some more writes
            engine.mem->write(0x21b6, c1);
            engine.mem->write(0x21b4, e1);
            //  Create some segments
            engine.mem->new_segment(0x3000, 0x3fff);
            engine.mem->new_segment(0x5000, 0x5fff);
            engine.restore_snapshot(s1);
            // Rewind
            nb += _assert(engine.mem->read(0x21b4, 8)->eq(e2), "SnapshotManager rewind failed to reset engine.memory correctly"); 
            nb += _assert(engine.mem->segments().size() == nb_segments, "SnapshotManager rewind failed to reset segments correctly"); 

            // Write and snapshot two times
            engine.mem->write(0x2200, c1);
            s1 = engine.take_snapshot();
    
            engine.mem->write(0x2204, c1);
            engine.cpu.ctx().set(0, e1+e1);
            engine.cpu.ctx().set(1,e2+c1);
            s2 = engine.take_snapshot();
            
            engine.cpu.ctx().set(0, e1*e1);
            engine.mem->write(0x2207, e2);

            engine.restore_snapshot(s2, true);
            nb += _assert(engine.mem->read(0x2204, 8)->eq(c1), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(engine.mem->read(0x2200, 8)->eq(exprcst(64, 0xc0c0babec0c0babe)), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(engine.cpu.ctx().get(0).as_expr()->eq( e1+e1), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(engine.cpu.ctx().get(1).as_expr()->eq(c1+e2), "SnapshotManager: rewind failed for two consecutive snapshots");
            
            engine.restore_snapshot(s1, true);
            nb += _assert(engine.cpu.ctx().get(0).as_expr()->eq(e1), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(engine.cpu.ctx().get(1).as_expr()->eq(e2), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(engine.mem->read(0x2200, 8)->eq(c1), "SnapshotManager: rewind failed for two consecutive snapshots");

            // Rewind on mixed symbolic and concrete engine.memory writes
            engine.mem->write(0x2300, c1);
            engine.mem->write(0x22fa, e2);
            engine.mem->write(0x2302, e1);
            s1 = engine.take_snapshot();

            engine.mem->write(0x22fc, exprcst(64, 0x4141414141414141));
            engine.mem->write(0x2306, exprcst(64, 0x4141414141414141));
            engine.mem->write(0x2302, exprvar(64, "var3"));
            s2 = engine.take_snapshot();

            engine.restore_snapshot(s1);

            nb += _assert(engine.mem->read(0x2300, 2)->eq(extract(e2, 63, 48)), "SnapshotManager: restore failed for mixed symbolic and concrete writes");
            nb += _assert(engine.mem->read(0x2300, 8)->eq(concat( exprcst(16, 0x1234), concat(e1, extract(e2, 63, 48)))), "SnapshotManager: rewind failed for mixed symbolic and concrete writes");
            
            //  Create some segments to test snapshot on overlapping memory accesses
            engine.mem->new_segment(0x3000, 0x3fff);
            engine.mem->new_segment(0x4000, 0x5fff);
            engine.mem->write(0x3ffd, 0xabcdef11deadbeef, 8);
            engine.take_snapshot();
            engine.mem->write(0x3ffc, e2);
            engine.restore_last_snapshot();

            nb += _assert(engine.mem->read(0x3ffd, 8)->as_uint() == 0xabcdef11deadbeef, "SnapshotManager: restore failed for symbolic write overlapping between segments");

            return nb;
        }
        
        
        unsigned int snapshot_X86()
        {
            unsigned int nb = 0;
            MaatEngine engine = MaatEngine(Arch::Type::X86);
            MaatEngine::snapshot_t s1, s2, s3;
            /* Code to execute 
                0:  89 d8                   mov    eax,ebx
                2:  01 d1                   add    ecx,edx
                4:  89 15 00 20 00 00       mov    DWORD PTR ds:0x2000,edx
                a:  29 15 00 30 00 00       sub    DWORD PTR ds:0x3000,edx
                10: 53                      push   ebx
                11: 89 d3                   mov    ebx,edx
                13: ba 02 00 00 00          mov    edx,0x2
                18: 90                      nop
                19: 0b 0e                   jmp 0x10
                * 
                * { 0x89, 0xD8, 0x01, 0xD1, 0x89, 0x15, 0x00, 0x20, 0x00, 0x00, 0x29, 0x15, 0x00, 0x30, 0x00, 0x00, 0x53, 0x89, 0xD3, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x90, 0xeb, 0x0e}
                * 
                * "\x89\xD8\x01\xD1\x89\x15\x00\x20\x00\x00\x29\x15\x00\x30\x00\x00\x53\x89\xD3\xBA\x02\x00\x00\x00\x90\xeb\x0e"
            */

            /* Initialize */
            uint8_t code[27] = { 0x89, 0xD8, 0x01, 0xD1, 0x89, 0x15, 0x00, 0x20, 0x00, 0x00, 0x29, 0x15, 0x00, 0x30, 0x00, 0x00, 0x53, 0x89, 0xD3, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x90, 0xeb, 0x0e };
            engine.cpu.ctx().set(X86::EAX, exprcst(32, 1));
            engine.cpu.ctx().set(X86::EBX, exprcst(32, 2));
            engine.cpu.ctx().set(X86::ECX, exprcst(32, 3));
            engine.cpu.ctx().set(X86::EDX, exprcst(32, 4));
            engine.cpu.ctx().set(X86::ESP, exprcst(32, 0x4000));

            engine.mem->new_segment(0x0000, 0x3fff);
            engine.mem->write(0x2000, exprcst(32, 0x12345678));
            engine.mem->write(0x3000, exprcst(32, 0x87654321));

            engine.mem->new_segment(0x5000, 0x50ff);
            engine.mem->write_buffer(0x5000, code, sizeof(code));

            /* Set breakpoint */
            engine.hooks.add(Event::EXEC, When::BEFORE, "end", AddrFilter(0x5000+0x19));

            /* Take snapshots */
            s1 = engine.take_snapshot();
            engine.run_from(0x5000, 3);
            s2 = engine.take_snapshot();
            engine.run(3);
            s3 = engine.take_snapshot();
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Snapshot X86: failed to hit end breakpoint");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_int() != 1, "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::EBX).as_int() != 2, "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::ECX).as_int() != 3, "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::EDX).as_int() != 4, "Snapshot X86: unexpected state");
            nb += _assert((uint32_t)engine.mem->read(0x2000, 4)->as_uint() == 4, "Snapshot X86: unexpected state");
            nb += _assert((uint32_t)engine.mem->read(0x3000, 4)->as_uint() == 0x8765431d, "Snapshot X86: unexpected state");

            /* Restore last */
            engine.restore_snapshot(s3, true);
            nb += _assert(engine.cpu.ctx().get(X86::EDX).as_int() == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_int() != 1, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EBX).as_int() != 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::ECX).as_int() != 3, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x2000, 4)->as_uint(*engine.vars) != 0x12345678, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x3000, 4)->as_uint(*engine.vars) != 0x87654321, "Snapshot X86: failed to restore snapshot");

            /* Restore again */
            engine.restore_last_snapshot();
            nb += _assert(engine.cpu.ctx().get(X86::EDX).as_int() == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_int() == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EBX).as_int() == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::ECX).as_int() == 7, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x2000, 4)->as_uint(*engine.vars) == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x3000, 4)->as_uint(*engine.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");

            /* Restore to first */
            engine.restore_snapshot(s1, true);
            nb += _assert(engine.cpu.ctx().get(X86::EDX).as_int() == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_int() == 1, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EBX).as_int() == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::ECX).as_int() == 3, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x2000, 4)->as_uint(*engine.vars) == 0x12345678, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x3000, 4)->as_uint(*engine.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");

            /* ====== same code with some symbolic registers */
            engine.cpu.ctx().set(X86::EAX, exprcst(32, 1));
            engine.cpu.ctx().set(X86::EBX, exprcst(32, 2));
            engine.cpu.ctx().set(X86::ECX, exprcst(32, 3));
            engine.cpu.ctx().set(X86::EDX, exprvar(32, "edx"));
            engine.vars->remove("edx");
            engine.cpu.ctx().set(X86::ESP, exprcst(32, 0x4000));
            
            /* Take snapshots */
            s1 = engine.take_snapshot();
            engine.run_from(0x5000, 3);
            s2 = engine.take_snapshot();
            engine.run(3);
            s3 = engine.take_snapshot();
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Snapshot X86: failed to hit end breakpoint");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_int() != 1, "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::EBX).is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::ECX).is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::EDX).is_concrete(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::EDX).as_int() == 2, "Snapshot X86: unexpected state");
            nb += _assert(engine.mem->read(0x2000, 4)->is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.mem->read(0x3000, 4)->is_symbolic(*engine.vars), "Snapshot X86: unexpected state");

            engine.restore_snapshot(s2);
            nb += _assert(!engine.cpu.ctx().get(X86::EBX).is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::EBX).as_int() == 2, "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::ECX).is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.cpu.ctx().get(X86::EDX).is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.mem->read(0x2000, 4)->is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(!engine.mem->read(0x3000, 4)->is_symbolic(*engine.vars), "Snapshot X86: unexpected state");
            nb += _assert(engine.mem->read(0x3000, 4)->as_uint(*engine.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");
            
            engine.restore_snapshot(s1, true);
            nb += _assert(engine.cpu.ctx().get(X86::EDX).is_symbolic(*engine.vars), "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_int() == 1, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::EBX).as_int() == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.cpu.ctx().get(X86::ECX).as_int() == 3, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x2000, 4)->as_uint(*engine.vars) == 0x12345678, "Snapshot X86: failed to restore snapshot");
            nb += _assert(engine.mem->read(0x3000, 4)->as_uint(*engine.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");

            return nb;
        }

    }
}

using namespace test::snapshot;
// All unit tests 
void test_snapshots()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing snapshots... " << std::flush;

    total += basic();
    total += snapshot_X86();


    std::cout   << "\t\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;
}
