#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t transform( uint64_t val ){
    for( int i = 0; i < 100; i++ ){
        val = val ^ (0x1101010110011100);
        val = (val << 3) + (val >> 2);
    }
    return val;
}

int main(int argc, char* argv[]){
    uint64_t arg, res;
    arg = atol(argv[1]);
    res = transform(arg);
    printf("Arg: %16lx   Res: %16lx\n", arg, res);
    return 0;
}
