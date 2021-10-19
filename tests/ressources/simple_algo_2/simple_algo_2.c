#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t transform( uint32_t val ){
    val = val ^ 0x11010101;
    val = (val << 3) ^ (val >> 2);
    val = val ^ 0x10110001;
    return val;
}

int main(int argc, char* argv[]){
    uint32_t arg, res;
    arg = atoi(argv[1]);
    res = transform(arg);
    printf("Arg: %08x   Res: %08x\n", arg, res);
    return 0;
}
