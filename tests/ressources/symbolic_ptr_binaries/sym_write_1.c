#include <stdlib.h>

int func(int idx){
    int values[] = {1, 1, 1, 1, 1, 1};
    values[idx % 6 ] = 42;
    return values[5];
}

int main(int argc, char* argv[]){
    if( argc < 2 ){
        return 0;
    }
    return func(atoi(argv[1]));
}
