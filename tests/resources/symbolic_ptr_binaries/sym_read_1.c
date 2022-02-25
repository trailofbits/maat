#include <stdlib.h>

// We want to find 'index' such that the function returns 42
int func(int index) {
    int a[] = {1,2,42,3,4};
    return a[index%5];
}

int main(int argc, char* argv[]){
    if( argc != 2 ){
        return 0;
    }
    return func(atoi(argv[1])); 
}
