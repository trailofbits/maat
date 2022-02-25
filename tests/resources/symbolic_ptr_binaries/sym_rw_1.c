#include <stdlib.h>

// We want to find 'index' such that the function returns 42
int func(int ri, int wi) {
    int a[] = {1,2,3,4,5,6,7,8,9,10};
    a[wi % 10] = 42; 
    return a[ri%10];
}

int main(int argc, char* argv[]){
    if( argc != 3 ){
        return 0;
    }
    return func(atoi(argv[1]), atoi(argv[2])); 
}
