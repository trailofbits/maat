#include <stdio.h>

int check(unsigned char * input){
     unsigned char pass[5] = {0xdf, 0xd3, 0xd3, 0xc8, 0xb4};
     int i = 0;
     for( i = 0; i < 5; i++ ){
          if( (input[i]^0xb3)+1 != pass[i] )
               return 0;
     }
     return 1;
}

int main(int argc, char* argv[]){
     return check(argv[1]);
}
