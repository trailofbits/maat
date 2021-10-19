#include <stdio.h>

int check(char * input){
     char pass[5] = {'t', 'r', 'u', 'c', '\0'};
     int i = 0;
     while( i < 4 && pass[i] == input[i]){
          if( input[i] == '\0' )
               return 0;
          i++;
     }
     return (pass[i] == input[i]);
}

int main(int argc, char* argv[]){
     return check(argv[1]);
}
