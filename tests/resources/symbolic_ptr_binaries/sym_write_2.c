// Modified from: https://github.com/hxuhack/logic_bombs

// s must start with the char '3' to return 42
int func(char* s) {
    int symvar = s[0] - 0x30;
    int a1[] ={1,1,1,1,1}; 
    int a2[] ={6,7,8,9,10,11}; 
    int x = symvar%5;
    int res = 0;
    
    a1[x] = 3;
    a2[a1[3]] = 42;

    return a2[3];
}

int main(int argc, char* argv[]){
    if( argc != 2 ){
        return 0;
    }
    return func(argv[1]); 
}
