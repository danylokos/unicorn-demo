#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define KEY_LEN 11

const char enc_key[] = { 0x32, 0x24, 0x22, 0x33, 0x24, 0x35, 0x1e, 0x2a, 0x24, 0x38, 0x41 }; // "secret_key" xor 0x41

int check_key(char *key) {
    char dec_key[KEY_LEN];
    for (int i=0; i<KEY_LEN; i++) {
        dec_key[i] = enc_key[i] ^ 0x41;
    }
    return strcmp(dec_key, key);
}

int main(int argc, char* argv[]) {
    printf("Enter key:\n");
    char key[KEY_LEN];
    scanf("%10s", key);
    if (check_key(key) == 0) {
        printf("Success!\n");
    } else {
        printf("Wrong key.\n");
    }
    return 0;
}
