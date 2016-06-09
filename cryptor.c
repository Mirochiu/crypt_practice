#include <stdio.h>
#include <openssl/aes.h>

void printBlockData(unsigned char* data, int blksz, unsigned char* blkname)
{
    int idx;
    printf("======= [ %10s ] =======\n", blkname);
    for (idx=0 ; idx<blksz ; ++idx) {
        printf("%02X", data[idx]);
    }
    printf("\n");
}

void printAesKey(AES_KEY* key, unsigned char* keyname) {
    int idx;
    unsigned char* ptr;
    printf("======== < %10s > =======\n", keyname);
    printf("Rounds: %d\n", key->rounds);
    printf("Key length: %lu\n", sizeof(key->rd_key));
    ptr = (unsigned char*) (key->rd_key);
    for (idx=0 ; idx<sizeof(key->rd_key); ++idx) {
        printf("%02X", (int)*ptr++);
    }
    printf("\n");
}

int main (int argc, char* argv[])
{
    AES_KEY enc_key, dec_key;
    unsigned char user_key[128/8] = "0";
    unsigned char data[AES_BLOCK_SIZE] = "ABCEXYX";
    unsigned char cipher[AES_BLOCK_SIZE] = {0};
    unsigned char dec_data[AES_BLOCK_SIZE] = {0};

    printf("AES options: %s\n", AES_options());

    AES_set_encrypt_key(user_key, 128, &enc_key);
    AES_set_decrypt_key(user_key, 128, &dec_key);

    printAesKey(&enc_key, "key for enc");
    printAesKey(&dec_key, "key for dec");

    AES_encrypt(data, cipher, &enc_key);
    AES_decrypt(cipher, dec_data, &dec_key);

    printBlockData(data, sizeof(data), "plain text");
    printBlockData(cipher, sizeof(cipher), "cipher data");
    printBlockData(dec_data, sizeof(dec_data), "decrypted text");

    return 0;
}
