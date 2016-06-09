#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

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

#define BUF_SIZE 512
#define KEY_BITS 128

int main (int argc, char* argv[])
{
    FILE *infile, *keyfile, *outfile;
    unsigned char outfname[128] = {0};
    unsigned char inkey[KEY_BITS/8] = {0};
    unsigned char filebuf[BUF_SIZE];
    unsigned char outbuf[BUF_SIZE];
    unsigned char initvec[KEY_BITS/8] = "my init vector";
    AES_KEY cryptkey;
    int readlen, writelen, mode = 0;

    if (argc <= 2) {
        fprintf(stderr, "usage: %s <in-file> <key-file> [<mode> [<out-file>]]\n", argv[0]);
        return -1;
    }

    if (argc > 3) {
        mode = atoi(argv[3]);
        printf("running mode %s\n", mode?"DECRYPT":"ENCRYPT");
    }

    // read key file and generate the key for encrypt/decrypt
    keyfile = fopen(argv[2], "rb");
    if (!keyfile) {
        fprintf(stderr, "keyfile %s error\n", argv[2]);
        perror(argv[0]);
        return -1;
    }
    printf("keyfile: %s\n", argv[2]);

    readlen = fread(inkey, 1, KEY_BITS/8, keyfile);
    if (readlen <= 0) {
        fprintf(stderr, "read key file len error %d\n", readlen);
        return -1;
    }
    fclose(keyfile);

    if (mode) {
        AES_set_decrypt_key(inkey, KEY_BITS, &cryptkey);
        printAesKey(&cryptkey, "decrypt key");
    }
    else {
        AES_set_encrypt_key(inkey, KEY_BITS, &cryptkey);
        printAesKey(&cryptkey, "encrypt key");
    }

    // find the extion name of input file path when parameter not found
    if (argc > 4) {
        strncpy(outfname, argv[4], sizeof(outfname)-1);
    }
    else {
        char *dot, *slash;
        int fname_len = strlen(argv[1]);
        dot = strrchr(argv[1], '.');
        slash = strrchr(argv[1], '/');
        if (dot > slash) {
            fname_len = dot-argv[1];
        }
        snprintf(outfname, sizeof(outfname)-1, "%.*s_%s%s",
            fname_len, argv[1], mode?"dec":"enc", dot?dot:"");
    }

    outfile = fopen(outfname, "wb");
    if (!outfile) {
        fprintf(stderr, "out file %s error\n", outfname);
        perror(argv[0]);
        return -1;
    }

    // start to process the data
    infile = fopen(argv[1], "rb");
    if (!infile) {
        fprintf(stderr, "input file %s error\n", argv[1]);
        perror(argv[0]);
        return -1;
    }
    printf("input: %s\n", argv[1]);

    readlen = fread(filebuf, 1, BUF_SIZE, infile);
    while(readlen > 0) {
        if (readlen < KEY_BITS/8) {
            memset(filebuf+readlen, 0, KEY_BITS/8-readlen);
            readlen = KEY_BITS/8;
        }
        if (mode)
            AES_cbc_encrypt(filebuf, outbuf, readlen, &cryptkey, initvec, AES_DECRYPT);
        else
            AES_cbc_encrypt(filebuf, outbuf, readlen, &cryptkey, initvec, AES_ENCRYPT);

        writelen = fwrite(outbuf, 1, readlen, outfile);
        if (writelen != readlen) {
            fprintf(stderr, "cannot output the data %d/%d, exit\n", writelen, readlen);
            break;
        }

        printf(".");
        readlen = fread(filebuf, 1, BUF_SIZE, infile);
    }
    printf("\n");
    if (readlen!=0) {
        fprintf(stderr, "processing got unexpected error\n");
        perror(argv[0]);
    }

    fclose(infile);
    fflush(outfile);
    fclose(outfile);

    return 0;
}

