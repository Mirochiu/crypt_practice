// From: http://hayageek.com/rsa-encryption-decryption-openssl-c/
//
// Ubuntu 14.04.4
// sudo apt-get install -y libssl-dev
// # /usr/include/openssl/
//
// compile:
// gcc rsacryptor.c -o rsacryptor -lcrypto -Wall
//
// usage:
// ./rsacryptor "hello world"

// openssl genrsa -out private_key.pem 2048
// openssl rsa -in private_key.pem -out public_key.pem -outform PEM -pubout
// ./rsacryptor "hello world" public_key.pem private_key.pem

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#define CRYPTO_ERROR_MSG_LEN 130

#define LOGI printf
#define LOGE printf
#define LOGD printf
#define LOGV printf

int padding = RSA_PKCS1_PADDING;

RSA* createRSA(unsigned char * key, int public)
{
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1); // -1 means auto size
    if (!keybio) {
        LOGE( "Failed to create key BIO");
        return 0;
    }
    if (public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL) {
        LOGE( "Failed to create RSA");
    }
    return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA *rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA *rsa = createRSA(key, 1);
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA *rsa = createRSA(key, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA *rsa = createRSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

void printLastError(char *title)
{
    char *errmsg = malloc(CRYPTO_ERROR_MSG_LEN+1);
    memset(errmsg, 0, sizeof(CRYPTO_ERROR_MSG_LEN+1));
    ERR_load_crypto_strings();
    ERR_error_string_n(ERR_get_error(), errmsg, CRYPTO_ERROR_MSG_LEN);
    printf("%s ERROR: %s\n", title, errmsg);
    free(errmsg);
}

unsigned char* loadKeyFile(char* pPath)
{
    fpos_t endpos;
    unsigned char *retkey;
    size_t readlen;
    FILE *pfile = fopen(pPath, "rb");
    if (pfile) {
        if (!fseek(pfile, 0, SEEK_END) && 
            !fgetpos(pfile, &endpos) &&
            !fseek(pfile, 0, SEEK_SET)) {
            LOGV("got file len %ld\n", endpos.__pos);
            retkey = malloc(endpos.__pos);
            if (retkey) {
                readlen = fread(retkey, 1, endpos.__pos, pfile);
                if (readlen == endpos.__pos) {
                    return retkey;
                }
                else {
                    LOGE("read file error %lu/%ld\n", readlen, endpos.__pos);
                }
            }
            else {

            }
        }
        else {
            LOGE("Cannot get file size\n");
        }
    }
    else {
        LOGE("Cannot open the path %s\n", pPath);
    }
    return NULL;
}

static unsigned char builtin_publicKey[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
    "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"
    "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"
    "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"
    "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"
    "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"
    "wQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

static unsigned char builtin_privateKey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"
    "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"
    "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"
    "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"
    "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"
    "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"
    "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"
    "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"
    "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"
    "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"
    "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"
    "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"
    "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"
    "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"
    "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"
    "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"
    "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"
    "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"
    "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"
    "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"
    "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"
    "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"
    "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"
    "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"
    "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"
    "-----END RSA PRIVATE KEY-----\n";

int main(int argc, unsigned char** argv)
{
    unsigned char plainText[2048/8] = {0}; // if your key length = 2048
    unsigned char encrypted[4098]={0};
    unsigned char decrypted[4098]={0};
    unsigned char *publicKey;
    unsigned char *privateKey;
    int encrypted_length;
    int decrypted_length;

    if (argc != 2 && argc != 4) {
        LOGE("usage: %s <plain-text> [<private key path> <public key path>]\n", argv[0]);
        return -1;
    }

    if (argc > 3) {
        publicKey = loadKeyFile(argv[2]);
        if (!publicKey) {
            LOGE("setup built-in public key");
            publicKey = (unsigned char*)builtin_publicKey;
        }
        else {
            LOGD("public key='%s'\n", publicKey);
        }
        privateKey = loadKeyFile(argv[3]);
        if (!privateKey) {
            LOGE("setup built-in private key");
            privateKey = (unsigned char*)builtin_privateKey;
        }
        else {
            LOGD("private key='%s'\n", privateKey);
        }
    } else {
        LOGD("setup built-in public and private key\n");
        publicKey = (unsigned char*)builtin_publicKey;
        privateKey = (unsigned char*)builtin_privateKey;
    }

    if (argc > 1) {
        strncpy(plainText, argv[1], sizeof(plainText)-1);
    }
    LOGD("plainText='%s'\n\n", plainText);

    encrypted_length = public_encrypt(plainText, strlen(plainText), publicKey, encrypted);
    if (encrypted_length == -1) {
        printLastError("Public Encrypt failed ");
        return 0;
    }
    LOGI("Encrypted(by public) data length=%d\n", encrypted_length);

    decrypted_length = private_decrypt(encrypted, encrypted_length, privateKey, decrypted);
    if (decrypted_length == -1) {
        printLastError("Private Decrypt failed ");
        return 0;
    }
    LOGI("Decrypted(by private) text='%s'\n", decrypted);
    LOGI("Decrypted(by private) data length=%d\n\n", decrypted_length);

    encrypted_length = private_encrypt(plainText, strlen(plainText), privateKey, encrypted);
    if (encrypted_length == -1) {
        printLastError("Private Encrypt failed");
        return 0;
    }
    LOGI("Encrypted(by private) data length=%d\n", encrypted_length);

    decrypted_length = public_decrypt(encrypted, encrypted_length, publicKey, decrypted);
    if (decrypted_length == -1) {
        printLastError("Public Decrypt failed");
        return 0;
    }

    LOGI("Decrypted(by public) text='%s'\n", decrypted);
    LOGI("Decrypted(by public) data length=%d\n", decrypted_length);
    return 0;
}