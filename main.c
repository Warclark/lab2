#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFSIZE 1024
#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16
/**
 * \brief Prints usage information for the program.
 */
void usrGid() {
    printf("file_encrypt -e||-d -f <filename> -p <password>\n");
    printf("-e-d  Encrypt or decrypt\n");
    printf("-f  file name\n");
    printf("-p  password\n");
}
/**
 * \brief Encrypts or decrypts data from an input file to an output file.
 *
 * \param in Input file stream.
 * \param out Output file stream.
 * \param key Encryption key.
 * \param iv Initialization vector.
 * \param mode Mode of operation: 1 for encryption, 0 for decryption.
 */

void crypt_func(FILE *in, FILE *out, uint8_t* key, uint8_t* iv, int mode) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("Error creating cipher context");
        exit(EXIT_FAILURE);
    }

    if (mode == 1) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            perror("Error initializing encryption");
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            perror("Error initializing decryption");
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }

    uint8_t inbuf[BUFSIZE], outbuf[BUFSIZE + AES_BLOCK_SIZE];
    int outlen;
    int inlen;
    while ((inlen = fread(inbuf, 1, BUFSIZE, in)) > 0) {
        if (mode == 1) {
            if (1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
                perror("Error during encryption");
                EVP_CIPHER_CTX_free(ctx);
                exit(EXIT_FAILURE);
            }
        } else {
            if (1 != EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
                perror("Error during decryption");
                EVP_CIPHER_CTX_free(ctx);
                exit(EXIT_FAILURE);
            }
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (mode == 1) {
        if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
            perror("Error finalizing encryption");
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    } else {
        if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
            perror("Error finalizing decryption");
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
}
/**
 * \brief Main function to handle command line arguments and perform encryption or decryption.
 *
 * \param argc Number of command line arguments.
 * \param argv List of command line arguments.
 * \return int Returns 0 on success, 1 on failure.
 */

int main (int argc, char* argv[]) {
    uint8_t en = 0;
    uint8_t de = 0;
    char* fileName = NULL;
    char* password = NULL;
    char* opts = "edf:p:";
    int opt;
    while((opt=getopt(argc, argv, opts))!=-1) {
        switch(opt) {
            case 'e':
                en = 1;
                break;
            case 'd':
                de = 1;
                break;
            case 'f':
                fileName = optarg;
                break;
            case 'p':
                password = optarg;
                break;
        }
    }

    if ((en == de) || !(fileName) || !(password)) {
        usrGid();
        exit(1);
    }

    uint8_t key[AES_KEYLEN / 8];
    uint8_t iv[AES_BLOCK_SIZE];
    const unsigned char salt[] = "salt";

    if (!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, sizeof(salt), 1000, AES_KEYLEN / 8, key)) {
        perror("Error generating key");
        exit(EXIT_FAILURE);
    }

    FILE *inFile = fopen(fileName, "rb");
    if (!inFile) {
        printf("Can't open input file!\n");
        exit(1);
    }

    FILE *outFile = NULL;
    if (en == 1) {
        outFile = fopen("crypt.out", "wb");
        if (!outFile) {
            printf("Can't create output file!\n");
            fclose(inFile);
                        exit(1);
                    }
                    if (!RAND_bytes(iv, sizeof(iv))) {
                        perror("Error generating IV");
                        fclose(inFile);
                        fclose(outFile);
                        exit(EXIT_FAILURE);
                    }
                    fwrite(iv, 1, AES_BLOCK_SIZE, outFile); // Write IV to output file
                    crypt_func(inFile, outFile, key, iv, 1);
                }
                else if (de == 1) {
                    outFile = fopen("dekrypt.out", "wb");
                    if (!outFile) {
                        printf("Can't create output file!\n");
                        fclose(inFile);
                        exit(1);
                    }
                    if (fread(iv, 1, AES_BLOCK_SIZE, inFile) != AES_BLOCK_SIZE) {
                        perror("Error reading IV");
                        fclose(inFile);
                        fclose(outFile);
                        exit(EXIT_FAILURE);
                    }
                    crypt_func(inFile, outFile, key, iv, 0);
                }

                fclose(inFile);
                fclose(outFile);

                return 0;
            }
