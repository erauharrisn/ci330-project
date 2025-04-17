#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "password_manager.h"

char key[16] = "s0ftw4r3secur1ty"; 
char iv[16] = "superdupersecret";

void encryptPassword(const char* password, char* ciphertext, int* ciphertext_len) {
    int len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) return;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) return;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, password, strlen(password))) return;
    *ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return;
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void decryptPassword(char* ciphertext, char* plaintext, int ciphertext_len, int* plaintext_len) {
    int len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) return;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) return;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return;

    *plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return;
    *plaintext_len += len;

    plaintext[*plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
}

void savePassword(const char* site, const char* username, char* ciphertext, int ciphertext_len) {
    FILE *file = fopen("creds.enc", "ab"); // Append in binary mode
    if (!file) {
        perror("Failed to open file");
        return;
    }

    int site_len = strlen(site);
    int username_len = strlen(username);

    fwrite(&site_len, sizeof(int), 1, file);
    fwrite(site, 1, site_len, file);

    fwrite(&username_len, sizeof(int), 1, file);
    fwrite(username, 1, username_len, file);

    fwrite(&ciphertext_len, sizeof(int), 1, file);
    fwrite(ciphertext, 1, ciphertext_len, file);

    fclose(file);
}

void deletePassword() {
    // Stub
}

void showPasswords() {
    FILE *file = fopen("creds.enc", "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    int site_len, username_len, ciphertext_len;
    char site[256], username[256];
    char ciphertext[512], plaintext[512];
    int plaintext_len;

    while (fread(&site_len, sizeof(int), 1, file) == 1) {
        fread(site, 1, site_len, file);
        site[site_len] = '\0';

        fread(&username_len, sizeof(int), 1, file);
        fread(username, 1, username_len, file);
        username[username_len] = '\0';

        fread(&ciphertext_len, sizeof(int), 1, file);
        fread(ciphertext, 1, ciphertext_len, file);

        decryptPassword(ciphertext, plaintext, ciphertext_len, &plaintext_len);
        plaintext[plaintext_len] = '\0';

        printf("Site: %s, Username: %s, Password: %s\n", site, username, plaintext);
    }

    fclose(file);
}


void prompt() {
    int choice;
    int flag = 1;
    char* site = malloc(128);
    char* username = malloc(128);
    char* password = malloc(128);
    char* plaintext = malloc(512);
    char* ciphertext = malloc(512);
    int ciphertext_len = 0;
    int plaintext_len = 0;

    while (flag) {
        printf("Please enter the number (1-4) for the choice you would like to do:\n");
        printf("------------------------------------------------------------\n");
        printf("Option 1: Save a new password\n");
        printf("Option 2: Delete a password\n");
        printf("Option 3: Show password(s)\n");
        printf("Option 4: Exit the password manager\n");

        scanf("%d", &choice);
        getchar(); // Clear newline

        switch (choice) {
            case 1:
                printf("Enter the company/site associated with the password: ");
                scanf("%s", site);
                printf("Enter the username associated with the password: ");
                scanf("%s", username);
                printf("Enter the password [limit 128 chars]: ");
                scanf("%s", password);

                encryptPassword(password, ciphertext, &ciphertext_len);
                savePassword(site, username, ciphertext, ciphertext_len);
                break;
            case 2:
                deletePassword();
                break;
            case 3:
                showPasswords();
                break;
            case 4:
                flag = 0;
                break;
            default:
                printf("Enter a valid choice\n");
                break;
        }
    }

    free(site);
    free(username);
    free(password);
    free(plaintext);
    free(ciphertext);
}

void print_hex(const char* data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", (unsigned char)data[i]);
    }
    printf("\n");
}

int main() {
    prompt();
    return 0;
}
