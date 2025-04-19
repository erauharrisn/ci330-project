#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "password_manager.h"

#define ELEMENT_LENGTH 10

char key[16] = "s0ftw4r3secur1ty"; 
char iv[16] = "superdupersecret";

int main() {
    prompt();
    return 0;
}

void prompt() {
    int choice;
    int flag = 1;
    char* site = malloc(64);
    char* username = malloc(64);
    char* password = malloc(64);
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
                showPassword();
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

void showPassword() {
    /* Add the following checks here: 
       - Run the whoami command using execvp to check the user that is currently using the program. You will need this for the next command.
       - Check if that user already has a .pm directory (Check the exit code from the "ls /home/[username]/.pm/" command?)
       - If not, make the directory. If yes, open the creds.enc file within that directory (see below)
    */
    struct list creds[ELEMENT_LENGTH]; // An array that holds 10 struct list elements 
    int i = 0; // A counter to loop through elements of the array 
    int arr_len = 0; 
    
    FILE *file = fopen("creds.enc", "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    int site_len, username_len, ciphertext_len, plaintext_len;
    char site[64], username[64], ciphertext[512], plaintext[512];

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
        strcpy(creds[i].site, site); 
        strcpy(creds[i].user, username); 
        strcpy(creds[i].pass, plaintext);
        i++;
    }
    printf("\nThe current saved passwords are:\n"); 
    arr_len = i;
    printArray(creds, arr_len); 

    fclose(file);
}

void deletePassword() {
    int num;
    struct list creds[ELEMENT_LENGTH];
    int i = 0, arr_len = 0;

    // Open the file and load all entries (same logic as in showPassword)
    FILE *file = fopen("creds.enc", "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    int site_len, username_len, ciphertext_len, plaintext_len;
    char site[64], username[64], ciphertext[512], plaintext[512];

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

        strcpy(creds[i].site, site);
        strcpy(creds[i].user, username);
        strcpy(creds[i].pass, plaintext);
        i++;
    }
    fclose(file);
    arr_len = i;

    printArray(creds, arr_len);

    printf("Which password would you like to delete? Please only enter the number: ");
    scanf("%d", &num);
    getchar(); // Clear newline

    if (num < 1 || num > arr_len) {
        printf("Invalid entry number.\n");
        return;
    }

    // Write back all entries except the one being deleted
    file = fopen("creds.enc", "wb"); // Overwrite file
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }

    for (i = 0; i < arr_len; i++) {
        if (i == num - 1) continue; // Skip the entry to delete

        int site_len = strlen(creds[i].site);
        int user_len = strlen(creds[i].user);
        char ciphertext[512];
        int ciphertext_len = 0;

        encryptPassword(creds[i].pass, ciphertext, &ciphertext_len);

        fwrite(&site_len, sizeof(int), 1, file);
        fwrite(creds[i].site, 1, site_len, file);

        fwrite(&user_len, sizeof(int), 1, file);
        fwrite(creds[i].user, 1, user_len, file);

        fwrite(&ciphertext_len, sizeof(int), 1, file);
        fwrite(ciphertext, 1, ciphertext_len, file);
    }

    fclose(file);
    printf("Entry deleted successfully.\n");
}

void printArray(struct list *creds, int arr_len) {
    int i; 
    for (i = 0; i < arr_len; i++) {
    	printf("%d. Site: %s\tUsername: %s\tPassword: %s\n", i+1, creds[i].site, creds[i].user, creds[i].pass); 
    }    
}
