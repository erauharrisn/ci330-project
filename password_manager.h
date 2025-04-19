// password_manager.h 

struct list {
    char user[64]; 
    char pass[64]; 
    char site[64];
};

void encryptPassword(const char* password, char* ciphertext, int* ciphertext_len);
void decryptPassword(char* ciphertext, char* plaintext, int ciphertext_len, int* plaintext_len);
void savePassword(const char* site, const char* username, char* ciphertext, int ciphertext_len);
void deletePassword();
void showPassword();
void prompt();
void printArray(struct list *creds, int arr_len);
