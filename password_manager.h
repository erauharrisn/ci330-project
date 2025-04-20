// password_manager.h 

// List struct to hold usernames, passwords, and sites during user input. 
struct list {
    char user[64]; 
    char pass[64]; 
    char site[64];
};

// Essential Program Functions 
void prompt();
void ensureUserDirectory(); 
void printArray(struct list *creds, int arr_len);
void encryptPassword(const char* password, char* ciphertext, int* ciphertext_len);
void decryptPassword(char* ciphertext, char* plaintext, int ciphertext_len, int* plaintext_len);
void savePassword(const char* site, const char* username, char* ciphertext, int ciphertext_len);
void showPassword();
void deletePassword();
