// password_manager.h 

void encryptPassword(const char* password, char* ciphertext, int* ciphertext_len);
void decryptPassword(char* ciphertext, char* plaintext, int ciphertext_len, int* plaintext_len);
void savePassword(const char* site, const char* username, char* ciphertext, int ciphertext_len);
void deletePassword();
void showPassword();
void prompt();
