#ifndef AUTH_H
#define AUTH_H

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define USERS_FILE "users.dat"

typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} UserCredentials;

// Function prototypes
int authenticateUser(const char *username, const char *password);
int registerUser(const char *username, const char *password);
int userExists(const char *username);
int validateCredentials(const char *username, const char *password);
void encryptPassword(char *password);
void initializeAuthSystem();

#endif // AUTH_H