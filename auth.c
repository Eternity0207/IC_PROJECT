#include "auth.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>

int validateCredentials(const char *username, const char *password) {
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME_LEN - 1) {
        return 0;
    }
    
    if (strlen(password) == 0 || strlen(password) > MAX_PASSWORD_LEN - 1) {
        return 0;
    }
    
    for (size_t i = 0; i < strlen(username); i++) {
        if (username[i] == ':' || username[i] == '\n' || username[i] == '\r') {
            return 0;
        }
    }
    
    return 1;
}

int userExists(const char *username) {
    FILE *file = fopen(USERS_FILE, "rb");
    if (!file) {
        return 0;
    }
    
    UserCredentials user;
    while (fread(&user, sizeof(UserCredentials), 1, file)) {
        if (strcmp(user.username, username) == 0) {
            fclose(file);
            return 1;
        }
    }
    
    fclose(file);
    return 0;
}

int authenticateUser(const char *username, const char *password) {
    if (!validateCredentials(username, password)) {
        return 0;
    }
    
    FILE *file = fopen(USERS_FILE, "rb");
    if (!file) {
        return 0;
    }
    
    UserCredentials user;
    
    while (fread(&user, sizeof(UserCredentials), 1, file)) {
        if (strcmp(user.username, username) == 0) {
            fclose(file);
            return (strcmp(user.password, password) == 0);
        }
    }
    
    fclose(file);
    return 0;
}

int registerUser(const char *username, const char *password) {
    if (!validateCredentials(username, password)) {
        return 0;
    }
    
    if (userExists(username)) {
        return 0;
    }
    
    FILE *file = fopen(USERS_FILE, "ab");
    if (!file) {
        return 0;
    }
    
    UserCredentials newUser;
    strncpy(newUser.username, username, MAX_USERNAME_LEN);
    strncpy(newUser.password, password, MAX_PASSWORD_LEN);
    
    int result = fwrite(&newUser, sizeof(UserCredentials), 1, file);
    fclose(file);
    
    return result == 1;
}

void initializeAuthSystem() {
    FILE *file = fopen(USERS_FILE, "ab");
    if (file) {
        fclose(file);
    }
    
    file = fopen(USERS_FILE, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fclose(file);
        
        if (size == 0) {
            registerUser("admin", "admin123");
        }
    }
}