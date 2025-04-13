#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include<stdbool.h>
#define DATABASE_FILE "users.dat"
#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 2

typedef struct ClientNode ClientNode;

struct ClientNode {
    SOCKET socket;
    char ip[INET6_ADDRSTRLEN];
    SOCKET paired_socket;
    ClientNode *next;
};

typedef struct User{
    char username[20];
    char password[20];
    struct User * next;
} User;

ClientNode *client_list = NULL;
SOCKET listener = INVALID_SOCKET;
fd_set master_fd_set;
SOCKET max_fd = 0;

void add_client(SOCKET socket, const char *ip);
void free_users(User* head);
void remove_client(SOCKET socket);
ClientNode *find_client_by_ip(const char *ip);
ClientNode *find_client_by_socket(SOCKET socket);
void forward_message(SOCKET sender_socket, const char *msg, int msg_len);
void accept_new_connection();
bool verify(User *head, const char *username, const char *password);
void adduser(User **head, const char *username, const char *password);
void handle_client_message(SOCKET client_socket, User** users);
void save_to_database(User* user);
User* load_database(User* initial_head);
User* finduser(User *head, const char *username);
User* create_newUser(const char *username, const char *password);

void add_client(SOCKET socket, const char *ip) {
    int client_count = 0;
    ClientNode *current = client_list;
    while (current != NULL) {
        client_count++;
        current = current->next;
    }
    
    if (client_count >= MAX_CLIENTS) {
        send(socket, "SERVER_FULL", 12, 0);
        closesocket(socket);
        return;
    }

    ClientNode *new_node = (ClientNode *)malloc(sizeof(ClientNode));
    if (new_node == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    new_node->socket = socket;
    strncpy(new_node->ip, ip, INET6_ADDRSTRLEN);
    new_node->ip[INET6_ADDRSTRLEN - 1] = '\0';
    new_node->paired_socket = INVALID_SOCKET;
    new_node->next = client_list;
    client_list = new_node;

    if (socket > max_fd) {
        max_fd = socket;
    }

    printf("New client connected: %s\n", ip);
    
    if (client_count == 1) {
        ClientNode *first = client_list->next;
        ClientNode *second = client_list;
        
        first->paired_socket = second->socket;
        second->paired_socket = first->socket;
        
        send(first->socket, "PAIRED", 7, 0);
        send(second->socket, "PAIRED", 7, 0);
        printf("Clients paired: %s and %s\n", first->ip, second->ip);
    } else {
        send(socket, "WAITING_FOR_PARTNER", 20, 0);
    }
}

void remove_client(SOCKET socket) {
    ClientNode *prev = NULL;
    ClientNode *current = client_list;
    
    while (current != NULL) {
        if (current->socket == socket) {
            if (current->paired_socket != INVALID_SOCKET) {
                send(current->paired_socket, "PARTNER_DISCONNECTED", 20, 0);
                
                ClientNode *temp = client_list;
                while (temp != NULL) {
                    if (temp->socket == current->paired_socket) {
                        temp->paired_socket = INVALID_SOCKET;
                        break;
                    }
                    temp = temp->next;
                }
            }
            
            if (prev == NULL) {
                client_list = current->next;
            } else {
                prev->next = current->next;
            }
            
            free(current);
            printf("Client removed\n");
            return;
        }
        prev = current;
        current = current->next;
    }
}

ClientNode *find_client_by_ip(const char *ip) {
    ClientNode *current = client_list;
    while (current != NULL) {
        if (strcmp(current->ip, ip) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

ClientNode *find_client_by_socket(SOCKET socket) {
    ClientNode *current = client_list;
    while (current != NULL) {
        if (current->socket == socket) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void forward_message(SOCKET sender_socket, const char *msg, int msg_len) {
    ClientNode *sender = find_client_by_socket(sender_socket);
    if (sender == NULL || sender->paired_socket == INVALID_SOCKET) {
        const char *waitmsg = "[WAITING] There is no one on other side to chat yet!";
        send(sender_socket, waitmsg, strlen(waitmsg), 0);
        return;
    }
    
    send(sender->paired_socket, msg, msg_len, 0);
}

void accept_new_connection() {
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    SOCKET new_socket = accept(listener, (struct sockaddr *)&client_addr, &addr_len);
    
    if (new_socket == INVALID_SOCKET) {
        printf("Accept failed with error: %d\n", WSAGetLastError());
        return;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
        printf("Failed to convert client IP\n");
        closesocket(new_socket);
        return;
    }
    
    add_client(new_socket, client_ip);
    FD_SET(new_socket, &master_fd_set);
}

void handle_client_message(SOCKET client_socket, User** users) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    
    if (bytes_received <= 0) {
        closesocket(client_socket);
        FD_CLR(client_socket, &master_fd_set);
        remove_client(client_socket);
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    ClientNode *client = find_client_by_socket(client_socket);
    if (client == NULL) return;
    
    if (strncmp(buffer, "LOGIN", 5) == 0) {
        char username[50], password[50];
        sscanf(buffer + 6, "%s %s", username, password);
        printf("New Login Request, Usename:%s Password:%s\n", username, password);
        bool auth_result = verify(*users, username, password);
        printf("Authentication result: %s\n", auth_result ? "SUCCESS" : "FAILURE");
        if (auth_result) {
            send(client_socket, "LOGIN_SUCCESS", 14, 0);
        } else {
            send(client_socket, "LOGIN_FAILED", 13, 0);
        }
    }
    else if (strncmp(buffer, "SIGNUP", 6) == 0) {
        char username[50], password[50];
        sscanf(buffer + 7, "%s %s", username, password);
        printf("New Signup Request, Usename:%s Password:%s\n", username, password);
        
        if (!finduser(*users, username)) {
            adduser(users, username, password);
            printf("SIGNUP result: %s\n", "SUCCESS");
            save_to_database(create_newUser(username, password));

            *users = load_database(*users);
            send(client_socket, "SIGNUP_SUCCESS", 14, 0);
        } else {
            send(client_socket, "SIGNUP_FAILED", 13, 0);
            printf("SIGNUP result: %s\n", "FAILURE");
        }
    }
    else {
        forward_message(client_socket, buffer, bytes_received);
    }
}

void save_to_database(User* user) {
    printf("Attempting to save user: %s\n", user->username);
    FILE* file = fopen(DATABASE_FILE, "ab");
    if (!file) {
        perror("Failed to open database file");
        printf("Error: %s\n", strerror(errno));
        return;
    }
    size_t written = fwrite(user, sizeof(User), 1, file);
    if (written != 1) {
        printf("Failed to write user to database\n");
        perror("Error");
    } else {
        printf("Successfully saved user: %s\n", user->username);
    }
    fclose(file);
}

User* load_database(User* existing_head) {
    free_users(existing_head);

    FILE* file = fopen(DATABASE_FILE, "rb");
    if (!file) {
        printf("No existing database file found\n");
        return NULL;
    }

    User* head = NULL;
    User temp;

    while (fread(&temp, sizeof(User), 1, file) == 1) {
        User* new_user = create_newUser(temp.username, temp.password);
        new_user->next = head;
        head = new_user;
    }

    fclose(file);
    return head;
}

User* create_newUser(const char *username, const char *password) {
    User *newUser = (User*)malloc(sizeof(User));
    strncpy(newUser->username, username, sizeof(newUser->username) - 1);
    strncpy(newUser->password, password, sizeof(newUser->password) - 1);
    newUser->username[sizeof(newUser->username) - 1] = '\0';
    newUser->password[sizeof(newUser->password) - 1] = '\0';
    newUser->next = NULL;
    return newUser;
}

void adduser(User **head, const char * username , const char * password){
    User * newUser = create_newUser(username,password);
    newUser->next= *head;
    *head= newUser;
}

User* finduser(User *head, const char *username) {
    User *current = head;
    while(current != NULL) {
        if(strncmp(current->username, username, sizeof(current->username)) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

bool verify(User *head, const char *username, const char *password) {
    User *user = finduser(head, username);
    if(user == NULL) {
        printf("User '%s' not found\n", username);
        return false;
    }
    printf("Stored password: '%s'\n", user->password);
    printf("Provided password: '%s'\n", password);
    printf("Comparison result: %d\n", strcmp(user->password, password));
    
    return strcmp(user->password, password) == 0;
}

void free_users(User* head) {
    User* current = head;
    while (current != NULL) {
        User* temp = current;
        current = current->next;
        free(temp);
    }
}

int main(void) {
    User* users = load_database(NULL);
    if (!users) {
        printf("No existing database, starting fresh\n");
        adduser(&users, "admin", "admin123");
    }

    WSADATA ws;
    if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    int reuse = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(listener, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(listener);
        WSACleanup();
        return 1;
    }
    
    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(listener);
        WSACleanup();
        return 1;
    }
    
    printf("Server started on port %d\n", PORT);
    
    FD_ZERO(&master_fd_set);
    FD_SET(listener, &master_fd_set);
    max_fd = listener;
    
    while (1) {
        fd_set read_fds = master_fd_set;
        int socket_count = select(0, &read_fds, NULL, NULL, NULL);
        
        if (socket_count == SOCKET_ERROR) {
            printf("Select error: %d\n", WSAGetLastError());
            continue;
        }
        
        for (SOCKET i = 0; i <= max_fd; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == listener) {
                    accept_new_connection();
                } else {
                    handle_client_message(i, &users);
                }
            }
        }
    }
    
    closesocket(listener);
    free_users(users);
    WSACleanup();
    return 0;
}