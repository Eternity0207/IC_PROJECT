#define _WIN32_WINNT 0x0600  // Must be first line for Windows compatibility
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include<stdbool.h>


#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100

// Forward declarations
typedef struct ClientNode ClientNode;

struct ClientNode {
    SOCKET socket;
    char ip[INET6_ADDRSTRLEN];
    SOCKET paired_socket;
    ClientNode *next;
};

// Global variables
ClientNode *client_list = NULL;
SOCKET listener = INVALID_SOCKET;
fd_set master_fd_set;
SOCKET max_fd = 0;

// Function prototypes
void add_client(SOCKET socket, const char *ip);
void remove_client(SOCKET socket);
ClientNode *find_client_by_ip(const char *ip);
ClientNode *find_client_by_socket(SOCKET socket);
void handle_ip_request(SOCKET sender_socket, const char *requested_ip);
void forward_message(SOCKET sender_socket, const char *msg, int msg_len);
void accept_new_connection();
void handle_client_message(SOCKET client_socket);

void add_client(SOCKET socket, const char *ip) {
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

void handle_ip_request(SOCKET sender_socket, const char *requested_ip) {
    ClientNode *sender = find_client_by_socket(sender_socket);
    if (sender == NULL) return;
    
    ClientNode *target = find_client_by_ip(requested_ip);
    
    if (target != NULL && target != sender && target->paired_socket == INVALID_SOCKET) {
        sender->paired_socket = target->socket;
        target->paired_socket = sender->socket;
        
        send(sender_socket, "IP_FOUND", 8, 0);
        send(target->socket, "IP_FOUND", 8, 0);
        
        printf("Clients paired: %s <-> %s\n", sender->ip, target->ip);
    } else {
        send(sender_socket, "IP_NOT_FOUND", 12, 0);
    }
}

void forward_message(SOCKET sender_socket, const char *msg, int msg_len) {
    ClientNode *sender = find_client_by_socket(sender_socket);
    if (sender == NULL || sender->paired_socket == INVALID_SOCKET) return;
    
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
    
    const char *welcome_msg = "Welcome! Send the IP address of the client you want to connect to in the format: IP_Address:xxx.xxx.xxx.xxx";
    send(new_socket, welcome_msg, strlen(welcome_msg), 0);
}

void handle_client_message(SOCKET client_socket) {
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
    
    if (client->paired_socket == INVALID_SOCKET) {
        if (strncmp(buffer, "IP_Address:", 11) == 0) {
            char requested_ip[INET6_ADDRSTRLEN];
            strncpy(requested_ip, buffer + 11, INET6_ADDRSTRLEN - 1);
            requested_ip[INET6_ADDRSTRLEN - 1] = '\0';
            handle_ip_request(client_socket, requested_ip);
        }
    } else {
        forward_message(client_socket, buffer, bytes_received);
    }
}
/// hellooooooooooooooooooooo
typedef struct User{
    char username[20];
    char password[20];
    struct User * next;
} User;

void save_to_database(User* user) {
    FILE* file = fopen(DATABASE_FILE, "ab");
    if (!file) {
        perror("Failed to open database file");
        return;
    }
    fwrite(user, sizeof(User), 1, file);
    fclose(file);
}

User* load_database() {
    FILE* file = fopen(DATABASE_FILE, "rb");
    if (!file) {
        return NULL;
    }

    User* head = NULL;
    User temp;

    while (fread(&temp, sizeof(User), 1, file) == 1) {
        User* new_user = malloc(sizeof(User));
        *new_user = temp;
        new_user->next = head;
        head = new_user;
    }

    fclose(file);
    return head;
}



User * create_newUser(const char * username, const char * password){
    User * newUser=(User*)malloc(sizeof(User)); // allocating memory in heap for new user
    strncpy(newUser->username,username,sizeof(newUser->username));
    strncpy(newUser->password,password,sizeof(newUSer->password));
    newUser->next=NULL;

    return newUser;
}

void adduser(User **head, const char * username , const char * password){
    User * newUser = create_newUser(username,password);
    newUser->next= *head;
    *head= newUSer;
}

User * finduser(User * head , const char * username){
    User * current = head;
    while(current != NULL){
        if(strncmp(current->username,username)==0){
            return current ;
        }

        current = current -> next;
    }

    return NULL;

}

bool verify(User * head, const char * username, const char * password){
    User * user= finduser(head,username);

    if(user==NULL){
        return NULL;
    }

    return strcmp(user->password,password)==0 ;
}


void free_users(User* head) {
    User* current = head;
    while (current != NULL) {
        User* temp = current;
        current = current->next;
        free(temp);
    }
}

//////okppppppppp

int main(void) {



    User* users = load_database();
    if (!users) {
        printf("No existing database, starting fresh\n");
        // Add some default users if needed
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

        char username[50], password[50];
        
        
        recv(client_socket, username, sizeof(username), 0);
        recv(client_socket, password, sizeof(password), 0);
        
       
        bool result = verify(users, username, password);
        
       
        if (result) {
            send(client_socket, "Login successful", 16, 0);
            printf("User %s logged in\n", username);
        } else {
            send(client_socket, "Login failed", 12, 0);
            printf("Failed login for %s\n", username);
        }

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
                    handle_client_message(i);
                }
            }
        }
    }
    
    closesocket(listener);
    free_users(users);
    WSACleanup();
    return 0;
}