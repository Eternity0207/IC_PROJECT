#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <ws2tcpip.h>
#include "diffie_hellman.h"
#include "aes.h"

#define DH_KEY_SIZE 256
#define PORT 8080
#define BUFFER_SIZE 4096
#define WM_NEW_MESSAGE (WM_USER + 1)

// Connection states
#define STATE_INITIAL 0
#define STATE_WAITING_FOR_PAIR 1
#define STATE_PAIRED 2
#define STATE_KEY_EXCHANGED 3

// Global variables
unsigned char privateKey[DH_KEY_SIZE];
unsigned char publicKey[DH_KEY_SIZE];
unsigned char sharedSecret[DH_KEY_SIZE];
int connectionState = STATE_INITIAL;
char target_ip[INET6_ADDRSTRLEN] = {0};
char my_ip[INET6_ADDRSTRLEN] = {0};

// Window handles and socket
HWND hwndMain, hwndChatArea, hwndInputBox, hwndSendButton, hwndIpInput;
SOCKET client_socket;
char messageBuffer[BUFFER_SIZE];

// Function prototypes
LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);
void *receiveMessages(void *arg);
void sendMessage();
void addMessage(const char *message, int isSent);
void get_local_ip();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Generate DH key pair
    generateDHKeyPair(privateKey, publicKey);
    
    // Initialize Winsock
    WSADATA ws;
    if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
        MessageBox(NULL, "WSAStartup failed!", "Error", MB_OK);
        return 1;
    }
    
    // Get local IP address
    get_local_ip();
    
    // Create main window
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ChatClient";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);
    
    hwndMain = CreateWindow("ChatClient", "Secure Chat Client", WS_OVERLAPPEDWINDOW, 
                          100, 100, 600, 600, NULL, NULL, hInstance, NULL);
    
    // Connect to server
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Change to server IP
    
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        MessageBox(NULL, "Failed to connect to server!", "Error", MB_OK);
        return 1;
    }
    
    // Send our IP address to server
    send(client_socket, my_ip, strlen(my_ip), 0);
    
    // Start receive thread
    pthread_t recv_thread;
    pthread_create(&recv_thread, NULL, receiveMessages, NULL);
    
    // Show window and start message loop
    ShowWindow(hwndMain, nCmdShow);
    UpdateWindow(hwndMain);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Cleanup
    closesocket(client_socket);
    WSACleanup();
    return 0;
}

void get_local_ip() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        strcpy(my_ip, "127.0.0.1");
        return;
    }
    
    struct hostent *host = gethostbyname(hostname);
    if (host == NULL) {
        strcpy(my_ip, "127.0.0.1");
        return;
    }
    
    // Get first IPv4 address
    for (int i = 0; host->h_addr_list[i] != NULL; i++) {
        if (host->h_addrtype == AF_INET) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[i], sizeof(struct in_addr));
            strcpy(my_ip, inet_ntoa(addr));
            return;
        }
    }
    
    strcpy(my_ip, "127.0.0.1");
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Create chat area (read-only)
            hwndChatArea = CreateWindow("EDIT", "", 
                                       WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                                       10, 10, 560, 400, hwnd, NULL, NULL, NULL);
            
            // Create IP input (shown only in initial state)
            hwndIpInput = CreateWindow("EDIT", "", 
                                     WS_CHILD | WS_VISIBLE | WS_BORDER,
                                     10, 420, 300, 25, hwnd, NULL, NULL, NULL);
            
            // Create "Connect" button
            CreateWindow("BUTTON", "Connect", 
                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                        320, 420, 100, 25, hwnd, (HMENU)2, NULL, NULL);
            
            // Create message input (initially hidden)
            hwndInputBox = CreateWindow("EDIT", "", 
                                       WS_CHILD | WS_BORDER | ES_MULTILINE,
                                       10, 460, 450, 30, hwnd, NULL, NULL, NULL);
            ShowWindow(hwndInputBox, SW_HIDE);
            
            // Create send button (initially hidden)
            hwndSendButton = CreateWindow("BUTTON", "Send",
                                        WS_CHILD | BS_PUSHBUTTON,
                                        470, 460, 100, 30, hwnd, (HMENU)1, NULL, NULL);
            ShowWindow(hwndSendButton, SW_HIDE);
            
            // Add initial message
            addMessage("Enter the IP address of the client you want to connect to:", 0);
            break;
        }
        
        case WM_SIZE: {
            RECT rect;
            GetClientRect(hwnd, &rect);
            int width = rect.right - rect.left;
            int height = rect.bottom - rect.top;
            
            // Resize controls based on connection state
            if (connectionState == STATE_INITIAL || connectionState == STATE_WAITING_FOR_PAIR) {
                MoveWindow(hwndChatArea, 10, 10, width - 20, height - 80, TRUE);
                MoveWindow(hwndIpInput, 10, height - 60, width - 120, 25, TRUE);
                MoveWindow(GetDlgItem(hwnd, 2), width - 100, height - 60, 90, 25, TRUE);
            } else {
                MoveWindow(hwndChatArea, 10, 10, width - 20, height - 120, TRUE);
                MoveWindow(hwndInputBox, 10, height - 100, width - 120, 30, TRUE);
                MoveWindow(hwndSendButton, width - 100, height - 100, 90, 30, TRUE);
            }
            break;
        }
        
        case WM_COMMAND:
            if (LOWORD(wParam) == 1) { // Send button
                sendMessage();
            } else if (LOWORD(wParam) == 2) { // Connect button
                if (connectionState == STATE_INITIAL) {
                    GetWindowText(hwndIpInput, target_ip, INET6_ADDRSTRLEN);
                    
                    // Format IP request message
                    char ip_request[BUFFER_SIZE];
                    snprintf(ip_request, BUFFER_SIZE, "IP_Address:%s", target_ip);
                    
                    // Send to server
                    send(client_socket, ip_request, strlen(ip_request), 0);
                    
                    addMessage("Waiting for client to connect...", 0);
                    connectionState = STATE_WAITING_FOR_PAIR;
                    
                    // Disable IP input
                    EnableWindow(hwndIpInput, FALSE);
                    EnableWindow(GetDlgItem(hwnd, 2), FALSE);
                }
            }
            break;
        
        case WM_NEW_MESSAGE: {
            char *msg = (char *)wParam;
            addMessage(msg, 0);
            free(msg);
            break;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void *receiveMessages(void *arg) {
    char buffer[BUFFER_SIZE];
    
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Disconnected from server"), 0);
            break;
        }
        
        buffer[bytes_received] = '\0';
        char *msg_copy = strdup(buffer);
        
        // Check for special messages from server
        if (strcmp(buffer, "IP_FOUND") == 0) {
            connectionState = STATE_PAIRED;
            
            // Update UI
            PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Client found! You can now chat securely."), 0);
            
            // Show message input controls
            PostMessage(hwndMain, WM_COMMAND, MAKEWPARAM(0, 0), 0);
            
            // Initiate key exchange
            char key_msg[BUFFER_SIZE];
            snprintf(key_msg, BUFFER_SIZE, "DH_PUBKEY:");
            memcpy(key_msg + 10, publicKey, DH_KEY_SIZE);
            send(client_socket, key_msg, 10 + DH_KEY_SIZE, 0);
            
            PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Initiating secure connection..."), 0);
            continue;
        } else if (strcmp(buffer, "IP_NOT_FOUND") == 0) {
            connectionState = STATE_INITIAL;
            PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Client not found. Please enter a different IP address."), 0);
            
            // Re-enable IP input
            PostMessage(hwndMain, WM_COMMAND, MAKEWPARAM(0, 0), 0);
            continue;
        } else if (strcmp(buffer, "PARTNER_DISCONNECTED") == 0) {
            connectionState = STATE_INITIAL;
            PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Partner disconnected. Please enter a new IP address."), 0);
            
            // Reset UI
            PostMessage(hwndMain, WM_COMMAND, MAKEWPARAM(0, 0), 0);
            continue;
        }
        
        // Handle key exchange
        if (connectionState == STATE_PAIRED && strncmp(buffer, "DH_PUBKEY:", 10) == 0) {
            unsigned char otherPublicKey[DH_KEY_SIZE];
            memcpy(otherPublicKey, buffer + 10, DH_KEY_SIZE);
            
            generateSharedSecret(sharedSecret, privateKey, otherPublicKey);
            connectionState = STATE_KEY_EXCHANGED;
            
            PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Secure connection established!"), 0);
            continue;
        }
        
        // Handle encrypted messages
        if (connectionState == STATE_KEY_EXCHANGED && strncmp(buffer, "ENC:", 4) == 0) {
            unsigned char encryptedData[BUFFER_SIZE];
            int encryptedLen = bytes_received - 4;
            memcpy(encryptedData, buffer + 4, encryptedLen);
            
            unsigned char decryptedData[BUFFER_SIZE];
            int decryptedLen = aesDecrypt(encryptedData, encryptedLen, sharedSecret, decryptedData);
            
            if (decryptedLen >= 0) {
                decryptedData[decryptedLen] = '\0';
                PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup((char *)decryptedData), 0);
            } else {
                PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Error: Failed to decrypt message"), 0);
            }
            continue;
        }
        
        // Regular messages
        PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)msg_copy, 0);
    }
    
    return NULL;
}

void sendMessage() {
    if (connectionState < STATE_PAIRED) return;
    
    GetWindowText(hwndInputBox, messageBuffer, BUFFER_SIZE);
    if (strlen(messageBuffer) == 0) return;
    
    if (connectionState == STATE_PAIRED) {
        // Send public key if not yet exchanged
        char key_msg[BUFFER_SIZE];
        snprintf(key_msg, BUFFER_SIZE, "DH_PUBKEY:");
        memcpy(key_msg + 10, publicKey, DH_KEY_SIZE);
        send(client_socket, key_msg, 10 + DH_KEY_SIZE, 0);
        
        addMessage("Initiating secure connection...", 1);
    } else if (connectionState == STATE_KEY_EXCHANGED) {
        // Encrypt and send message
        unsigned char encryptedData[BUFFER_SIZE * 2];
        aesEncrypt((unsigned char *)messageBuffer, strlen(messageBuffer), sharedSecret, encryptedData);
        
        int encryptedLen = ((strlen(messageBuffer) / 16) + 1) * 16 + 16;
        
        char encryptedMsg[BUFFER_SIZE * 2];
        strcpy(encryptedMsg, "ENC:");
        memcpy(encryptedMsg + 4, encryptedData, encryptedLen);
        
        send(client_socket, encryptedMsg, 4 + encryptedLen, 0);
        
        addMessage(messageBuffer, 1);
    }
    
    SetWindowText(hwndInputBox, "");
}

void addMessage(const char *message, int isSent) {
    char currentText[BUFFER_SIZE * 10] = {0};
    GetWindowText(hwndChatArea, currentText, sizeof(currentText));
    
    char newText[BUFFER_SIZE * 10];
    char formattedMessage[BUFFER_SIZE + 50];
    
    if (isSent) {
        snprintf(formattedMessage, BUFFER_SIZE + 50, "You: %s", message);
    } else {
        snprintf(formattedMessage, BUFFER_SIZE + 50, "Other: %s", message);
    }
    
    if (strlen(currentText) > 0) {
        snprintf(newText, BUFFER_SIZE * 10, "%s\r\n%s", currentText, formattedMessage);
    } else {
        strcpy(newText, formattedMessage);
    }
    
    SetWindowText(hwndChatArea, newText);
    SendMessage(hwndChatArea, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessage(hwndChatArea, EM_SCROLLCARET, 0, 0);
}