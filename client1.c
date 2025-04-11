#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "diffie_hellman.h"
#include "aes.h"

// Updated key size to match new implementation
#define DH_KEY_SIZE 256  // Changed from 16 to 256 bytes (2048-bit)
#define PORT 8080
#define BUFFER_SIZE 4096  // Increased buffer size to handle larger encrypted messages
#define WM_NEW_MESSAGE (WM_USER + 1)

// Global variables for cryptography
unsigned char privateKey[DH_KEY_SIZE];
unsigned char publicKey[DH_KEY_SIZE];
unsigned char sharedSecret[DH_KEY_SIZE];
int keyExchangeComplete = 0;
int keySent=0;
int keyRecieved=0;

// generateDHKeyPair(privateKey, publicKey)

LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);
void *receiveMessages(void *arg);
void sendMessage();
void addMessage(const char *message, int isSent);

HWND hwndMain, hwndChatArea, hwndInputBox, hwndSendButton;
SOCKET client_socket;
char messageBuffer[BUFFER_SIZE];

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Generate DH key pair
    generateDHKeyPair(privateKey, publicKey);
    
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ChatClient";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);
    
    hwndMain = CreateWindow("ChatClient", "Client 1 Chat", WS_OVERLAPPEDWINDOW, 
                            100, 100, 500, 500, NULL, NULL, hInstance, NULL);
    ShowWindow(hwndMain, nCmdShow);
    
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);
    
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    serv.sin_addr.s_addr = inet_addr("127.0.0.1");  // Default to localhost, change to your server IP
    
    if (connect(client_socket, (struct sockaddr *)&serv, sizeof(serv)) == SOCKET_ERROR) {
        MessageBox(NULL, "Failed to connect to server!", "Error", MB_OK);
        return 0;
    }
    
    pthread_t recvThread;
    pthread_create(&recvThread, NULL, receiveMessages, NULL);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    closesocket(client_socket);
    WSACleanup();
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            hwndChatArea = CreateWindow("EDIT", "", 
                                       WS_CHILD | WS_VISIBLE | WS_VSCROLL | 
                                       ES_MULTILINE | ES_READONLY,
                                       10, 10, 460, 350, hwnd, NULL, NULL, NULL);
            
            hwndInputBox = CreateWindow("EDIT", "", 
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | 
                                       ES_MULTILINE | ES_AUTOVSCROLL,
                                       10, 370, 360, 30, hwnd, NULL, NULL, NULL);
            
            hwndSendButton = CreateWindow("BUTTON", "Send", WS_CHILD | WS_VISIBLE,
                                         380, 370, 90, 30, hwnd, (HMENU)1, NULL, NULL);
            break;

        case WM_SIZE: {
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            int width = rect.right - rect.left;
            int height = rect.bottom - rect.top;

            // Resize chat area
            MoveWindow(hwndChatArea, 10, 10, width - 20, height - 80, TRUE);

            // Resize input box
            MoveWindow(hwndInputBox, 10, height - 50, width - 120, 30, TRUE);

            // Resize send button
            MoveWindow(hwndSendButton, width - 100, height - 50, 90, 30, TRUE);
        }
        break;

        case WM_COMMAND:
            if (LOWORD(wp) == 1) sendMessage();
            break;

        case WM_NEW_MESSAGE: {
            char *msgText = (char *)wp;
            addMessage(msgText, 0);
            free(msgText);
            break;
        }

        case WM_KEYDOWN:
            if (wp == VK_RETURN) {
                // Check if Shift key is pressed
                if (GetKeyState(VK_SHIFT) & 0x8000) {
                    // Shift+Enter: Add a new line
                    int curPos = SendMessage(hwndInputBox, EM_GETSEL, 0, 0) & 0xFFFF;
                    SendMessage(hwndInputBox, EM_REPLACESEL, TRUE, (LPARAM)"\r\n");
                } else {
                    // Enter only: Send the message
                    sendMessage();
                }
                return 0;
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}

void *receiveMessages(void *arg) {
    char buffer[BUFFER_SIZE * 2]; // Double buffer size to safely handle large messages
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int status = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (status <= 0) break;
        
        // Check if this is a key exchange message
        if ((strncmp(buffer, "DH_PUBKEY:", 10) == 0) && !keySent && !keyRecieved) {
            // Extract the other client's public key
            unsigned char otherPublicKey[DH_KEY_SIZE];
            memcpy(otherPublicKey, buffer + 10, DH_KEY_SIZE);

            // Generate the shared secret
            generateSharedSecret(sharedSecret, privateKey, otherPublicKey);
            
            // Add a message to the chat
            addMessage("Received key exchange request...", 0);
            
            // Always send our key back in response
            char keyMsg[BUFFER_SIZE + DH_KEY_SIZE];
            sprintf(keyMsg, "DH_PUBKEY:");
            memcpy(keyMsg + 10, publicKey, DH_KEY_SIZE);
            send(client_socket, keyMsg, 10 + DH_KEY_SIZE, 0);
            
            // Set key exchange as complete AFTER sending our key
            keySent = 1;
            keyRecieved=1;
            addMessage("Secure connection established!", 0);
            // addMessage(sharedSecret, 0);
        }
        else if ((strncmp(buffer, "DH_PUBKEY:", 10) == 0) && keySent && !keyRecieved) {
            // Extract the other client's public key
            unsigned char otherPublicKey[DH_KEY_SIZE];
            memcpy(otherPublicKey, buffer + 10, DH_KEY_SIZE);

            // Generate the shared secret
            generateSharedSecret(sharedSecret, privateKey, otherPublicKey);
            
            // Add a message to the chat
            addMessage("Received key in return...", 0);

            keyRecieved=1;
            addMessage("Secure connection established!", 0);
            // addMessage(sharedSecret, 0);

        }
        // Check if this is an encrypted message
        else if (keySent && keyRecieved && strncmp(buffer, "ENC:", 4) == 0) {
            // Extract the encrypted data
            unsigned char encryptedData[BUFFER_SIZE];
            int encryptedLen = status - 4;
            memcpy(encryptedData, buffer + 4, encryptedLen);
            
            // Decrypt the data
            unsigned char decryptedData[BUFFER_SIZE];
            int decryptedLen = aesDecrypt(encryptedData, encryptedLen, sharedSecret, decryptedData);
            
            if (decryptedLen >= 0) {
                // Null-terminate the decrypted message
                decryptedData[decryptedLen] = '\0';
                
                // Post the decrypted message
                PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup((char*)decryptedData), 0);
            } else {
                // Handle decryption error
                PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Error: Failed to decrypt message"), 0);
            }
        }
        // Regular message (before key exchange)
        else {
            PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup(buffer), 0);
        }
    }
    return NULL;
}

void sendMessage() {
    GetWindowText(hwndInputBox, messageBuffer, BUFFER_SIZE);
    if (strlen(messageBuffer) == 0) return;
    
    if (!keySent && !keyRecieved) {
        // First message initiates key exchange
        char keyMsg[BUFFER_SIZE + DH_KEY_SIZE];
        sprintf(keyMsg, "DH_PUBKEY:");
        memcpy(keyMsg + 10, publicKey, DH_KEY_SIZE);
        send(client_socket, keyMsg, 10 + DH_KEY_SIZE, 0);
        addMessage("Initiating secure connection...", 1);
        keySent=1;
    } else {
        // Encrypt the message using the updated AES implementation
        unsigned char encryptedData[BUFFER_SIZE * 2]; // Need extra space for IV and padding
        aesEncrypt((unsigned char*)messageBuffer, strlen(messageBuffer), sharedSecret, encryptedData);
        
        // Calculate the encrypted message length (original + padding + IV)
        int encryptedLen = ((strlen(messageBuffer) / 16) + 1) * 16 + 16; // IV size is 16 bytes
        
        // Prepare message with prefix
        char encryptedMsg[BUFFER_SIZE * 2];
        strcpy(encryptedMsg, "ENC:");
        
        // Append the encrypted data
        memcpy(encryptedMsg + 4, encryptedData, encryptedLen);
        
        // Send the encrypted message
        send(client_socket, encryptedMsg, 4 + encryptedLen, 0);
        
        // Display the original message in our chat window
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
        sprintf(formattedMessage, "You:\r\n%s", message);
    } else {
        sprintf(formattedMessage, "Friend:\r\n%s", message);
    }

    if (strlen(currentText) > 0) {
        sprintf(newText, "%s\r\n\r\n%s", currentText, formattedMessage);
    } else {
        strcpy(newText, formattedMessage);
    }

    SetWindowText(hwndChatArea, newText);
    
    // Scroll to the bottom of the chat area
    SendMessage(hwndChatArea, EM_SETSEL, 0, -1);
    SendMessage(hwndChatArea, EM_SETSEL, -1, -1);
    SendMessage(hwndChatArea, EM_SCROLLCARET, 0, 0);
}
