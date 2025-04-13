#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_diffie_hellman.h"
#include "B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_aes.h"
#include "B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_auth.h"

#define DH_KEY_SIZE 256  
#define WM_AUTH_RESULT (WM_USER + 2)
#define PORT 8080
#define BUFFER_SIZE 4096  
#define WM_NEW_MESSAGE (WM_USER + 1)

unsigned char privateKey[DH_KEY_SIZE];
unsigned char publicKey[DH_KEY_SIZE];
unsigned char sharedSecret[DH_KEY_SIZE];
int keyExchangeComplete = 0;
int keySent = 0;
int keyRecieved = 0;

int isLoggedIn = 0;
char currentUsername[50] = {0};
typedef struct {
    char username[50];
    char password[50];
    int isLogin;
} AuthData;

HWND hwndMain, hwndChatArea, hwndInputBox, hwndSendButton;
HWND hwndLogin, hwndUsername, hwndPassword, hwndLoginButton, hwndSignupButton;

SOCKET client_socket;
char messageBuffer[BUFFER_SIZE];

LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);
void *receiveMessages(void *arg);
void sendMessage();
void addMessage(const char *message, int isSent);
void ShowLoginWindow(HWND hwnd);
void ShowChatWindow(HWND hwnd);
void TryLogin();
void TrySignup();
void ConnectToServer();

DWORD WINAPI AuthThread(LPVOID lpParam) {
    AuthData *data = (AuthData *)lpParam;
    char buffer[BUFFER_SIZE];
    int responseLen;

    if (data->isLogin) {
        sprintf(buffer, "LOGIN %s %s", data->username, data->password);
    } else {
        sprintf(buffer, "SIGNUP %s %s", data->username, data->password);
    }

    send(client_socket, buffer, strlen(buffer), 0);
    responseLen = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    if (responseLen > 0) {
        buffer[responseLen] = '\0';
        char *result = _strdup(buffer);
        if (data->isLogin && strcmp(result, "LOGIN_SUCCESS") == 0) {
            strncpy(currentUsername, data->username, sizeof(currentUsername) - 1);
            currentUsername[sizeof(currentUsername) - 1] = '\0'; 
        }
        PostMessage(hwndMain, WM_AUTH_RESULT, (WPARAM)data->isLogin, (LPARAM)result);
    }

    free(data);
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    ConnectToServer();
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ChatClient";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);
    
    hwndMain = CreateWindow("ChatClient", "Secure Chat Client", WS_OVERLAPPEDWINDOW, 
                            100, 100, 500, 500, NULL, NULL, hInstance, NULL);
    ShowWindow(hwndMain, nCmdShow);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    if (client_socket != INVALID_SOCKET) {
        closesocket(client_socket);
    }
    WSACleanup();
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            ShowLoginWindow(hwnd);
            break;

        case WM_SIZE: {
            if (isLoggedIn) {
                RECT rect;
                GetClientRect(hwnd, &rect);
                
                int width = rect.right - rect.left;
                int height = rect.bottom - rect.top;

                MoveWindow(hwndChatArea, 10, 10, width - 20, height - 80, TRUE);
                MoveWindow(hwndInputBox, 10, height - 50, width - 120, 30, TRUE);
                MoveWindow(hwndSendButton, width - 100, height - 50, 90, 30, TRUE);
            }
            break;
        }

        case WM_COMMAND:
        if (isLoggedIn) {
            if (LOWORD(wp) == 3) { 
                sendMessage();
            }
        } else {
            if (LOWORD(wp) == 1) { 
                TryLogin();
            } else if (LOWORD(wp) == 2) { 
                TrySignup();
            }
        }
            break;

        case WM_NEW_MESSAGE: {
            char *msgText = (char *)wp;
            addMessage(msgText, 0);
            free(msgText);
            break;
        }

        case WM_AUTH_RESULT: {
            int isLogin = (int)wp;
            char *response = (char *)lp;
            
            if (isLogin) {
                if (strcmp(response, "LOGIN_SUCCESS") == 0) {
                    isLoggedIn = 1;
                    ShowChatWindow(hwndMain);
                } else {
                    MessageBox(hwndMain, "Invalid credentials", "Login Failed", MB_OK);
                }
            } else {
                if (strcmp(response, "SIGNUP_SUCCESS") == 0) {
                    MessageBox(hwndMain, "Registration successful!", "Success", MB_OK);
                } else {
                    MessageBox(hwndMain, "Username exists", "Signup Failed", MB_OK);
                }
            }
            
            free(response);
            break;
        }
        
        case WM_KEYDOWN:
            if (wp == VK_RETURN) {
                if (isLoggedIn) {
                    if (GetKeyState(VK_SHIFT) & 0x8000) {
                        int curPos = SendMessage(hwndInputBox, EM_GETSEL, 0, 0) & 0xFFFF;
                        SendMessage(hwndInputBox, EM_REPLACESEL, TRUE, (LPARAM)"\r\n");
                    } else {
                        sendMessage();
                    }
                    return 0;
                }
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

void ShowLoginWindow(HWND hwnd) {
    if (IsWindow(hwndChatArea)) DestroyWindow(hwndChatArea);
    if (IsWindow(hwndInputBox)) DestroyWindow(hwndInputBox);
    if (IsWindow(hwndSendButton)) DestroyWindow(hwndSendButton);

    CreateWindow("STATIC", "Username:", WS_CHILD | WS_VISIBLE,
                 50, 50, 80, 25, hwnd, NULL, NULL, NULL);
    
    hwndUsername = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                140, 50, 200, 25, hwnd, NULL, NULL, NULL);
    
    CreateWindow("STATIC", "Password:", WS_CHILD | WS_VISIBLE,
                 50, 90, 80, 25, hwnd, NULL, NULL, NULL);
    
    hwndPassword = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                                140, 90, 200, 25, hwnd, NULL, NULL, NULL);
    
    hwndLoginButton = CreateWindow("BUTTON", "Login", WS_CHILD | WS_VISIBLE,
                                   140, 130, 90, 30, hwnd, (HMENU)1, NULL, NULL);
    
    hwndSignupButton = CreateWindow("BUTTON", "Sign Up", WS_CHILD | WS_VISIBLE,
                                    250, 130, 90, 30, hwnd, (HMENU)2, NULL, NULL);
    
    SetWindowText(hwndMain, "Secure Chat - Login");
}

void ShowChatWindow(HWND hwnd) {
    if (IsWindow(hwndUsername)) DestroyWindow(hwndUsername);
    if (IsWindow(hwndPassword)) DestroyWindow(hwndPassword);
    if (IsWindow(hwndLoginButton)) DestroyWindow(hwndLoginButton);
    if (IsWindow(hwndSignupButton)) DestroyWindow(hwndSignupButton);

    hwndChatArea = CreateWindow("EDIT", "", 
                               WS_CHILD | WS_VISIBLE | WS_VSCROLL | 
                               ES_MULTILINE | ES_READONLY,
                               10, 10, 460, 350, hwnd, NULL, NULL, NULL);
    
    hwndInputBox = CreateWindow("EDIT", "", 
                               WS_CHILD | WS_VISIBLE | WS_BORDER | 
                               ES_MULTILINE | ES_AUTOVSCROLL,
                               10, 370, 360, 30, hwnd, NULL, NULL, NULL);
    
    hwndSendButton = CreateWindow("BUTTON", "Send", WS_CHILD | WS_VISIBLE,
                                 380, 370, 90, 30, hwnd, (HMENU)3, NULL, NULL);
    
    char windowTitle[100];
    sprintf(windowTitle, "Secure Chat - %s", currentUsername);
    SetWindowText(hwndMain, windowTitle);
}

void TryLogin() {
    AuthData *data = malloc(sizeof(AuthData));
    GetWindowText(hwndUsername, data->username, sizeof(data->username));
    GetWindowText(hwndPassword, data->password, sizeof(data->password));
    data->isLogin = 1;
    CreateThread(NULL, 0, AuthThread, data, 0, NULL);
}

void TrySignup() {
    AuthData *data = malloc(sizeof(AuthData));
    GetWindowText(hwndUsername, data->username, sizeof(data->username));
    GetWindowText(hwndPassword, data->password, sizeof(data->password));
    data->isLogin = 0;
    CreateThread(NULL, 0, AuthThread, data, 0, NULL);
}

void ConnectToServer() {
    WSADATA ws;
    if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
        MessageBox(hwndMain, "WSAStartup failed", "Error", MB_OK);
        return;
    }

    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket == INVALID_SOCKET) {
        char msg[256];
        sprintf(msg, "Socket creation failed: %d", WSAGetLastError());
        MessageBox(hwndMain, msg, "Socket Error", MB_OK);
        return;
    }

    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    serv.sin_addr.s_addr = inet_addr(""); // Enter IP Address of the server here

    if (connect(client_socket, (struct sockaddr *)&serv, sizeof(serv)) == SOCKET_ERROR) {
        char msg[256];
        sprintf(msg, "connect() failed with error: %d", WSAGetLastError());
        MessageBox(hwndMain, msg, "Connection Error", MB_OK);

        closesocket(client_socket);
        client_socket = INVALID_SOCKET;
        return;
    }

    generateDHKeyPair(privateKey, publicKey);

    pthread_t recvThread;
    pthread_create(&recvThread, NULL, receiveMessages, NULL);
}

void *receiveMessages(void *arg) {
    char buffer[BUFFER_SIZE * 2];
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int status = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (status <= 0) break;
        
        if ((strncmp(buffer, "DH_PUBKEY:", 10) == 0) && !keySent && !keyRecieved) {
            unsigned char otherPublicKey[DH_KEY_SIZE];
            memcpy(otherPublicKey, buffer + 10, DH_KEY_SIZE);
            generateSharedSecret(sharedSecret, privateKey, otherPublicKey);
            
            addMessage("Received key exchange request...", 0);
            
            char keyMsg[BUFFER_SIZE + DH_KEY_SIZE];
            sprintf(keyMsg, "DH_PUBKEY:");
            memcpy(keyMsg + 10, publicKey, DH_KEY_SIZE);
            send(client_socket, keyMsg, 10 + DH_KEY_SIZE, 0);
            
            keySent = 1;
            keyRecieved = 1;
            addMessage("Secure connection established!", 0);
        }
        else if ((strncmp(buffer, "DH_PUBKEY:", 10) == 0) && keySent && !keyRecieved) {
            unsigned char otherPublicKey[DH_KEY_SIZE];
            memcpy(otherPublicKey, buffer + 10, DH_KEY_SIZE);
            generateSharedSecret(sharedSecret, privateKey, otherPublicKey);
            
            addMessage("Received key in return...", 0);
            keyRecieved = 1;
            addMessage("Secure connection established!", 0);
        }
        else if (keySent && keyRecieved && strncmp(buffer, "ENC:", 4) == 0) {
            unsigned char encryptedData[BUFFER_SIZE];
            int encryptedLen = status - 4;
            memcpy(encryptedData, buffer + 4, encryptedLen);
            
            unsigned char decryptedData[BUFFER_SIZE];
            int decryptedLen = aesDecrypt(encryptedData, encryptedLen, sharedSecret, decryptedData);
            
            if (decryptedLen >= 0) {
                decryptedData[decryptedLen] = '\0';
                PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup((char*)decryptedData), 0);
            } else {
                PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup("Error: Failed to decrypt message"), 0);
            }
        }
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
        char keyMsg[BUFFER_SIZE + DH_KEY_SIZE];
        sprintf(keyMsg, "DH_PUBKEY:");
        memcpy(keyMsg + 10, publicKey, DH_KEY_SIZE);
        send(client_socket, keyMsg, 10 + DH_KEY_SIZE, 0);
        addMessage("Initiating secure connection...", 1);
        keySent = 1;
    } else {
        unsigned char encryptedData[BUFFER_SIZE * 2];
        aesEncrypt((unsigned char*)messageBuffer, strlen(messageBuffer), sharedSecret, encryptedData);
        
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
    
    SendMessage(hwndChatArea, EM_SETSEL, 0, -1);
    SendMessage(hwndChatArea, EM_SETSEL, -1, -1);
    SendMessage(hwndChatArea, EM_SCROLLCARET, 0, 0);
}