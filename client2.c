#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define WM_NEW_MESSAGE (WM_USER + 1)

LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);
void *receiveMessages(void *arg);
void sendMessage();
void addMessage(const char *message, int isSent);

HWND hwndMain, hwndChatArea, hwndInputBox, hwndSendButton;
SOCKET client_socket;
char messageBuffer[BUFFER_SIZE];
int messageY = 10;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ChatClient";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);
    
    hwndMain = CreateWindow("ChatClient", "Client 1 Chat", WS_OVERLAPPEDWINDOW, 100, 100, 500, 500, NULL, NULL, hInstance, NULL);
    ShowWindow(hwndMain, nCmdShow);
    
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);
    
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    serv.sin_addr.s_addr = inet_addr("127.0.0.1");
    
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
            hwndChatArea = CreateWindow("STATIC", "", WS_CHILD | WS_VISIBLE,
                                        10, 10, 460, 350, hwnd, NULL, NULL, NULL);
            
            hwndInputBox = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                        10, 370, 360, 30, hwnd, NULL, NULL, NULL);
            
            hwndSendButton = CreateWindow("BUTTON", "Send", WS_CHILD | WS_VISIBLE,
                                         380, 370, 90, 30, hwnd, (HMENU)1, NULL, NULL);
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

        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        
        default:
            return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}

void *receiveMessages(void *arg) {
    char buffer[BUFFER_SIZE];
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int status = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (status <= 0) break;
        PostMessage(hwndMain, WM_NEW_MESSAGE, (WPARAM)strdup(buffer), 0);
    }
    return NULL;
}

void sendMessage() {
    GetWindowText(hwndInputBox, messageBuffer, BUFFER_SIZE);
    if (strlen(messageBuffer) == 0) return;
    send(client_socket, messageBuffer, strlen(messageBuffer), 0);
    addMessage(messageBuffer, 1);
    SetWindowText(hwndInputBox, "");
}

void addMessage(const char *message, int isSent) {
    HWND hwndMessage = CreateWindow("STATIC", message, WS_CHILD | WS_VISIBLE | SS_LEFT | WS_BORDER,
                                    isSent ? 250 : 10, messageY, 200, 30, hwndChatArea, NULL, NULL, NULL);
    
    HFONT hFont = CreateFont(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");
    SendMessage(hwndMessage, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    messageY += 40;
}
