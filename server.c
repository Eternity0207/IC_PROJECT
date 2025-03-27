#define _WIN32_WINNT 0x0600 // Ensure compatibility with Vista or later

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#define PORT 8080

int listener = 0;
struct sockaddr_in serv;
int maxFd = 0;
int client[2] = {0, 0};
fd_set fr;

int msgCount[2] = {0, 0};

void acceptConnection() {
    int clientSocket = accept(listener, NULL, NULL);
    if (clientSocket < 0) {
        printf("Error accepting connection! (Error Code: %d)\n", WSAGetLastError());
        return;
    }

    for (int index = 0; index < 2; index++) {
        if (client[index] == 0) {
            client[index] = clientSocket;
            printf("Client %d connected, socket: %d\n", index + 1, clientSocket);

            if (client[index] > maxFd) {
                maxFd = client[index] + 1;
            }
            return;
        }
    }

    printf("Server is full! Rejecting connection...\n");
    closesocket(clientSocket);
}

void receiveClientMessage(int senderIndex) {
    int senderSocket = client[senderIndex];
    int receiverIndex = (senderIndex == 0) ? 1 : 0;
    int receiverSocket = client[receiverIndex];

    char msg[256] = {0};
    int err = recv(senderSocket, msg, sizeof(msg) - 1, 0);

    if (err <= 0) {
        printf("Client %d disconnected\n", senderIndex + 1);
        closesocket(client[senderIndex]);
        FD_CLR(client[senderIndex], &fr);
        client[senderIndex] = 0;

        maxFd = listener;
        for (int i = 0; i < 2; i++) {
            if (client[i] > maxFd) {
                maxFd = client[i];
            }
        }
        maxFd += 1;
    } else {
        msg[err] = '\0';
        printf("Message from Client %d: %s\n", senderIndex + 1, msg);

        if (receiverSocket != 0) {
            send(receiverSocket, msg, strlen(msg), 0);
        } else {
            char *waitingMsg = "[SERVER] Waiting for another client to connect...";
            send(senderSocket, waitingMsg, strlen(waitingMsg), 0);
        }
    }
}

int main(void) {
    WSADATA ws;
    if (WSAStartup(MAKEWORD(2, 2), &ws) < 0) {
        exit(EXIT_FAILURE);
    }

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0) {
        exit(EXIT_FAILURE);
    }

    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    InetPtonA(AF_INET, "SERVER_IP", &serv.sin_addr); // Use InetPtonA for IP address conversion
    memset(&serv.sin_zero, 0, sizeof(serv.sin_zero));

    int err = bind(listener, (struct sockaddr *)&serv, sizeof(serv));
    if (err < 0) {
        exit(EXIT_FAILURE);
    }

    err = listen(listener, 2);
    if (err < 0) {
        exit(EXIT_FAILURE);
    }

    maxFd = listener + 1;
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    while (1) {
        FD_ZERO(&fr);
        FD_SET(listener, &fr);

        for (int i = 0; i < 2; i++) {
            if (client[i] != 0) {
                FD_SET(client[i], &fr);
                if (client[i] >= maxFd) {
                    maxFd = client[i] + 1;
                }
            }
        }

        err = select(maxFd, &fr, NULL, NULL, &tv);
        if (err < 0) {
            exit(EXIT_FAILURE);
        } else if (err > 0) {
            if (FD_ISSET(listener, &fr)) {
                acceptConnection();
            } else {
                for (int i = 0; i < 2; i++) {
                    if (FD_ISSET(client[i], &fr)) {
                        receiveClientMessage(i);
                    }
                }
            }
        }
    }

    return 0;
}