# Vibify — Speak Securely, Stay Private

Vibify is a minimalist messenger application that enables secure communication between two IP addresses. The app incorporates **Diffie-Hellman Key Exchange** for secure key sharing and **AES-256 encryption** for message confidentiality. It also features a simple and intuitive GUI for ease of use.

## Features

- **Secure Communication**: Messages are encrypted using AES-256.
- **Key Exchange**: Diffie-Hellman Key Exchange ensures secure key sharing.
- **Minimalist GUI**: A clean and user-friendly interface.
- **IP-to-IP Messaging**: Direct communication between two IP addresses.

## Technologies Used

- **Programming Language**: C
- **Encryption**: AES-256 and Diffie-Hellman Key Exchange
- **GUI Framework**: Windows API (windows.h)
## How It Works

1. **Key Exchange**: 
    - The Diffie-Hellman algorithm is used to securely exchange a shared secret key between two users.
2. **Message Encryption**:
    - Messages are encrypted using AES-256 before being sent.
    - The recipient decrypts the message using the shared secret key.
3. **GUI**:
    - Users can send and receive messages through a minimalist graphical interface.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Eternity0207/IC_PROJECT.git
    cd IC_PROJECT
    ```
2. Install dependencies:
    ```bash
    Install MSYS2
    Install MinGW
    64 via MSYS2
    Install OpenSSL dependencies via MSYS2
    Use these commands:
    pacman -Syu
    pacman -S mingw-w64-x86_64-gcc (To install gcc compiler)
    pacman -S mingw-w64-x86_64-openssl (To install OpenSSL dependencies)
    pacman -S make cmake git (To install build tools)
    ```
3. Run the application:
    ```bash
    gcc server. c -0 server .exe -Iws2_32
    ./server.exe
    
    gcc client.c diffie_hellnan.c aes.c auth.c -o client.exe -lssl -lws2_32 -Icrypto -lpthread -lgdi32
    ./client.exe
    ```

## Usage

1. Launch the application.
2. Enter the IP address of the recipient.
3. Start sending and receiving encrypted messages.

## Future Enhancements

- Add support for group chats.
- Implement additional encryption algorithms.
- Improve the GUI design.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- [Diffie-Hellman Key Exchange](https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/key-exchange/diffie-hellman-key-exchange.md)
- [AES Encryption](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [Windows API (windows.h)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/)
