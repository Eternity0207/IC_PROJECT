# Messenger App

A minimalist messenger application that enables secure communication between two IP addresses. The app incorporates **Diffie-Hellman Key Exchange** for secure key sharing and **AES-256 encryption** for message confidentiality. It also features a simple and intuitive GUI for ease of use.

## Features

- **Secure Communication**: Messages are encrypted using AES-256.
- **Key Exchange**: Diffie-Hellman Key Exchange ensures secure key sharing.
- **Minimalist GUI**: A clean and user-friendly interface.
- **IP-to-IP Messaging**: Direct communication between two IP addresses.

## Technologies Used

- **Programming Language**: [Your chosen language, e.g., Python, Java]
- **Encryption**: AES-256 and Diffie-Hellman Key Exchange
- **GUI Framework**: [Your chosen framework, e.g., Tkinter, PyQt]

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
    git clone https://github.com/yourusername/messenger-app.git
    cd messenger-app
    ```
2. Install dependencies:
    ```bash
    [Add installation commands, e.g., pip install -r requirements.txt]
    ```
3. Run the application:
    ```bash
    [Add command to run the app, e.g., python app.py]
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

- [Diffie-Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Your GUI framework documentation]
