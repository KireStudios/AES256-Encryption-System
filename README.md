# AES-256 Encryption and Decryption

This repository contains a C++ implementation of the AES-256 (Advanced Encryption Standard) algorithm. The implementation includes both encryption and decryption functionalities and is designed to work with 32-byte keys.

## Features

- **AES-256 Support**: Encrypt and decrypt data using AES-256 with a 32-byte key.
- **Static Methods**: Methods for encryption and decryption are static, allowing for easy usage without needing to instantiate the class.
- **Key Expansion**: Automatically handles key expansion to generate round keys required for AES-256.

## Files

- `AES256.hpp`: Header file containing the `AES256` class definition with method declarations.
- `AES256.cpp`: Implementation file with definitions of the methods declared in `AES256.hpp`.

## Usage

### Encryption

To encrypt a block of plaintext, use the `Encrypt` method:

```cpp
#include "AES256.hpp"
#include <iostream>
#include <cstdint>

int main() {
    uint8_t key[32] = { /* 32-byte key */ };
    uint8_t plaintext[16] = { /* 16-byte plaintext block */ };
    uint8_t ciphertext[16];

    AES256::Encrypt(plaintext, key, ciphertext);

    // Output or use the encrypted ciphertext
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << static_cast<int>(ciphertext[i]) << " ";
    }

    return 0;
}
```

### Decryption

To decrypt a block of ciphertext, use the `Decrypt` method:

```cpp
#include "AES256.hpp"
#include <iostream>
#include <cstdint>

int main() {
    uint8_t key[32] = { /* 32-byte key */ };
    uint8_t ciphertext[16] = { /* 16-byte ciphertext block */ };
    uint8_t plaintext[16];

    AES256::Decrypt(ciphertext, key, plaintext);

    // Output or use the decrypted plaintext
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << static_cast<int>(plaintext[i]) << " ";
    }

    return 0;
}
```

### Key Expansion

The `KeyExpansion` method generates round keys from the original AES-256 key. This is a crucial part of the AES algorithm, which allows the encryption and decryption processes to use multiple round keys.

### Encryption and Decryption Process

- **Encryption**: The process involves several rounds of transformations:

    1. **Initial Round**: Add RoundKey
    2. **Main Rounds**: SubBytes, ShiftRows, MixColumns, AddRoundKey
    3. **Final Round**: SubBytes, ShiftRows, AddRoundKey
- **Decryption**: The process involves reversing the encryption steps with the appropriate inverse operations.

## Requirements

- C++11 or later

## Compilation

To compile the provided source code, you need a C++ compiler such as `g++`. Follow these steps:

1. **Open a terminal** in the root directory of your project where the source files are located.
2. **Compile the code** using the following command:

```sh
g++ -std=c++11 -o aes256_example aes256_example.cpp AES256.cpp
```

Replace `aes256_example.cpp` with the name of your main program file if it differs.

3. **Run the executable**:

```sh
./aes256_example
```

This will build the project and create an executable file named `aes256_example`. Adjust file names as necessary based on your project setup.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or feedback, please contact [erik.ventura.gili@gmail.com](mailto:erik.ventura.gili@gmail.com).