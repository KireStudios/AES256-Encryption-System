#include "AES256.hpp"

// Expand the key into a set of round keys
void AES256::KeyExpansion(const uint8_t key[32], uint32_t subKeys[60]) {
	// Copy the initial key into the first part of subKeys
	for (int i = 0; i < 8; i++) {
		subKeys[i] = (key[4 * i] << 24) |
					 (key[4 * i + 1] << 16) |
					 (key[4 * i + 2] << 8) |
					 key[4 * i + 3];
	}

	// Generate the remaining subKeys
	for (int i = 8; i < 60; i++) {
		if (i % 8 == 0) {
			subKeys[i] = subKeys[i - 8] ^ SubWord(RotWord(subKeys[i - 1])) ^ RCon[i / 8];
		}
		else if (i % 8 == 4) {
			subKeys[i] = subKeys[i - 8] ^ SubWord(subKeys[i - 1]);
		}
		else {
			subKeys[i] = subKeys[i - 8] ^ subKeys[i - 1];
		}
	}
}

// Encrypt plaintext using AES-256 algorithm
void AES256::Encrypt(const uint8_t* plaintext, const uint8_t key[32], uint8_t* ciphertext) {
	uint8_t State[4][4];
	uint8_t Keys[15][4][4];

	uint32_t SubKeys[60];

	// Expand the key
	KeyExpansion(key, SubKeys);

	// Copy plaintext into the State matrix
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[j][i] = plaintext[4 * i + j];
		}
	}

	// Prepare the Keys for the rounds
	for (int i = 0; i < 15; i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				Keys[i][k][j] = SubKeys[4 * i + j] >> (8 * (3 - k)) << 24;
			}
		}
	}

	/// Initial Round
	// Add RoundKey
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[i][j] = State[i][j] ^ Keys[0][i][j];
		}
	}

	/// Main Rounds
	for (int r = 1; r < 15; r++) {
		// Sub Bytes
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				State[i][j] = SBox[State[i][j]];
			}
		}

		// Shift Rows
		for (int i = 1; i < 4; i++) {
			uint8_t* temp = new uint8_t[i];

			// Copy the first 'shift' elements to the temporary array
			for (int j = 0; j < i; j++) {
				temp[j] = State[i][j];
			}

			// Shift the remaining elements to the left
			for (int j = 0; j < 4 - i; j++) {
				State[i][j] = State[i][j + i];
			}

			// Copy the temporary array elements to the end of the original array
			for (int j = 0; j < i; j++) {
				State[i][4 - i + j] = temp[j];
			}

			delete[] temp;
		}

		// Mix Columns
		uint8_t temp[4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp[j] = State[j][i];
			}
			State[0][i] = gf_mul(0x02, temp[0]) ^ gf_mul(0x03, temp[1]) ^ gf_mul(0x01, temp[2]) ^ gf_mul(0x01, temp[3]);
			State[1][i] = gf_mul(0x01, temp[0]) ^ gf_mul(0x02, temp[1]) ^ gf_mul(0x03, temp[2]) ^ gf_mul(0x01, temp[3]);
			State[2][i] = gf_mul(0x01, temp[0]) ^ gf_mul(0x01, temp[1]) ^ gf_mul(0x02, temp[2]) ^ gf_mul(0x03, temp[3]);
			State[3][i] = gf_mul(0x03, temp[0]) ^ gf_mul(0x01, temp[1]) ^ gf_mul(0x01, temp[2]) ^ gf_mul(0x02, temp[3]);
		}

		// Add RoundKey
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				State[i][j] = State[i][j] ^ Keys[r][i][j];
			}
		}
	}

	/// Final Round
	// Sub Bytes
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[i][j] = SBox[State[i][j]];
		}
	}

	// Shift Rows Left
	for (int i = 1; i < 4; i++) {
		uint8_t* temp = new uint8_t[i];

		// Copy the first 'shift' elements to the temporary array
		for (int j = 0; j < i; j++) {
			temp[j] = State[i][j];
		}

		// Shift the remaining elements to the left
		for (int j = 0; j < 4 - i; j++) {
			State[i][j] = State[i][j + i];
		}

		// Copy the temporary array elements to the end of the original array
		for (int j = 0; j < i; j++) {
			State[i][4 - i + j] = temp[j];
		}

		delete[] temp;
	}

	// Add RoundKey
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[i][j] = State[i][j] ^ Keys[14][i][j];
		}
	}


	/// Get the ciphertext from the State matrix
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			ciphertext[4 * i + j] = State[j][i];
		}
	}
}

// Decrypt ciphertext using AES-256 algorithm
void AES256::Decrypt(const uint8_t* ciphertext, const uint8_t key[32], uint8_t* plaintext) {
	uint8_t State[4][4];
	uint8_t Keys[15][4][4];

	uint32_t SubKeys[60];

	// Expand the key
	KeyExpansion(key, SubKeys);

	// Copy ciphertext into the State matrix
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[j][i] = ciphertext[4 * i + j];
		}
	}

	// Prepare the Keys for the rounds
	for (int i = 0; i < 15; i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				Keys[i][k][j] = SubKeys[4 * i + j] >> (8 * (3 - k)) << 24;
			}
		}
	}

	/// Initial Round
	// Add RoundKey
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[i][j] = State[i][j] ^ Keys[14][i][j];
		}
	}

	/// Main Rounds
	for (int r = 14; r > 0; r--) {
		// Shift Rows Right
		for (int i = 1; i < 4; i++) {
			uint8_t* temp = new uint8_t[i];

			// Copy the last 'shift' elements to the temporary array
			for (int j = 0; j < i; j++) {
				temp[j] = State[i][4 - i + j];
			}

			// Shift the remaining elements to the right
			for(int j = 3; j >= i; j--) {
				State[i][j] = State[i][j - i];
			}

			// Copy the temporary array elements to the beginning of the original array
			for (int j = 0; j < i; j++) {
				State[i][j] = temp[j];
			}

			delete[] temp;
		}

		// Inverse Sub Bytes
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				State[i][j] = InvSBox[State[i][j]];
			}
		}

		// Add RoundKey
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				State[i][j] = State[i][j] ^ Keys[r][i][j];
			}
		}

		// Inverse Mix Columns
		uint8_t temp[4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp[j] = State[j][i];
			}
			State[0][i] = gf_mul(0x0E, temp[0]) ^ gf_mul(0x0B, temp[1]) ^ gf_mul(0x0D, temp[2]) ^ gf_mul(0x09, temp[3]);
			State[1][i] = gf_mul(0x09, temp[0]) ^ gf_mul(0x0E, temp[1]) ^ gf_mul(0x0B, temp[2]) ^ gf_mul(0x0D, temp[3]);
			State[2][i] = gf_mul(0x0D, temp[0]) ^ gf_mul(0x09, temp[1]) ^ gf_mul(0x0E, temp[2]) ^ gf_mul(0x0B, temp[3]);
			State[3][i] = gf_mul(0x0B, temp[0]) ^ gf_mul(0x0D, temp[1]) ^ gf_mul(0x09, temp[2]) ^ gf_mul(0x0E, temp[3]);
		}
	}

	/// Final Round
	// Shift Rows Right
	for (int i = 1; i < 4; i++) {
		uint8_t* temp = new uint8_t[i];

		// Copy the last 'shift' elements to the temporary array
		for (int j = 0; j < i; j++) {
			temp[j] = State[i][4 - i + j];
		}

		// Shift the remaining elements to the right
		for (int j = 3; j >= i; j--) {
			State[i][j] = State[i][j - i];
		}

		// Copy the temporary array elements to the beginning of the original array
		for (int j = 0; j < i; j++) {
			State[i][j] = temp[j];
		}

		delete[] temp;
	}

	// Inverse Sub Bytes
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[i][j] = InvSBox[State[i][j]];
		}
	}

	// Add RoundKey
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			State[i][j] = State[i][j] ^ Keys[0][i][j];
		}
	}


	/// Get the plaintext from the State matrix
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			plaintext[4 * i + j] = State[j][i];
		}
	}
}