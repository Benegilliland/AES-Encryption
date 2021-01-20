#include <iostream>

#define uchar unsigned char
#define ROTL8(x,shift) ((uchar) ((x) << (shift)) | ((x) >> (8 - (shift))))

void printWords(int x, uchar* word) {
	for (int i = 0; i < x; i++) {
		for (int j = 0; j < 4; j++) {
			std::cout << std::hex << (int)word[i+4*j] << " ";
		}
		std::cout << "\n";
	}
}

void copy(uchar* array1, uchar* array2, int size) {
	for (int i = 0; i < size; i++) {
		array2[i] = array1[i];
	}
}

void initialize_aes_sbox(uchar* sbox) {
	uchar p = 1, q = 1;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x11B : 0);

		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		uchar xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63;
	} while (p != 1);

	sbox[0] = 0x63;
}

void AddRoundKey(uchar* state, uchar* word) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4*j] = word[i + 4*j] ^ state[i + 4*j];
		}
	}
}


uchar GMul(uchar a, uchar b) { // Galois Field (256) Multiplication of two Bytes
	uchar p = 0;

	for (int counter = 0; counter < 8; counter++) {
		if ((b & 1) != 0) {
			p ^= a;
		}

		bool hi_bit_set = (a & 0x80) != 0;
		a <<= 1;
		if (hi_bit_set) {
			a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}

	return p;
}

void ShiftRows(uchar* state) {
	uchar state2[16];
	copy(state, state2, 16);
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i + 4 * j] = state[i + 4 * ((j+i)%4)];
		}
	}
	copy(state2, state, 16);
}

void MixColumns(uchar* state) {
	uchar state2[16];
	for (int i = 0; i < 4; i++) {
		state2[4*i] = GMul(0x02, state[4*i]) ^ GMul(0x03, state[4*i + 1]) ^ GMul(0x01, state[4*i + 2]) ^ GMul(0x01, state[4*i + 3]);
		state2[4*i+1] = GMul(0x01, state[4*i]) ^ GMul(0x02, state[4*i + 1]) ^ GMul(0x03, state[4*i + 2]) ^ GMul(0x01, state[4*i + 3]);
		state2[4*i+2] = GMul(0x01, state[4*i]) ^ GMul(0x01, state[4*i + 1]) ^ GMul(0x02, state[4*i + 2]) ^ GMul(0x03, state[4*i + 3]);
		state2[4*i+3] = GMul(0x03, state[4*i]) ^ GMul(0x01, state[4*i + 1]) ^ GMul(0x01, state[4*i + 2]) ^ GMul(0x02, state[4*i + 3]);
	}
	copy(state2, state, 16);
}

uchar calculate_sub(uchar s, uchar* sbox) {
	uchar hex_i, hex_j;
	hex_i = s & 0x0F;
	hex_j = (s >> 4) & 0x0F;
	return sbox[hex_i + 16 * hex_j];
}

void SubBytes(uchar* state, uchar* sbox) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = calculate_sub(state[i + 4 * j], sbox);
		}
	}
}

void SubWord(uchar* word, uchar* sbox) {
	uchar temp[4];
	for (int i = 0; i < 4; i++) {
		temp[i] = calculate_sub(word[i], sbox);
	}
	copy(temp, word, 4);
}

void RotWord(uchar* word) {
	uchar temp[4] = { word[1],word[2],word[3],word[0] };
	copy(temp, word, 4);
}

void KeyExpansion(uchar* key, uchar* w, uchar* sbox, int nk) {
	uchar temp[4];
	const uchar Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

	copy(key, w, 4 * nk);
	int i = nk;

	while (i < 4 * (nk + 7)) {
		copy(&w[4 * (i - 1)], temp, 4);
		if (i % nk == 0) {
			RotWord(temp);
			SubWord(temp, sbox);
			temp[0] = temp[0] ^ Rcon[(i / nk) - 1];
		}
		else if (nk > 6 && i % nk == 4) {
			SubWord(temp, sbox);
		}
		for (int j = 0; j < 4; j++) {
			w[4 * i + j] = w[4 * (i - nk) + j] ^ temp[j];
		}
		i++;
	}
}

void AES_Cipher(uchar* input, uchar* output, uchar* w, uchar* sbox, int nk) {
	uchar state[16];

	copy(input, state, 16);

	AddRoundKey(state, w);

	for (int round = 1; round < (nk + 6); round++) {
		SubBytes(state, sbox);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, &w[round * 16]);
	}

	SubBytes(state, sbox);
	ShiftRows(state);
	AddRoundKey(state, &w[(nk + 6) * 16]);

	copy(state, output, 16);
}

void InvShiftRows(uchar* state) {
	uchar state2[16];
	copy(state, state2, 16);
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i + 4 * j] = state[i + 4 * ((j + 3 * i) % 4)];
		}
	}
	copy(state2, state, 16);
}

uchar calculate_inv_sub(uchar s, uchar* sbox) { // Reverse table lookup
	for (uchar i = 0; i < 16; i++) {
		for (uchar j = 0; j < 16; j++) {
			if (sbox[i + 16 * j] == s) {
				return ((j << 4) | i);
			}
		}
	}
	return 0x00;
}

void InvSubBytes(uchar* state, uchar* sbox) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = calculate_inv_sub(state[i + 4 * j], sbox);
		}
	}
}

void InvMixColumns(uchar* state) {
	uchar state2[16];
	for (int i = 0; i < 4; i++) {
		state2[4*i] = GMul(0x0e, state[4*i]) ^ GMul(0x0b, state[4*i + 1]) ^ GMul(0x0d, state[4*i + 2]) ^ GMul(0x09, state[4*i + 3]);
		state2[4*i+1] = GMul(0x09, state[4*i]) ^ GMul(0x0e, state[4*i + 1]) ^ GMul(0x0b, state[4*i + 2]) ^ GMul(0x0d, state[4*i + 3]);
		state2[4*i+2] = GMul(0x0d, state[4*i]) ^ GMul(0x09, state[4*i + 1]) ^ GMul(0x0e, state[4*i + 2]) ^ GMul(0x0b, state[4*i + 3]);
		state2[4*i+3] = GMul(0x0b, state[4*i]) ^ GMul(0x0d, state[4*i + 1]) ^ GMul(0x09, state[4*i + 2]) ^ GMul(0x0e, state[4*i + 3]);
	}
	copy(state2, state, 16);
}

void Inverse_AES_Cipher(uchar* input, uchar* output, uchar* w, uchar* sbox, int nk) {
	uchar state[16];
	copy(input, state, 16);

	AddRoundKey(state, &w[(nk + 6) * 16]);

	for (int round = nk + 5; round > 0; round--) {
		InvShiftRows(state);
		InvSubBytes(state, sbox);
		AddRoundKey(state, &w[round * 16]);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state, sbox);
	AddRoundKey(state, w);

	copy(state, output, 16);
}

int main() {
	uchar w[240];
	uchar sbox[256];
	uchar input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uchar key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	uchar output[16];
	int nk = 8;
	initialize_aes_sbox(sbox);
	KeyExpansion(key, w, sbox, nk);
	AES_Cipher(input, output, w, sbox, nk);
	std::cout << "Encrypted output:\n";
	printWords(4, output);
	Inverse_AES_Cipher(output, input, w, sbox, nk);
	std::cout << "Decrypted output:\n";
	printWords(4, input);
}
