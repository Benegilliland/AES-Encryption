#include <iostream>

#define ROTL8(x,shift) ((unsigned char) ((x) << (shift)) | ((x) >> (8 - (shift))))

void printHex(int x, unsigned char* word) {
	for (int i = 0; i < x; i++) {
		for (int j = 0; j < 4; j++) {
			std::cout << (int)word[i+4*j] << " ";
		}
		std::cout << "\n";
	}
}

void copy(unsigned char* array1, unsigned char* array2, int size) {
	for (int i = 0; i < size; i++) {
		array2[i] = array1[i];
	}
}

void initialize_aes_sbox(unsigned char* sbox) {
	unsigned char p = 1, q = 1;
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x11B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		unsigned char xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;
}

void AddRoundKey(unsigned char* state, unsigned char* word) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4*j] = word[i + 4*j] ^ state[i + 4*j];
		}
	}
}

void ShiftRows(unsigned char* state) {
	unsigned char state2[16];
	copy(state, state2, 16);
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i + 4 * j] = state[i + 4 * ((j+i)%4)];
		}
	}
	copy(state2, state, 16);
}

void gmix_column(unsigned char* r) {
    unsigned char a[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for (c = 0; c < 4; c++) {
        a[c] = r[c];
        // h is 0xff if the high bit of r[c] is set, 0 otherwise 
        h = (unsigned char)((signed char)r[c] >> 7); // arithmetic right shift, thus shifting in either zeros or ones 
        b[c] = r[c] << 1; // implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line 
        b[c] ^= 0x1B & h; // Rijndael's Galois field 
    }
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; // 2 * a0 + a3 + a2 + 3 * a1 
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; // 2 * a1 + a0 + a3 + 3 * a2 
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; // 2 * a2 + a1 + a0 + 3 * a3 
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; // 2 * a3 + a2 + a1 + 3 * a0 
}

void MixColumns(unsigned char* state) {
    for (int i = 0; i < 4; i++) {
        gmix_column(&state[4*i]);
    }
}

unsigned char calculate_sub(unsigned char s, unsigned char* sbox) {
	unsigned char hex_i, hex_j;
	hex_i = s & 0x0F;
	hex_j = (s >> 4) & 0x0F;
	return sbox[hex_i + 16 * hex_j];
}

void SubBytes(unsigned char* state, unsigned char* sbox) {
	unsigned char hex_i, hex_j;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = calculate_sub(state[i + 4 * j], sbox);
		}
	}
}

void SubWord(unsigned char* word, unsigned char* sbox) {
	unsigned char temp[4];
	for (int i = 0; i < 4; i++) {
		temp[i] = calculate_sub(word[i], sbox);
	}
	copy(temp, word, 4);
}

void RotWord(unsigned char* word) {
	unsigned char temp[4] = { word[1],word[2],word[3],word[0] };
	copy(temp, word, 4);
}

void KeyExpansion(unsigned char* key, unsigned char* w, unsigned char* sbox, int nk) {
	unsigned char temp[4];
	const unsigned char Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

	copy(key, w, 4*nk);
	int i = nk;

	while (i < 4 * (nk + 7)) {
		copy(&w[4*(i - 1)], temp, 4);
		if (i % nk == 0) {
			RotWord(temp);
			SubWord(temp,sbox);
			temp[0] = temp[0] ^ Rcon[(i / nk)-1];
		}
		else if (nk > 6 && i % nk == 4) {
			SubWord(temp, sbox);
		}
		for (int j = 0; j < 4; j++) {
			w[4 * i + j] = w[4 * (i - nk) + j] ^ temp[j];
		}
		i++;
	}
	//printHex(28+4*nk, w);
}

void AES_Cipher(unsigned char* input, unsigned char* output,  unsigned char* key, unsigned char* sbox, int nk) {
	unsigned char state[16];
	unsigned char w[240];
	
	KeyExpansion(key, w, sbox, nk);

	copy(input, state, 16);

	std::cout << "Start of input\n";
	printHex(4, state);
	std::cout << "Round key value\n";
	printHex(4, w);

	AddRoundKey(state, w);

	std::cout << "Start of round\n";
	printHex(4, state);

	//for (int round = 1; round < 2; round++) {
	for (int round = 1; round < (nk+6); round++) {
		SubBytes(state, sbox);
		std::cout << "After sub bytes\n";
		printHex(4, state);
		ShiftRows(state);
		std::cout << "After shift rows\n";
		printHex(4, state);
		MixColumns(state);
		std::cout << "After mix columns\n";
		printHex(4, state);
		std::cout << "Round key value\n";
		printHex(4, &w[round * 16]);
		AddRoundKey(state, &w[round*16]);
		std::cout << "Start of round\n";
		printHex(4, state);
	}

	SubBytes(state, sbox);
	ShiftRows(state);
	AddRoundKey(state, &w[(nk+6)*16]);

	copy(state, output, 16);
}

int main() {
	unsigned char sbox[256];
	unsigned char input[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	unsigned char output[16];
	int nk = 4;
	initialize_aes_sbox(sbox);
	std::cout << std::hex;
	AES_Cipher(input, output, key, sbox, nk);
	std::cout << "Output:\n";
	printHex(4, output);
}
