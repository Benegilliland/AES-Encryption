#include "encryption.h"

void copy(uchar* array1, uchar* array2, int size) {
	for (int i = 0; i < size; i++) {
		array2[i] = array1[i];
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

void InitSbox(uchar* sbox) {
	uchar p = 1, q = 1;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x11B : 0);

		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		uchar xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63; // Calculate inverse transposition here too
	} while (p != 1);

	sbox[0] = 0x63;
}

uchar CalcInvSbox(uchar s, uchar* sbox) { // Reverse table lookup
	for (uchar i = 0; i < 16; i++) {
		for (uchar j = 0; j < 16; j++) {
			if (sbox[i + 16 * j] == s) {
				return ((j << 4) | i);
			}
		}
	}
	return 0x00;
}

void InitInvSbox(uchar* sbox, uchar* inv_sbox) {
	if (sbox[0] != 0x63) { // If sbox is not defined
		InitSbox(sbox);
	}
	for (int i = 0; i < 256; i++) {
		inv_sbox[i] = CalcInvSbox(i, sbox);
	}
}

uchar CalcSub(uchar s, uchar* sbox) {
	uchar hex_i = s & 0x0F;
	uchar hex_j = (s >> 4) & 0x0F;
	return sbox[hex_i + 16 * hex_j];
}

void SubWord(uchar* word, uchar* sbox) {
	uchar temp[4];
	for (int i = 0; i < 4; i++) {
		temp[i] = CalcSub(word[i], sbox);
	}
	copy(temp, word, 4);
}

void RotWord(uchar* word) {
	uchar temp[4] = { word[1],word[2],word[3],word[0] };
	copy(temp, word, 4);
}

void KeyExpansion(uchar* key, uchar* w, uchar* sbox) {
	uchar temp[4];
	const uchar Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

	copy(key, w, 4 * NK);
	int i = NK;

	while (i < 4 * (NK + 7)) {
		copy(&w[4 * (i - 1)], temp, 4);
		if (i % NK == 0) {
			RotWord(temp);
			SubWord(temp, sbox);
			temp[0] = temp[0] ^ Rcon[(i / NK) - 1];
		}
		else if (NK > 6 && i % NK == 4) {
			SubWord(temp, sbox);
		}
		for (int j = 0; j < 4; j++) {
			w[4 * i + j] = w[4 * (i - NK) + j] ^ temp[j];
		}
		i++;
	}
}

void AddRoundKey(uchar* state, uchar* word) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = word[i + 4 * j] ^ state[i + 4 * j];
		}
	}
}

void ShiftRows(uchar* state) {
	uchar state2[16];
	copy(state, state2, 16);
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i + 4 * j] = state[i + 4 * ((j + i) % 4)];
		}
	}
	copy(state2, state, 16);
}

void MixColumns(uchar* state) {
	uchar state2[16];
	for (int i = 0; i < 4; i++) {
		state2[4 * i] = GMul(0x02, state[4 * i]) ^ GMul(0x03, state[4 * i + 1]) ^ GMul(0x01, state[4 * i + 2]) ^ GMul(0x01, state[4 * i + 3]);
		state2[4 * i + 1] = GMul(0x01, state[4 * i]) ^ GMul(0x02, state[4 * i + 1]) ^ GMul(0x03, state[4 * i + 2]) ^ GMul(0x01, state[4 * i + 3]);
		state2[4 * i + 2] = GMul(0x01, state[4 * i]) ^ GMul(0x01, state[4 * i + 1]) ^ GMul(0x02, state[4 * i + 2]) ^ GMul(0x03, state[4 * i + 3]);
		state2[4 * i + 3] = GMul(0x03, state[4 * i]) ^ GMul(0x01, state[4 * i + 1]) ^ GMul(0x01, state[4 * i + 2]) ^ GMul(0x02, state[4 * i + 3]);
	}
	copy(state2, state, 16);
}

void SubBytes(uchar* state, uchar* sbox) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = CalcSub(state[i + 4 * j], sbox);
		}
	}
}

void AESCipher(uchar* input, uchar* output, uchar* w, uchar* sbox) {
	uchar state[16];

	copy(input, state, 16);

	AddRoundKey(state, w);

	for (int round = 1; round < (NK + 6); round++) {
		SubBytes(state, sbox);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, &w[round * 16]);
	}

	SubBytes(state, sbox);
	ShiftRows(state);
	AddRoundKey(state, &w[(NK + 6) * 16]);

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

void InvSubBytes(uchar* state, uchar* inv_sbox) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = CalcSub(state[i + 4 * j], inv_sbox);
		}
	}
}

void InvMixColumns(uchar* state) {
	uchar state2[16];
	for (int i = 0; i < 4; i++) {
		state2[4 * i] = GMul(0x0e, state[4 * i]) ^ GMul(0x0b, state[4 * i + 1]) ^ GMul(0x0d, state[4 * i + 2]) ^ GMul(0x09, state[4 * i + 3]);
		state2[4 * i + 1] = GMul(0x09, state[4 * i]) ^ GMul(0x0e, state[4 * i + 1]) ^ GMul(0x0b, state[4 * i + 2]) ^ GMul(0x0d, state[4 * i + 3]);
		state2[4 * i + 2] = GMul(0x0d, state[4 * i]) ^ GMul(0x09, state[4 * i + 1]) ^ GMul(0x0e, state[4 * i + 2]) ^ GMul(0x0b, state[4 * i + 3]);
		state2[4 * i + 3] = GMul(0x0b, state[4 * i]) ^ GMul(0x0d, state[4 * i + 1]) ^ GMul(0x09, state[4 * i + 2]) ^ GMul(0x0e, state[4 * i + 3]);
	}
	copy(state2, state, 16);
}

void InvAESCipher(uchar* input, uchar* output, uchar* w, uchar* inv_sbox) {
	uchar state[16];
	copy(input, state, 16);

	AddRoundKey(state, &w[(NK + 6) * 16]);

	for (int round = NK + 5; round > 0; round--) {
		InvShiftRows(state);
		InvSubBytes(state, inv_sbox);
		AddRoundKey(state, &w[round * 16]);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state, inv_sbox);
	AddRoundKey(state, w);

	copy(state, output, 16);
}