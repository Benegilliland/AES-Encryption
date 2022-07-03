#include "transformations.h"

byte GMul(byte a, byte b) { // Galois Field (2^8) Multiplication of two Bytes
	byte p = 0;

	for (int counter = 0; counter < 8; counter++) {
		if ((b & 1) != 0) {
			p ^= a;
		}

		_Bool hi_bit_set = (a & 0x80) != 0;
		a <<= 1;
		if (hi_bit_set) {
			a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}

	return p;
}

byte CalcSub(byte s, byte* sbox) {
	byte hex_i = s & 0x0F;
	byte hex_j = (s >> 4) & 0x0F;
	return sbox[hex_i + 16 * hex_j];
}

void SubWord(byte* word, byte* sbox) {
	byte temp[4];
	for (int i = 0; i < 4; i++) {
		temp[i] = CalcSub(word[i], sbox);
	}
	memcpy(word, temp, 4);
}

void RotWord(byte* word) {
	byte temp[4] = { word[1],word[2],word[3],word[0] };
	memcpy(word, temp, 4);
}

void AddRoundKey(byte* state, byte* word) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = word[i + 4 * j] ^ state[i + 4 * j];
		}
	}
}

void ShiftRows(byte* state) {
	byte state2[16];
	memcpy(state2, state, 16);
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i + 4 * j] = state[i + 4 * ((j + i) % 4)];
		}
	}
	memcpy(state, state2, 16);
}

void MixColumns(byte* state) {
	byte state2[16];
	for (int i = 0; i < 4; i++) {
		state2[4 * i] = GMul(0x02, state[4 * i]) ^ GMul(0x03, state[4 * i + 1]) ^ GMul(0x01, state[4 * i + 2]) ^ GMul(0x01, state[4 * i + 3]);
		state2[4 * i + 1] = GMul(0x01, state[4 * i]) ^ GMul(0x02, state[4 * i + 1]) ^ GMul(0x03, state[4 * i + 2]) ^ GMul(0x01, state[4 * i + 3]);
		state2[4 * i + 2] = GMul(0x01, state[4 * i]) ^ GMul(0x01, state[4 * i + 1]) ^ GMul(0x02, state[4 * i + 2]) ^ GMul(0x03, state[4 * i + 3]);
		state2[4 * i + 3] = GMul(0x03, state[4 * i]) ^ GMul(0x01, state[4 * i + 1]) ^ GMul(0x01, state[4 * i + 2]) ^ GMul(0x02, state[4 * i + 3]);
	}
	memcpy(state, state2, 16);
}

void SubBytes(byte* state, byte* sbox) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = CalcSub(state[i + 4 * j], sbox);
		}
	}
}

void InvShiftRows(byte* state) {
	byte state2[16];
	memcpy(state2, state, 16);
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i + 4 * j] = state[i + 4 * ((j + 3 * i) % 4)];
		}
	}
	memcpy(state, state2, 16);
}


void InvSubBytes(byte* state, byte* inv_sbox) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i + 4 * j] = CalcSub(state[i + 4 * j], inv_sbox);
		}
	}
}

void InvMixColumns(byte* state) {
	byte state2[16];
	for (int i = 0; i < 4; i++) {
		state2[4 * i] = GMul(0x0e, state[4 * i]) ^ GMul(0x0b, state[4 * i + 1]) ^ GMul(0x0d, state[4 * i + 2]) ^ GMul(0x09, state[4 * i + 3]);
		state2[4 * i + 1] = GMul(0x09, state[4 * i]) ^ GMul(0x0e, state[4 * i + 1]) ^ GMul(0x0b, state[4 * i + 2]) ^ GMul(0x0d, state[4 * i + 3]);
		state2[4 * i + 2] = GMul(0x0d, state[4 * i]) ^ GMul(0x09, state[4 * i + 1]) ^ GMul(0x0e, state[4 * i + 2]) ^ GMul(0x0b, state[4 * i + 3]);
		state2[4 * i + 3] = GMul(0x0b, state[4 * i]) ^ GMul(0x0d, state[4 * i + 1]) ^ GMul(0x09, state[4 * i + 2]) ^ GMul(0x0e, state[4 * i + 3]);
	}
	memcpy(state, state2, 16);
}

byte CalcInvSbox(byte s, byte* sbox) { // Reverse table lookup
	for (byte i = 0; i < 16; i++) {
		for (byte j = 0; j < 16; j++) {
			if (sbox[i + 16 * j] == s) {
				return ((j << 4) | i);
			}
		}
	}
	return 0x00;
}