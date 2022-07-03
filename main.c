#include "main.h"
#include "stdio.h"
#include "stdlib.h"

int main(int argc, char* argv[]) {
	byte input[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	byte key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	//byte NK = strtol(argv[2], NULL, 10);

	byte w[240];
	byte s_box[256];
	byte output[16];

	InitSbox(s_box);
	KeyExpansion(key, w, s_box);

	AESCipher(input, output, w, s_box);

	for (int i = 0; i < 16; i++) {
		printf("%x ", (char)output[i] & 0xFF);
	}

	return 0;
}

void InitSbox(byte* sbox) {
	byte p = 1, q = 1;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x11B : 0);

		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		byte xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63; // Calculate inverse transposition here too
	} while (p != 1);

	sbox[0] = 0x63;
}

void InitInvSbox(byte* sbox, byte* inv_sbox) {
	if (sbox[0] != 0x63) { // If sbox is not defined
		InitSbox(sbox);
	}
	for (int i = 0; i < 256; i++) {
		inv_sbox[i] = CalcInvSbox(i, sbox);
	}
}

void KeyExpansion(byte* key, byte* w, byte* sbox) {
	byte temp[4];
	const byte Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

	memcpy(w, key, 4 * NK);
	int i = NK;

	while (i < 4 * (NK + 7)) {
		memcpy(temp, &w[4 * (i - 1)], 4);
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

void AESCipher(byte* input, byte* output, byte* w, byte* sbox) {
	byte state[16];

	memcpy(state, input, 16);

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

	memcpy(output, state, 16);
}

void InvAESCipher(byte* input, byte* output, byte* w, byte* inv_sbox) {
	byte state[16];
	memcpy(state, input, 16);

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

	memcpy(output, state, 16);
}