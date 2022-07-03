#include "aes_encryption.h"

int main(int argc, char** argv) {
	const byte* key = "lkjhgriwptkfnbv";
	byte w[240];
	byte sbox[256];

	InitSbox(sbox);
	KeyExpansion(key, w, sbox);

	Benchmark(62500000 * 16, w, sbox);

	return 0;
}