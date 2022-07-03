#pragma once
#include "transformations.h"

void InitSbox(byte* sbox);
void InitInvSbox(byte* sbox, byte* inv_sbox);
void KeyExpansion(byte* key, byte* w, byte* sbox);
void AESCipher(byte* input, byte* output, byte* w, byte* sbox);
void InvAESCipher(byte* input, byte* output, byte* w, byte* sbox);