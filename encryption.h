#pragma once
#define NK 8 // Must be set to 4, 6 or 8

#define uchar unsigned char
#define ROTL8(x,shift) ((uchar) ((x) << (shift)) | ((x) >> (8 - (shift))))

void InitSbox(uchar* sbox);
void InitInvSbox(uchar* sbox, uchar* inv_sbox);
void KeyExpansion(uchar* key, uchar* w, uchar* sbox);
void AESCipher(uchar* input, uchar* output, uchar* w, uchar* sbox);
void InvAESCipher(uchar* input, uchar* output, uchar* w, uchar* sbox);