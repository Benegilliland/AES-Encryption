#define NK 4 // Must be set to 4, 6 or 8

#define byte unsigned char
#define ROTL8(x,shift) ((byte) ((x) << (shift)) | ((x) >> (8 - (shift))))

byte GMul(byte a, byte b);
byte CalcSub(byte s, byte* sbox);
void SubWord(byte* word, byte* sbox);
void RotWord(byte* word);
void AddRoundKey(byte* state, byte* word);
void ShiftRows(byte* state);
void MixColumns(byte* state);
void SubBytes(byte* state, byte* sbox);
void InvShiftRows(byte* state);
void InvSubBytes(byte* state, byte* inv_sbox);
void InvMixColumns(byte* state);
byte CalcInvSbox(byte s, byte* sbox);