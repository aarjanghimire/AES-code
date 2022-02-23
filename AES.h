#ifndef AES_H
#define AES_H

#include "lookuptable.h"
#include <stdlib.h>
#include <string.h>

//in: bytes to be rotated
//* i: RCon index to multiply by
void KeyExpansionCore(unsigned char* in, unsigned char i){

    //unsigned char t = in[0]
    //in[0] = in [1];
    //in[1] = in [2];
    //in[2] = in [3];
    //in[3] = t;
    unsigned int* q = (unsigned int*) in;
    //rotating left but operation is rotate right as integer are stored such way
    *q = (*q >> 8) | ((*q & 0xff) << 24);

    //s-box four bytes:
    in[0] = sbox[in[0]];
    in[1] = sbox[in[2]];
    in[2] = sbox[in[2]];
    in[3] = sbox[in[3]];

    //roundConstant using galoas field
    in[0] ^= rcon[i];
};


//inputkey[32] expandedKey[240] 
void KeyExpansion(unsigned char* inputKey, unsigned char* expandedKeys, int round)
{
    int byteGen = 176;
    int keyLen = 16;
    
    if (round = 13)
    {
        int byteGen = 256;
        int keyLen = 32;
    }
    
    //first 32 bytes
    for (int i = 0; i < keyLen; i++)
    {
        expandedKeys[i] = inputKey[i];
    }
    int bytesGenereated = keyLen; //we have generated 32 bytes so far
    int rconIteration = 1;
    unsigned char temp[4];

    while (bytesGenereated < byteGen)
    {
        for (int i = 0; i < 4; i++)
        {
            temp[i] = expandedKeys[i + bytesGenereated -4];
        }
        if (bytesGenereated %16 == 0)
        {
            KeyExpansionCore(temp, rconIteration);
            rconIteration++;
        }

        //add xor
        for (unsigned char a = 0; a < 4; a++)
        {
            expandedKeys[bytesGenereated] = expandedKeys[bytesGenereated - 16] ^ temp[a];
            bytesGenereated++;
        }   
    }
};

//looks in the substitution table
//state: bytes to be substuted
void SubstituteByte(unsigned char* state) 
{
    // Substitute each state value with another byte in the Rijndael S-Box
    for (int i = 0; i < 16; i++)
    {
        state[i] = sbox[state[i]];
    }
};

//looks in the substitution table
//state: bytes to be substuted
void InvSubstitutingBytes(unsigned char* state) 
{
  // Substitute each state value with another byte in the Rijndael inverse-S-Box
  for (int i = 0; i < 16; i++) 
  {
    state[i] = isbox[state[i]];
  }
};


/*
before shift :
    0   4   8   12
    1   5   9   13
    2   6   10  14
    3   7   11  15

after shift :
    0   4   8   12
    5   9   13  1
    10  14  2   6
    15  3   7   11
*/

//state: 4*4 matrix where rows are shifted as mentioned in above comment
void ShiftRows(unsigned char* state) 
{
    unsigned char temp[16];

    // First row don't shift
    temp[0] = state[0];
    temp[4] = state[4];
    temp[8] = state[8];
    temp[12] = state[12];

    // Second row shift right once
    temp[1] = state[5];
    temp[5] = state[9];
    temp[9] = state[13];
    temp[13] = state[1];

    // Third row shift right twice
    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];

    // Fourth row shift right three times
    temp[3] = state[15];
    temp[7] = state[3];
    temp[11] = state[7];
    temp[15] = state[11];


    for (int i = 0; i < 16; i++)
    {
        state[i] = temp[i];
    }
};

//state: 4*4 matrix where rows are inversely shifted as mentioned in above comment
void InverseShiftRows(unsigned char* state) {
    unsigned char temp[16];

    // First row don't shift (idx = idx)
    temp[0] = state[0];
    temp[4] = state[4];
    temp[8] = state[8];
    temp[12] = state[12];
    
    // Second row shift right once (idx = (idx - 4) % 16)
    temp[1] = state[13];
    temp[5] = state[1];
    temp[9] = state[5];
    temp[13] = state[9];

    // Third row shift right twice (idx = (idx +/- 8) % 16)
    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];

    // Fourth row shift right three times (idx = (idx + 4) % 16)
    temp[3] = state[7];
    temp[7] = state[11];
    temp[11] = state[15];
    temp[15] = state[3];


    for (int i = 0; i < 16; i++){
        state[i] = temp[i];
    };
}


/*
    consistes of
    1. Dot Product (2 Galois fields)
    2. matrix Multiplication
*/

//state: 16 byte array to transform
void MixColumns(unsigned char *state) 
{
    unsigned char temp[16];
    
    temp[0] = (unsigned char)(mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
    temp[1] = (unsigned char)(state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
    temp[2] = (unsigned char)(state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
    temp[3] = (unsigned char)(mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

    temp[4] = (unsigned char)(mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
    temp[5] = (unsigned char)(state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
    temp[6] = (unsigned char)(state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
    temp[7] = (unsigned char)(mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

    temp[8] = (unsigned char)(mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
    temp[9] = (unsigned char)(state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
    temp[10] = (unsigned char)(state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
    temp[11] = (unsigned char)(mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

    temp[12] = (unsigned char)(mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
    temp[13] = (unsigned char)(state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
    temp[14] = (unsigned char)(state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
    temp[15] = (unsigned char)(mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

    for (int i = 0; i < 16; i++)
    {
        state[i] = temp[i];
    }
};

//state: 16 byte array to transform
void InverseMixColumns(unsigned char* state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char) (mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]]);
    tmp[1] = (unsigned char) (mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]]);
    tmp[2] = (unsigned char) (mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]]);
    tmp[3] = (unsigned char) (mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]]);

    tmp[4] = (unsigned char) (mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]]);
    tmp[5] = (unsigned char) (mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]]);
    tmp[6] = (unsigned char) (mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]]);
    tmp[7] = (unsigned char) (mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]]);

    tmp[8] = (unsigned char) (mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]]);
    tmp[9] = (unsigned char) (mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]]);
    tmp[10] = (unsigned char) (mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]]);
    tmp[11] = (unsigned char) (mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]]);

    tmp[12] = (unsigned char) (mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]]);
    tmp[13] = (unsigned char) (mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]]);
    tmp[14] = (unsigned char) (mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]]);
    tmp[15] = (unsigned char) (mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]]);

    for (int i = 0; i < 16; i++){
        state[i] = tmp[i];
    }
}


//derived from Galois fields (also called as finite field) 
//and in binary addition without carry turns out to be bitwise XOR

// roundKey: 16 unsigned char byte array to XOR against
void AddRoundKey(unsigned char* state, unsigned char* roundKey) {
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
};

/*  Encrypts message using 13 round ECB AES-256 encryption and given expanded key.

    Encryption Process:
        First Round:
            --------------------
            Add Round Key [First 16 Bytes]
            --------------------

        Next 13 Rounds:
            --------------------------------
            Sub Bytes with S-Box
            Left Shift Rows
            Mix Columns
            Add Round Key [16 * (Round + 1)]
            --------------------------------

        Final Round:
            --------------------------------
            Sub Bytes with S-Box
            Left Shift Rows
            Add Round Key [Last 16 Bytes]
            --------------------------------

    The final round does not call the mix columns function. This is
    so the encryption and decryption scheme is symetric.

    message: 16 byte message to encrypt
    expandedKey: 240 byte expanded key for cipher
*/
char * Encrypt(unsigned char* message, unsigned char* expandedKey, int rounds)
{
    unsigned char state[16];
    for (int i = 0; i < 16; i++)
    {
        state[i] = message[i];
    }

    AddRoundKey(state, expandedKey);

    for (int i = 0; i < rounds; i++)
    {
        SubstituteByte(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + (16 * (i + 1)));
    }
    //final round
    SubstituteByte(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + ((rounds + 1)*16));

    char * EncryptedMessage  = (char *) malloc(16);
    memcpy(EncryptedMessage, state, 16);
    return EncryptedMessage;
}


/*  Decrypts message using 13 round ECB AES-256 encryption and given expanded key.

    Decryption Process:
        First Round:
            --------------------
            Add Round Key [Last 16 Bytes]
            --------------------

        Next 13 Rounds:
            --------------------------------
            Right Shift Rows
            Sub Bytes with Inverse S-Box
            Add Round Key [16 * (13 - Round)]
            Inverse Mix Columns
            --------------------------------

        Final Round:
            --------------------------------
            Right Shift Rows
            Sub Bytes with Inverse S-Box
            Add Round Key [First 16 Bytes]
            --------------------------------

    message: 16 byte message to decrypt
    expandedKey: 240 byte expanded key for cipher
*/
char * Decrypt(unsigned char* message, unsigned char* expandedKey, int rounds) 
{
    unsigned char state[16];
     // Take only the first 16 characters of the message
    for (int i = 0; i < 16; i++){
        state[i] = message[i];
    }

    AddRoundKey(state, expandedKey + ((rounds + 1)*16));

    for (int i = rounds; i > 0; i--) {
       InverseShiftRows(state);
       InvSubstitutingBytes(state);
       AddRoundKey(state, expandedKey + (16 * i));
       InverseMixColumns(state);
    }

    //final round
    InverseShiftRows(state);
    InvSubstitutingBytes(state);
    AddRoundKey(state, expandedKey);

    char * DecryptedMessage = (char *) malloc(16);
    memcpy(DecryptedMessage, state, 16);
    return DecryptedMessage;
}


unsigned char * RightPad(unsigned char * str, unsigned int pad_len) 
{

    const unsigned int str_len = strlen((const char*) str);
    unsigned int padded_str_len = str_len;

    if (padded_str_len % pad_len != 0){
        padded_str_len = (padded_str_len / pad_len + 1) * pad_len;
    }
    
    unsigned char * padded_str = new unsigned char[padded_str_len];
    for (int i = 0; i < padded_str_len; i++) {
        if (i >= str_len) padded_str[i] = 0;
        else padded_str[i] = str[i];
    }
    return padded_str;
}


#endif