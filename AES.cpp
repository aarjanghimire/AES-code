// AES.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cstring>
#include <stdio.h>
#include "AES.h"



/* Function: print_hex
 * -------------------
 * Takes 16 bytes and prints as hex code.
 *
 * msg: bytes to be printed
 */
void PrintHex(char * msg) {
  for (int i = 0; i < 16; i++)
    printf("%02X ", (unsigned char) *(msg+i));
  putchar('\n');
}

int main()
{
    unsigned char message[] = "";

    unsigned char key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 32};

    //unsigned char key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    int round = 13;

    int originalLen = strlen((const char*)message);
    int lenofPaddedMessage = originalLen;

    if (lenofPaddedMessage % 16 != 0)
    {
        lenofPaddedMessage = (lenofPaddedMessage / 16 + 1) * 16;
    }
    
    unsigned char* paddedMessage = RightPad(message, 16);
    
    
    char* EncMessage;

    unsigned char expandedKey[240];
    KeyExpansion(key, expandedKey, round);
        
    
    std::cout << "\nActual Message\n";
    std::cout<<paddedMessage;

        std::cout << "\nEncrypted Message\n";

    for (int i = 0; i < lenofPaddedMessage; i+=16)
    {
      EncMessage=Encrypt(paddedMessage+i, expandedKey, round);
      PrintHex(EncMessage);
      std::cout<<Decrypt((unsigned char*)EncMessage, expandedKey, round)<<"\n";
    }


    delete[] paddedMessage;
    return 0;
}
