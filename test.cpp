#include <iostream>
#include "MiniAes.h"
#include <bitset>

using namespace std;

int main()
{

    cout << "Test1 P = 1001110001100011, K = 1100001111110000" << endl;
    uint16_t p = 0b1001110001100011;
    uint16_t key = 0b1100001111110000;
    MiniAes aes = MiniAes(key);
    aes.key_addition();
    nibbles4 res = aes.block_encrypt(aes.uint162nibbles4(p));
    cout << "Encrypted Result:" << endl;
    cout << bitset<4>(res[0][0]) << bitset<4>(res[1][0]) << bitset<4>(res[0][1]) << bitset<4>(res[1][1]) << endl;
    cout << endl;

    res = aes.block_decrypt(res);
    cout << "Decrypted Result:" << endl;
    cout << bitset<4>(res[0][0]) << bitset<4>(res[1][0]) << bitset<4>(res[0][1]) << bitset<4>(res[1][1]) << endl;
    cout << endl;

    cout << "Test2 P = 1111010001100011, K = 1010111000111011" << endl;
    uint16_t p1 = 0b1111010001100011;
    uint16_t key1 = 0b1010111000111011;
    aes = MiniAes(key1);
    aes.key_addition();
    res = aes.block_encrypt(aes.uint162nibbles4(p1));
    cout << "Encrypted Result:" << endl;
    cout << bitset<4>(res[0][0]) << bitset<4>(res[1][0]) << bitset<4>(res[0][1]) << bitset<4>(res[1][1]) << endl;
    cout << endl;

    res = aes.block_decrypt(res);
    cout << "Decrypted Result:" << endl;
    cout << bitset<4>(res[0][0]) << bitset<4>(res[1][0]) << bitset<4>(res[0][1]) << bitset<4>(res[1][1]) << endl;
}

