#include "MiniAes.h"
#include <bitset>

std::unordered_map<uint8_t, uint8_t> MiniAes::s_box = {
    {0b0000, 0b1110}, {0b1000, 0b0011},
    {0b0001, 0b0100}, {0b1001, 0b1010},
    {0b0010, 0b1101}, {0b1010, 0b0110},
    {0b0011, 0b0001}, {0b1011, 0b1100},
    {0b0100, 0b0010}, {0b1100, 0b0101},
    {0b0101, 0b1111}, {0b1101, 0b1001},
    {0b0110, 0b1011}, {0b1110, 0b0000},
    {0b0111, 0b1000}, {0b1111, 0b0111}
}; ///<  a 4 ¡Á 4 substitution table (S-box)

std::unordered_map<uint8_t, uint8_t> MiniAes::inverse_s_box = {
    {0b0000, 0b1110}, {0b1000, 0b0111},
    {0b0001, 0b0011}, {0b1001, 0b1101},
    {0b0010, 0b0100}, {0b1010, 0b1001},
    {0b0011, 0b1000}, {0b1011, 0b0110},
    {0b0100, 0b0001}, {0b1100, 0b1011},
    {0b0101, 0b1100}, {0b1101, 0b0010},
    {0b0110, 0b1010}, {0b1110, 0b0000},
    {0b0111, 0b1111}, {0b1111, 0b0101}
};///<  a 4 ¡Á 4 substitution table (inverse_s_box to decrypt) 

uint8_t MiniAes::rcon1 = 0b0001;
uint8_t MiniAes::rcon2 = 0b0010;

MiniAes::MiniAes() {
    key_ = 0b1100001111110000; 
}

/**
* @brief Addition in GF(2^4)
* 
*/
niblle MiniAes::addition(niblle a, niblle b){
    return a ^ b;
}

niblle MiniAes::multiplication(niblle a, niblle b){
    uint8_t p = 0;
    for (int i = 0; i < 4; i++) {
        p ^= -(b & 1) & a;
        auto mask = -((a >> 3) & 1);
        // 0b10011 is x^4 + x + 1
        a = (a << 1) ^ (0b10011 & mask);
        b >>= 1;
    }

    return p;
}

nibbles4 MiniAes::nibble_sub(nibbles4 p, bool flag) {
    auto box = flag ? s_box : inverse_s_box;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            p[i][j] = box[p[i][j]];
        }
    }
    return p;
}

nibbles4 MiniAes::shift_row(nibbles4 p) {
    uint8_t temp;
    temp = p[1][0];
    p[1][0] = p[1][1];
    p[1][1] = temp;
    return p;
}

nibbles4 MiniAes::mix_column(nibbles4 p) {
    nibbles4 mixed;
    mixed[0][0] = addition(multiplication(p[0][0], 0b0011), multiplication(p[1][0], 0b0010));
    mixed[1][0] = addition(multiplication(p[0][0], 0b0010), multiplication(p[1][0], 0b0011));
    mixed[0][1] = addition(multiplication(p[0][1], 0b0011), multiplication(p[1][1], 0b0010));
    mixed[1][1] = addition(multiplication(p[0][1], 0b0010), multiplication(p[1][1], 0b0011));
    return mixed;
}

nibbles4 MiniAes::uint162nibbles4(uint16_t value) {
    nibbles4 res;
    res[0][0] = (value & 0b1111000000000000) >> 12;
    res[1][0] = (value & 0b0000111100000000) >> 8;
    res[0][1] = (value & 0b0000000011110000) >> 4;
    res[1][1] = value & 0b0000000000001111;
    
    return res;
}

void MiniAes::key_addition() {
    nibbles4 key, key1, key2;
    key = uint162nibbles4(key_);
    key_list_.push_back(key); // k0 - k3

    //add k4 - k7
    key1[0][0] = key[0][0] ^ s_box[key[1][1]] ^ rcon1; // k4
    key1[1][0] = key1[0][0] ^ key[1][0]; //k5 = k4 ^ k1
    key1[0][1] = key1[1][0] ^ key[0][1]; //k6 = k5 ^ k2
    key1[1][1] = key1[0][1] ^ key[1][1]; //k7 = k6 ^ k3
    key_list_.push_back(key1);

    //add k8 - k11
    key2[0][0] = key1[0][0] ^ s_box[key1[1][1]] ^ rcon2; // k8
    key2[1][0] = key2[0][0] ^ key1[1][0]; //k9 = k8 ^ k5
    key2[0][1] = key2[1][0] ^ key1[0][1]; //k10 = k9 ^ k6
    key2[1][1] = key2[0][1] ^ key1[1][1]; //k7 = k3 ^ k6
    key_list_.push_back(key2);
}

/**
* 
*/
nibbles4  MiniAes::block_ROX(nibbles4 a, nibbles4 b) {
    nibbles4 res;
    for (int i = 0; i < a.size(); i++) {
        for (int j = 0; j < a.size(); j++) {
            res[i][j] = a[i][j] ^ b[i][j];
        }
    }
    return res;
}

nibbles4 MiniAes::block_encrypt(nibbles4 p) {
    nibbles4 res;
    res = block_ROX(p, key_list_[0]);
    //round 1
    res = nibble_sub(res, true);
    res = shift_row(res);
    res = mix_column(res);
    res = block_ROX(res, key_list_[1]);

    //round 2
    res = nibble_sub(res, true);
    res = shift_row(res);
    res = block_ROX(res, key_list_[2]);
    return res;
}


nibbles4 MiniAes::block_decrypt(nibbles4 c) {
    nibbles4 res;
 
    res = block_ROX(c, key_list_[2]);
    //round 1
    res = shift_row(res);
    res = nibble_sub(res, false);
    res = block_ROX(res, key_list_[1]);

    //round 2
    res = mix_column(res);
    res = shift_row(res);
    res = nibble_sub(res, false);
    res = block_ROX(res, key_list_[0]);
    return res;
}