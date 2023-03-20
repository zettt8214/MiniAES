#pragma once
#include <iostream>
#include <string>
#include <unordered_map>
#include <array>
#include <vector>

typedef std::array<std::array<uint8_t, 2>, 2> nibbles4; ///< a matrix with 4 nibbles
typedef uint8_t niblle;	///< a nibble

/**
* @brief Mini Aes algorithm
*/
class MiniAes
{
private:
	
	
	static std::unordered_map<uint8_t, uint8_t> s_box;
	static std::unordered_map<uint8_t, uint8_t> inverse_s_box;
	static uint8_t rcon1;
	static uint8_t rcon2;
	uint16_t key_;
	std::vector<nibbles4> key_list_;
	nibbles4 block_ROX(nibbles4, nibbles4);
	niblle addition(niblle, niblle);
	niblle multiplication(niblle, niblle);
	nibbles4 nibble_sub(nibbles4, bool);
	nibbles4 shift_row(nibbles4);
	nibbles4 mix_column(nibbles4);

public:
	MiniAes();
	MiniAes(uint16_t key) { key_ = key; };
	nibbles4 block_encrypt(nibbles4);
	nibbles4 block_decrypt(nibbles4);
	void key_addition();
	nibbles4 uint162nibbles4(uint16_t);
};

