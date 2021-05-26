#pragma once
#include "../headers.hpp"

namespace cryptology
{
    template <int key_size, int block_size>
    class EncryptionBase
    {
    protected:
        const static int n_byte_in_key = key_size / BYTE_SIZE;
        const static int n_byte_in_block = block_size / BYTE_SIZE;
    public:
        EncryptionBase()
        {
            cout << "constructor of EncryptionBase<" << key_size << "," << block_size << ">" << endl;
        }

        virtual ~EncryptionBase()
        {
            cout << "destructor of EncryptionBase<" << key_size << "," << block_size << ">" << endl;
        }
        virtual void encrypt(byte plain_text[n_byte_in_block], byte cipher_text[n_byte_in_block]) = 0;
        virtual void decrypt(byte cipher_text[n_byte_in_block], byte plain_text[n_byte_in_block]) = 0;
        constexpr static int get_key_length()
        {
            return key_size;
        }
        constexpr static int get_block_length()
        {
            return block_size;
        }
    };
} // namespace cryptology
