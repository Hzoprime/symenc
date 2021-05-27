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
        virtual void set_key(const byte key[n_byte_in_key]) = 0;

        virtual void encrypt(const byte plain_text[n_byte_in_block], byte cipher_text[n_byte_in_block]) = 0;
        virtual void decrypt(const byte cipher_text[n_byte_in_block], byte plain_text[n_byte_in_block]) = 0;
        constexpr static int get_key_bytes()
        {
            return n_byte_in_key;
        }
        constexpr static int get_block_bytes()
        {
            return n_byte_in_block;
        }
    };
} // namespace cryptology
