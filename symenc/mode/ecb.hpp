#include "mode.hpp"

namespace cryptology
{
    template <template <int, int> typename Encryption, int key_size, int block_size>
    class ECB : public ModeBase<Encryption, key_size, block_size>
    {
        typedef ModeBase<Encryption, key_size, block_size> _base;

    public:
        ECB() : ModeBase<Encryption, key_size, block_size>()
        {
        }
        ~ECB()
        {
        }
        void set_key(const byte key[Encryption<key_size, block_size>::get_key_bytes()])
        {
            _base::e->set_key(key);
        }
        void encrypt(const byte *plain_text, const int &length, byte *cipher_text)
        {
            const int n_bytes_of_block = _base::e->get_block_bytes();
            int n_of_block = length / n_bytes_of_block;
            for (int i = 0; i < n_of_block; i++)
            {
                _base::e->encrypt(plain_text + n_bytes_of_block * i, cipher_text + n_bytes_of_block * i);
            }
            byte last_block[16];
            memset(last_block, 0, n_bytes_of_block);
            memcpy(last_block, plain_text + n_bytes_of_block * n_of_block, length - n_bytes_of_block * n_of_block);
            _base::e->encrypt(last_block, cipher_text + n_bytes_of_block * n_of_block);
        }
        void decrypt(const byte *cipher_text, const int &length, byte *plain_text)
        {
            const int n_bytes_of_block = _base::e->get_block_bytes();
            int n_of_block = length / n_bytes_of_block;
            for (int i = 0; i < n_of_block; i++)
            {
                _base::e->decrypt(cipher_text + n_bytes_of_block * i, plain_text + n_bytes_of_block * i);
            }
            byte last_block[16];
            memset(last_block, 0, n_bytes_of_block);
            memcpy(last_block, cipher_text + n_bytes_of_block * n_of_block, length - n_bytes_of_block * n_of_block);
            _base::e->decrypt(last_block, plain_text + n_bytes_of_block * n_of_block);
        }
        void encrypt(const string &plain_text, byte *cipher_text)
        {
            const byte *text_ptr = (const byte *)plain_text.c_str();
            int n_bytes_of_text = plain_text.size();
            encrypt(text_ptr, n_bytes_of_text, cipher_text);
        }
        void decrypt(const string &cipher_text, byte *plain_text)
        {
            const byte *text_ptr = (const byte *)cipher_text.c_str();
            int n_bytes_of_text = cipher_text.size();
            decrypt(text_ptr, n_bytes_of_text, plain_text);
        }
    };
}
