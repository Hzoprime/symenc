#pragma once
#include "../headers.hpp"
#include "../algorithm/symalg.hpp"
namespace cryptology
{
    template <template <int, int> typename Encryption, int key_size, int block_size>
    class ModeBase
    {
        static_assert(is_base_of<EncryptionBase<key_size, block_size>, Encryption<key_size, block_size>>::value);

    protected:
        EncryptionBase<key_size, block_size> *e;

    public:
        ModeBase()
        {
            e = new Encryption<key_size, block_size>();
        }
        virtual ~ModeBase()
        {
            delete e;
        }
        virtual void encrypt(const string &plain_text, byte *cipher_text) = 0;
        virtual void decrypt(const string &cipher_text, byte* plain_text) = 0;
        virtual void encrypt(const byte *plain_text, const int &length, byte *cipher_text) = 0;
        virtual void decrypt(const byte *cipher_text, const int &length, byte *plain_text) = 0;
    };
}
