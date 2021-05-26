#pragma once
#include "../headers.hpp"
#include "../algorithm/symalg.hpp"
namespace cryptology
{
    template <typename Encryption>
    class ModeBase
    {
    private:
        EncryptionBase<Encryption::get_key_length(), Encryption::get_block_length()> *e;
    public:
        ModeBase()
        {
            e = new Encryption();
        }
        virtual ~ModeBase() {}
        virtual string encrypt(const string &plain_text) = 0;
        virtual string decrypt(const string &cipher_text) = 0;

        virtual void encrypt(char *plain_text, const int &length, char *cipher_text) = 0;
        virtual void decrypt(char *cipher_text, const int &length, char *plain_text) = 0;
    };
}
