#include "mode.hpp"

namespace cryptology
{
    template <typename Encryption>
    class ECB : public ModeBase<Encryption>
    {
    public:
        ECB() : ModeBase<Encryption>()
        {
        }
        void encrypt(char *plain_text, const int &length, char *cipher_text)
        {
        }
        void decrypt(char *cipher_text, const int &length, char *plain_text)
        {
        }
        string encrypt(const string &plain_text)
        {

            // plain_text.c_str();
            return string();

        }
        string decrypt(const string &cipher_text)
        {
            return string();
        }
    };
}
