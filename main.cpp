#include "symenc/headers.hpp"
#include "symenc/algorithm/symalg.hpp"
#include "symenc/algorithm/aes.hpp"
#include "symenc/mode/ecb.hpp"
#include <map>
using cryptology::AES;
using cryptology::byte;
using cryptology::ECB;
using std::cin;
using std::cout;
using std::endl;
using std::map;
int to_value[256];
int to_exp[256];

#define CHECK(x, y) (to_value[(to_exp[(x)] + to_exp[(y)]) % 255] == (int)cryptology::gf256_##y[x])
#define MY_MUL(x, y) (to_value[(to_exp[(x)] + to_exp[(y)]) % 255])
#define WIKI_MUL(x, y) ((int)cryptology::gf256_##y[x])

class BytePtr
{
private:
    typedef byte *ptr;

public:
    byte *bytes;
    BytePtr()
    {
        bytes = new byte[100];
        cout << "constructor of byteptr" << endl;
    }
    BytePtr(const BytePtr &p) : bytes(new byte[100])
    {
        cout << "copy constructor of byteptr" << endl;
        memcpy(this->bytes, p.bytes, 100);
    }
    BytePtr(BytePtr &&p) : bytes(p.bytes)
    {
        p.bytes = nullptr;
        cout << "move constructor of byteptr" << endl;
    }
    ~BytePtr()
    {
        if (bytes != nullptr)
        {
            delete[] bytes;
        }
        else
        {
            cout << "nullptr" << endl;
        }

        cout << "destructor of byteptr" << endl;
    }
};

BytePtr a()
{
    BytePtr b;
    b.bytes[0] = '2';
    b.bytes[1] = '\0';
    return b;
}
BytePtr bbb(BytePtr bb)
{
    BytePtr c(bb);
    c.bytes[0] = '\0';
    return c;
}
void t()
{
    BytePtr p;
    BytePtr b = a();
    BytePtr c = bbb(b);
}
// -fno-elide-constructors
void oops()
{
    memset(to_value, -1, sizeof(to_value));
    to_value[0] = 1;
    memset(to_exp, -1, sizeof(to_value));
    to_exp[1] = 0;
    for (int i = 1; i < 255; i++)
    {
        to_value[i] = ((to_value[i - 1] << 1) ^ to_value[i - 1]);
        if (to_value[i] & 0x100)
        {
            to_value[i] ^= 0x11b;
        }
        if (to_exp[to_value[i]] != -1)
        {
            cout << i << ' ' << to_value[i] << ' ' << to_exp[to_value[i]] << endl;
        }
        else
        {
            to_exp[to_value[i]] = i;
        }
    }
    for (int i = 0; i < 256; i++)
    {
        cout << to_value[i] << ' ';
    }
    cout << endl;
    for (int i = 0; i < 256; i++)
    {
        cout << to_exp[i] << ' ';
    }
    cout << endl;
}
using std::string;
int main()
{
    t();
    return 0;
    ECB<AES, 256, 128> ee;
    byte key[16];
    for (int i = 0; i < 16; i++)
    {
        key[i] = rand() % 0x7f;
    }
    ee.set_key(key);
    byte block[1234];
    for (int i = 0; i < 1234; i++)
    {
        block[i] = rand() % 0x7f;
    }
    byte cipher[1234];
    ee.encrypt(block, 1234, cipher);
    byte plain_text[1264];
    ee.decrypt(cipher, 1264, plain_text);
    for (int i = 0; i < 1234; i++)
    {
        if (plain_text[i] != block[i])
        {
            cout << i << '\t' << (int)block[i] << '\t' << (int)plain_text[i] << endl;
        }
    }

    // byte cipher[16];
    // a.set_key(key);
    // cout << block << endl;
    // a.encrypt(block, cipher);
    // byte plain[16];
    // a.decrypt(cipher, plain);
    // cout << plain << endl;
    // cout << endl;
    // cout << endl;
    // cout << endl;
    // a.test(block, cipher);
    cout << "ri" << endl;
    return 0;
}
