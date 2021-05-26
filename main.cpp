#include <iostream>
#include "symenc/algorithm/symalg.hpp"
#include "symenc/algorithm/aes.hpp"
#include "symenc/mode/ecb.hpp"
using cryptology::AES;
using cryptology::byte;
using cryptology::ECB;
using std::cin;
using std::cout;
using std::endl;
#include <map>
using std::map;
int to_value[256];
int to_exp[256];

#define CHECK(x, y) (to_value[(to_exp[(x)] + to_exp[(y)]) % 255] == (int)cryptology::gf256_##y[x])
#define MY_MUL(x, y) (to_value[(to_exp[(x)] + to_exp[(y)]) % 255])
#define WIKI_MUL(x, y) ((int)cryptology::gf256_##y[x])

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

int main()
{
    // std::is_base_of<cryptology::EncryptionBase, cryptology::AES>::value;


    cryptology::EncryptionBase<256, 128> *e;
    e = new AES<256>();


    ECB<AES<256>> ee;
    // oops();
    // for (int i = 0; i < 256; i++)
    // {
    //     cout << i << endl;
    //     assert(CHECK(i, 2));
    //     assert(CHECK(i, 3));
    //     assert(CHECK(i, 9));
    //     assert(CHECK(i, 11));
    //     assert(CHECK(i, 13));
    //     assert(CHECK(i, 14));
    // }

    // AES<256> a;
    // byte key[16];
    // for (int i = 0; i < 16; i++)
    // {
    //     key[i] = rand() % 0x7f;
    // }
    // byte block[16];
    // for (int i = 0; i < 16; i++)
    // {
    //     block[i] = rand() % 0x7f;
    // }
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
}
