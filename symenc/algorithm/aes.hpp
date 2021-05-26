#pragma once
#include "../headers.hpp"
#include "symalg.hpp"

namespace cryptology
{
    template <int key_size, int block_size = 128>
    class AES : public EncryptionBase<key_size, block_size>
    {
        static_assert(block_size == 128);

    private:
        const static int n_byte_in_key = EncryptionBase<key_size, 128>::n_byte_in_key;
        const static int n_byte_in_block = EncryptionBase<key_size, 128>::n_byte_in_block;
        const static int round;
        byte expanded_key[round + 1][16];
        byte state[4][4];
        constexpr static byte rcon_number[10][4] = {{0x01}, {0x02}, {0x04}, {0x08}, {0x10}, {0x20}, {0x40}, {0x80}, {0x1B}, {0x36}};
        constexpr static byte sbox[16][16] = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};
        constexpr static byte in_sbox[16][16] = {
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
            {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
            {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
            {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
            {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
            {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
            {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
            {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
            {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
            {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
            {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
            {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
            {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
            {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};

        void expand_key(byte origin_key[n_byte_in_key])
        {
            int i = 0; // count of byte number;
            for (i = 0; i < n_byte_in_key; i++)
            {
                expanded_key[i / 16][i % 16] = origin_key[i];
            }
            while (i < (round + 1) * 16)
            {
                byte temp[4];
                for (int j = 0; j < 4; j++)
                {
                    temp[j] = expanded_key[(i - 4 + j) / 16][(i - 4 + j) % 16];
                }

                if ((i % n_byte_in_key) == 0)
                {
                    rot_word(temp, 1);
                    sub_word(temp);
                    for (int j = 0; j < 4; j++)
                    {
                        temp[j] ^= rcon_number[i / n_byte_in_key][j];
                    }
                }

                else if ((n_byte_in_key / 4 > 6) && (((i / 4)) % (n_byte_in_key / 4) == 4))
                {
                    sub_word(temp);
                }

                for (int j = 0; j < 4; j++)
                {
                    expanded_key[(i + j) / 16][(i - j) % 16] = temp[j] ^ expanded_key[(i + j) / 16 - 1][(i - j) % 16];
                }
                i += 4;
            }
        }

        void mix_column(const int &column_index)
        {
            byte a[4];
            byte b[4];
            /*
        * impl from wikipedia
        * The array 'a' is simply a copy of the input array 'r'
        * The array 'b' is each element of the array 'a' multiplied by 2 in Rijndael's Galois field
        * The array 'c' is each element of the array 'a' multiplied by 3 in Rijndael's Galois field
        * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field
        *
        */

            for (int i = 0; i < 4; i++)
            {
                a[i] = state[i][column_index];
                b[i] = gf256_2[a[i]];
            }
            for (int i = 0; i < 4; i++)
            {
                state[i][column_index] = b[i] ^ a[(3 + i) % 4] ^ a[(2 + i) % 4] ^ b[(1 + i) % 4] ^ a[(1 + i) % 4];
            }
        }
        void inv_mix_column(const int &column_index)
        {
            byte a[4];
            byte b[4];
            byte c[4];
            byte d[4];
            byte e[4];
            /*
        * impl from wikipedia
        * The array 'a' is simply a copy of the input array 'r'
        * The array 'b' is each element of the array 'a' multiplied by 9 in Rijndael's Galois field
        * The array 'c' is each element of the array 'a' multiplied by 11 in Rijndael's Galois field
        * The array 'd' is each element of the array 'a' multiplied by 13 in Rijndael's Galois field
        * The array 'e' is each element of the array 'a' multiplied by 14 in Rijndael's Galois field
        *
        */
            for (int i = 0; i < 4; i++)
            {
                a[i] = state[i][column_index];
                b[i] = gf256_9[a[i]];
                c[i] = gf256_11[a[i]];
                d[i] = gf256_13[a[i]];
                e[i] = gf256_14[a[i]];
            }
            for (int i = 0; i < 4; i++)
            {
                state[i][column_index] = e[i] ^ c[(i + 1) % 4] ^ d[(i + 2) % 4] ^ b[(i + 3) % 4];
            }
        }

        void sub_word(byte bytes[4])
        {
            for (int i = 0; i < 4; i++)
            {
                bytes[i] = sbox[bytes[i] / 16][bytes[i] % 16];
            }
        }
        void rot_word(byte bytes[4], const int &shift)
        {
            // shift from right to left if shift > 0

            byte temp[12];
            for (int i = 0; i < 12; i++)
            {
                temp[i] = bytes[i % 4];
            }
            for (int i = 4; i < 8; i++)
            {
                bytes[i % 4] = temp[i + shift];
            }
        }

        void mix_columns()
        {
            for (int i = 0; i < 4; i++)
            {
                mix_column(i);
            }
        }
        void shift_rows()
        {
            for (int i = 0; i < 4; i++)
            {
                rot_word(state[i], i);
            }
        }
        void sub_bytes()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i][j] = sbox[state[i][j] / 16][state[i][j] % 16];
                }
            }
        }
        void add_round_keys(const int &round)
        {
            byte *key = expanded_key[round];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i][j] ^= key[i * 4 + j];
                }
            }
        }

        void inv_mix_columns()
        {
            for (int i = 0; i < 4; i++)
            {
                inv_mix_column(i);
            }
        }
        void inv_shift_rows()
        {
            for (int i = 0; i < 4; i++)
            {
                rot_word(state[i], -i);
            }
        }
        void inv_sub_bytes()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i][j] = in_sbox[state[i][j] / 16][state[i][j] % 16];
                }
            }
        }

        void reset()
        {
            memset(state, 0, sizeof(state));
            memset(expanded_key, 0, sizeof(expanded_key));
        }

    public:
        AES()
        {
            cout << "constructor of AES<" << key_size << ">" << endl;
        }

        ~AES()
        {
            cout << "destructor of AES<" << key_size << ">" << endl;
        }

        void set_key(byte key[n_byte_in_key])
        {
            cout << "set_key" << endl;
            reset();
            expand_key(key);
        }

        void encrypt(const byte plain_text[n_byte_in_block], byte cipher_text[n_byte_in_block])
        {
            cout << "encrypt" << endl;
            memcpy(state, plain_text, sizeof(state));
            add_round_keys(0);
            for (int i = 1; i < round; i++)
            {
                sub_bytes();
                shift_rows();
                mix_columns();
                add_round_keys(i);
            }
            sub_bytes();
            shift_rows();
            add_round_keys(round);
            memcpy(cipher_text, state, sizeof(state));
        }
        void decrypt(const byte cipher_text[n_byte_in_block], byte plain_text[n_byte_in_block])
        {
            cout << "decrypt" << endl;
            memcpy(state, cipher_text, sizeof(state));

            add_round_keys(round);
            inv_shift_rows();
            inv_sub_bytes();
            for (int i = round - 1; i > 0; i--)
            {
                add_round_keys(i);
                inv_mix_columns();
                inv_shift_rows();
                inv_sub_bytes();
            }

            add_round_keys(0);

            memcpy(plain_text, state, sizeof(state));
        }

        void test_mix_columns(byte plain_text[n_byte_in_block], byte cipher[n_byte_in_block])
        {
            memcpy(state, plain_text, sizeof(state));
            cout << this->state << endl;
            mix_columns();
            inv_mix_columns();
            cout << this->state << endl;
        }
        void test_shift_rows(byte plain_text[n_byte_in_block], byte cipher[n_byte_in_block])
        {
            memcpy(state, plain_text, sizeof(state));
            cout << this->state << endl;
            shift_rows();
            inv_shift_rows();
            cout << this->state << endl;
        }
        void test_sub_bytes(byte plain_text[n_byte_in_block], byte cipher[n_byte_in_block])
        {
            memcpy(state, plain_text, sizeof(state));
            cout << this->state << endl;
            shift_rows();
            inv_shift_rows();
            cout << this->state << endl;
        }
        void test_add_round_key(byte plain_text[n_byte_in_block], byte cipher[n_byte_in_block])
        {
            memcpy(state, plain_text, sizeof(state));
            cout << this->state << endl;
            add_round_keys(0);
            add_round_keys(0);
            cout << this->state << endl;
        }

        void test(byte plain_text[n_byte_in_block], byte cipher[n_byte_in_block])
        {
            // memcpy(state, plain_text, sizeof(state));
            // test_mix_columns(plain_text, cipher);
            // test_shift_rows(plain_text, cipher);
            // test_sub_bytes(plain_text, cipher);
            // test_add_round_key(plain_text, cipher);
        }
    };

    template <int key_size, int block_size>
    const int AES<key_size, block_size>::round = AES<key_size>::n_byte_in_key / 4 + 6;
} // namespace cryptology

/*
 * x = 17
 * 17 * 13 -> 195 + 43 = 238 -> 221
 * 17 * 14 -> 195 + 54 = 249 -> 238
 * 17 * 13 + 17 -> 221 ^ 17
 *
 * */
