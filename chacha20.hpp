
#ifndef CHACHA20_CXX_H
#define CHACHA20_CXX_H 1

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace chacha20_detail
{
[[noreturn]] inline void fail(const char *msg)
{
    throw std::runtime_error(msg);
}
} // namespace chacha20_detail

namespace chacha20_util
{
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_pad = '=';
inline std::string toHex(const std::string &data)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data)
    {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}
inline std::string fromHex(const std::string &hexStr)
{
    std::string out;
    if (hexStr.size() % 2 != 0)
        chacha20_detail::fail("Odd length hex string");
    out.reserve(hexStr.size() / 2);
    for (size_t i = 0; i < hexStr.size(); i += 2)
    {
        uint8_t hi = static_cast<uint8_t>(std::stoi(hexStr.substr(i, 1), nullptr, 16));
        uint8_t lo = static_cast<uint8_t>(std::stoi(hexStr.substr(i + 1, 1), nullptr, 16));
        out.push_back((hi << 4) | lo);
    }
    return out;
}
inline std::string toBase64(const std::string &data)
{
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(b64_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back(b64_pad);
    return out;
}
inline std::string fromBase64(const std::string &b64)
{
    int val = 0, valb = -8;
    std::string out;
    for (uint8_t c : b64)
    {
        if (c == b64_pad)
            break;
        const char *p = std::find(b64_table, b64_table + 64, c);
        if (p == b64_table + 64)
            break;
        val = (val << 6) + (p - b64_table);
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}
inline std::string toBinary(const std::string &data)
{
    std::string out;
    out.reserve(data.size() * 8);
    for (uint8_t b : data)
        for (int i = 7; i >= 0; --i)
            out.push_back((b & (1 << i)) ? '1' : '0');
    return out;
}
inline std::string fromBinary(const std::string &bin)
{
    if (bin.size() % 8 != 0)
        chacha20_detail::fail("Binary string size must be multiple of 8");
    std::string out;
    for (size_t i = 0; i < bin.size(); i += 8)
    {
        uint8_t val = 0;
        for (int j = 0; j < 8; ++j)
            val = (val << 1) | (bin[i + j] == '1' ? 1 : 0);
        out.push_back(val);
    }
    return out;
}
} // namespace chacha20_util

class ChaCha20Result
{
    std::string data_;

  public:
    ChaCha20Result(const std::string &d) : data_(d)
    {
    }
    ChaCha20Result toHex() const
    {
        return ChaCha20Result(chacha20_util::toHex(data_));
    }
    ChaCha20Result fromHex() const
    {
        return ChaCha20Result(chacha20_util::fromHex(data_));
    }
    ChaCha20Result toBase64() const
    {
        return ChaCha20Result(chacha20_util::toBase64(data_));
    }
    ChaCha20Result fromBase64() const
    {
        return ChaCha20Result(chacha20_util::fromBase64(data_));
    }
    ChaCha20Result toBinary() const
    {
        return ChaCha20Result(chacha20_util::toBinary(data_));
    }
    ChaCha20Result fromBinary() const
    {
        return ChaCha20Result(chacha20_util::fromBinary(data_));
    }
    std::string asString() const
    {
        return data_;
    }
    std::vector<uint8_t> asVector() const
    {
        return std::vector<uint8_t>(data_.begin(), data_.end());
    }
    operator std::string() const
    {
        return data_;
    }
    operator std::vector<uint8_t>() const
    {
        return asVector();
    }
};

// Key/IV generation utilities
class ChaCha20KeyIVGen
{
  public:
    static std::string generateKey()
    {
        std::string key(32, 0);
        randomFill(reinterpret_cast<uint8_t *>(&key[0]), 32);
        return key;
    }
    static std::string generateIV()
    {
        std::string iv(12, 0);
        randomFill(reinterpret_cast<uint8_t *>(&iv[0]), 12);
        return iv;
    }
    static std::string generateXNonce()
    {
        std::string xnonce(24, 0);
        randomFill(reinterpret_cast<uint8_t *>(&xnonce[0]), 24);
        return xnonce;
    }

  private:
    static void randomFill(uint8_t *buf, size_t n)
    {
        std::random_device rd;
        for (size_t i = 0; i < n; ++i)
            buf[i] = static_cast<uint8_t>(rd());
    }
};

// =============== ChaCha20 Core ===============
class ChaCha20
{
  public:
    static constexpr size_t KeySize = 32;
    static constexpr size_t NonceSize = 12;
    static constexpr size_t BlockSize = 64;

    ChaCha20Result encrypt(const std::string &plaintext, const std::string &key, const std::string &iv, uint32_t counter = 0) const
    {
        return ChaCha20Result(apply(plaintext, key, iv, counter));
    }
    ChaCha20Result decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv, uint32_t counter = 0) const
    {
        return ChaCha20Result(apply(ciphertext, key, iv, counter));
    }

    static void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d)
    {
        a += b;
        d ^= a;
        d = (d << 16) | (d >> 16);
        c += d;
        b ^= c;
        b = (b << 12) | (b >> 20);
        a += b;
        d ^= a;
        d = (d << 8) | (d >> 24);
        c += d;
        b ^= c;
        b = (b << 7) | (b >> 25);
    }
    static void chachaBlock(std::array<uint32_t, 16> &output, const uint32_t key[8], const uint32_t nonce[3], uint32_t counter)
    {
        static constexpr uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        std::array<uint32_t, 16> state;
        state[0] = constants[0];
        state[1] = constants[1];
        state[2] = constants[2];
        state[3] = constants[3];
        for (int i = 0; i < 8; ++i)
            state[4 + i] = key[i];
        state[12] = counter;
        state[13] = nonce[0];
        state[14] = nonce[1];
        state[15] = nonce[2];

        output = state;
        for (int i = 0; i < 10; ++i)
        {
            quarterRound(output[0], output[4], output[8], output[12]);
            quarterRound(output[1], output[5], output[9], output[13]);
            quarterRound(output[2], output[6], output[10], output[14]);
            quarterRound(output[3], output[7], output[11], output[15]);
            quarterRound(output[0], output[5], output[10], output[15]);
            quarterRound(output[1], output[6], output[11], output[12]);
            quarterRound(output[2], output[7], output[8], output[13]);
            quarterRound(output[3], output[4], output[9], output[14]);
        }
        for (int i = 0; i < 16; ++i)
            output[i] += state[i];
    }
    static std::string apply(const std::string &input, const std::string &key, const std::string &iv, uint32_t counter)
    {
        if (key.size() != KeySize)
            chacha20_detail::fail("ChaCha20: Key must be 32 bytes");
        if (iv.size() != NonceSize)
            chacha20_detail::fail("ChaCha20: IV/Nonce must be 12 bytes");
        std::string out(input.size(), '\0');
        uint32_t key32[8], nonce32[3];
        for (int i = 0; i < 8; ++i)
            key32[i] = le32(key.data() + i * 4);
        for (int i = 0; i < 3; ++i)
            nonce32[i] = le32(iv.data() + i * 4);
        size_t offset = 0;
        while (offset < input.size())
        {
            std::array<uint32_t, 16> block;
            chachaBlock(block, key32, nonce32, counter++);
            for (size_t i = 0; i < BlockSize && offset + i < input.size(); ++i)
            {
                out[offset + i] = input[offset + i] ^ ((block[i / 4] >> (8 * (i % 4))) & 0xff);
            }
            offset += BlockSize;
        }
        return out;
    }
    static uint32_t le32(const char *p)
    {
        return (uint32_t(uint8_t(p[0]))) | (uint32_t(uint8_t(p[1])) << 8) | (uint32_t(uint8_t(p[2])) << 16) | (uint32_t(uint8_t(p[3])) << 24);
    }
    static void store32(char *p, uint32_t x)
    {
        p[0] = x & 0xff;
        p[1] = (x >> 8) & 0xff;
        p[2] = (x >> 16) & 0xff;
        p[3] = (x >> 24) & 0xff;
    }
    static void store64(char *p, uint64_t x)
    {
        for (int i = 0; i < 8; ++i)
            p[i] = (x >> (8 * i)) & 0xff;
    }
};

// =============== XChaCha20 (24-byte nonce) ===============
class XChaCha20 : public ChaCha20
{
  public:
    static constexpr size_t XNonceSize = 24;
    ChaCha20Result encrypt(const std::string &plaintext, const std::string &key, const std::string &xnonce, uint32_t counter = 0) const
    {
        return ChaCha20Result(applyX(plaintext, key, xnonce, counter));
    }
    ChaCha20Result decrypt(const std::string &ciphertext, const std::string &key, const std::string &xnonce, uint32_t counter = 0) const
    {
        return ChaCha20Result(applyX(ciphertext, key, xnonce, counter));
    }

  private:
    // HChaCha20: 128-bit output subkey from 256-bit key and 16-byte nonce
    static void hchachaBlock(uint32_t out[8], const uint32_t key[8], const uint32_t nonce[4])
    {
        static constexpr uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        std::array<uint32_t, 16> state;
        state[0] = constants[0];
        state[1] = constants[1];
        state[2] = constants[2];
        state[3] = constants[3];
        for (int i = 0; i < 8; ++i)
            state[4 + i] = key[i];
        for (int i = 0; i < 4; ++i)
            state[12 + i] = nonce[i];
        for (int i = 0; i < 10; ++i)
        {
            quarterRound(state[0], state[4], state[8], state[12]);
            quarterRound(state[1], state[5], state[9], state[13]);
            quarterRound(state[2], state[6], state[10], state[14]);
            quarterRound(state[3], state[7], state[11], state[15]);
            quarterRound(state[0], state[5], state[10], state[15]);
            quarterRound(state[1], state[6], state[11], state[12]);
            quarterRound(state[2], state[7], state[8], state[13]);
            quarterRound(state[3], state[4], state[9], state[14]);
        }
        out[0] = state[0];
        out[1] = state[1];
        out[2] = state[2];
        out[3] = state[3];
        out[4] = state[12];
        out[5] = state[13];
        out[6] = state[14];
        out[7] = state[15];
    }
    static std::string applyX(const std::string &input, const std::string &key, const std::string &xnonce, uint32_t counter)
    {
        if (key.size() != KeySize)
            chacha20_detail::fail("XChaCha20: Key must be 32 bytes");
        if (xnonce.size() != XNonceSize)
            chacha20_detail::fail("XChaCha20: Nonce must be 24 bytes");
        uint32_t key32[8], nonce24[6];
        for (int i = 0; i < 8; ++i)
            key32[i] = le32(key.data() + i * 4);
        for (int i = 0; i < 6; ++i)
            nonce24[i] = le32(xnonce.data() + i * 4);
        // HChaCha20 with first 16 bytes of nonce
        uint32_t subkey[8];
        hchachaBlock(subkey, key32, nonce24);
        // Use last 8 bytes of nonce as IV for ChaCha20
        char iv[12];
        store32(iv + 0, 0); // counter=0 for the IV (counter is given to ChaCha20::apply)
        store32(iv + 4, nonce24[4]);
        store32(iv + 8, nonce24[5]);
        std::string skey(reinterpret_cast<char *>(subkey), 32);
        std::string siv(iv, 12);
        return ChaCha20::apply(input, skey, siv, counter);
    }
};

// =============== Poly1305 MAC ===============
class Poly1305
{
  public:
    // Key must be 32 bytes: first 16 bytes for r, last 16 for s
    static void mac(uint8_t out[16], const uint8_t *msg, size_t msgLen, const uint8_t key[32])
    {
        // Poly1305 implementation based on the reference
        uint32_t r[5], h[5] = {0}, pad[4];
        uint64_t d[5], c;
        size_t i, blocks = msgLen / 16;

        // Clamp r
        r[0] = (key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24)) & 0x3ffffff;
        r[1] = ((key[3] >> 2) | (key[4] << 6) | (key[5] << 14) | (key[6] << 22)) & 0x3ffff03;
        r[2] = ((key[6] >> 4) | (key[7] << 4) | (key[8] << 12) | (key[9] << 20)) & 0x3ffc0ff;
        r[3] = ((key[9] >> 6) | (key[10] << 2) | (key[11] << 10) | (key[12] << 18)) & 0x3f03fff;
        r[4] = (key[13] | (key[14] << 8) | (key[15] << 16)) & 0x00fffff;

        // Pad
        pad[0] = (key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24));
        pad[1] = (key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24));
        pad[2] = (key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24));
        pad[3] = (key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24));

        const uint8_t *ptr = msg;
        size_t rem = msgLen;
        while (rem >= 16)
        {
            uint32_t t0 = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
            uint32_t t1 = ptr[4] | (ptr[5] << 8) | (ptr[6] << 16) | (ptr[7] << 24);
            uint32_t t2 = ptr[8] | (ptr[9] << 8) | (ptr[10] << 16) | (ptr[11] << 24);
            uint32_t t3 = ptr[12] | (ptr[13] << 8) | (ptr[14] << 16) | (ptr[15] << 24);
            h[0] += t0 & 0x3ffffff;
            h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
            h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
            h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
            h[4] += (t3 >> 8) | (1 << 24);

            // Multiply (h * r) mod (2^130 - 5)
            d[0] = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * 5 * r[4] + (uint64_t)h[2] * 5 * r[3] + (uint64_t)h[3] * 5 * r[2] + (uint64_t)h[4] * 5 * r[1];
            d[1] = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * 5 * r[4] + (uint64_t)h[3] * 5 * r[3] + (uint64_t)h[4] * 5 * r[2];
            d[2] = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] + (uint64_t)h[3] * 5 * r[4] + (uint64_t)h[4] * 5 * r[3];
            d[3] = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] + (uint64_t)h[3] * r[0] + (uint64_t)h[4] * 5 * r[4];
            d[4] = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + (uint64_t)h[2] * r[2] + (uint64_t)h[3] * r[1] + (uint64_t)h[4] * r[0];

            c = d[0] >> 26;
            h[0] = d[0] & 0x3ffffff;
            d[1] += c;
            c = d[1] >> 26;
            h[1] = d[1] & 0x3ffffff;
            d[2] += c;
            c = d[2] >> 26;
            h[2] = d[2] & 0x3ffffff;
            d[3] += c;
            c = d[3] >> 26;
            h[3] = d[3] & 0x3ffffff;
            d[4] += c;
            c = d[4] >> 26;
            h[4] = d[4] & 0x3ffffff;
            h[0] += c * 5;
            c = h[0] >> 26;
            h[0] &= 0x3ffffff;
            h[1] += c;

            ptr += 16;
            rem -= 16;
        }

        // Process any remaining bytes
        if (rem)
        {
            uint8_t block[16] = {0};
            memcpy(block, ptr, rem);
            block[rem] = 1;
            uint32_t t0 = block[0] | (block[1] << 8) | (block[2] << 16) | (block[3] << 24);
            uint32_t t1 = block[4] | (block[5] << 8) | (block[6] << 16) | (block[7] << 24);
            uint32_t t2 = block[8] | (block[9] << 8) | (block[10] << 16) | (block[11] << 24);
            uint32_t t3 = block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24);
            h[0] += t0 & 0x3ffffff;
            h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
            h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
            h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
            h[4] += (t3 >> 8);
        }

        // Final reduction mod 2^130-5
        c = h[1] >> 26;
        h[1] &= 0x3ffffff;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= 0x3ffffff;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= 0x3ffffff;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= 0x3ffffff;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += c;

        // Compute h + -p
        uint32_t g[5];
        g[0] = h[0] + 5;
        c = g[0] >> 26;
        g[0] &= 0x3ffffff;
        g[1] = h[1] + c;
        c = g[1] >> 26;
        g[1] &= 0x3ffffff;
        g[2] = h[2] + c;
        c = g[2] >> 26;
        g[2] &= 0x3ffffff;
        g[3] = h[3] + c;
        c = g[3] >> 26;
        g[3] &= 0x3ffffff;
        g[4] = h[4] + c - (1UL << 26);

        // Select h if h < p, or h + -p if h >= p
        uint32_t mask = (g[4] >> 31) - 1;
        for (i = 0; i < 5; ++i)
            h[i] = (h[i] & ~mask) | (g[i] & mask);

        // Serialize to 16 bytes and add pad
        uint64_t f0 = ((uint64_t)h[0]) | ((uint64_t)h[1] << 26);
        uint64_t f1 = ((uint64_t)h[1] >> 6) | ((uint64_t)h[2] << 20);
        uint64_t f2 = ((uint64_t)h[2] >> 12) | ((uint64_t)h[3] << 14);
        uint64_t f3 = ((uint64_t)h[3] >> 18) | ((uint64_t)h[4] << 8);

        f0 = (f0 + pad[0]) & 0xffffffff;
        f1 = (f1 + pad[1]) & 0xffffffff;
        f2 = (f2 + pad[2]) & 0xffffffff;
        f3 = (f3 + pad[3]) & 0xffffffff;

        out[0] = f0 & 0xff;
        out[1] = (f0 >> 8) & 0xff;
        out[2] = (f0 >> 16) & 0xff;
        out[3] = (f0 >> 24) & 0xff;
        out[4] = f1 & 0xff;
        out[5] = (f1 >> 8) & 0xff;
        out[6] = (f1 >> 16) & 0xff;
        out[7] = (f1 >> 24) & 0xff;
        out[8] = f2 & 0xff;
        out[9] = (f2 >> 8) & 0xff;
        out[10] = (f2 >> 16) & 0xff;
        out[11] = (f2 >> 24) & 0xff;
        out[12] = f3 & 0xff;
        out[13] = (f3 >> 8) & 0xff;
        out[14] = (f3 >> 16) & 0xff;
        out[15] = (f3 >> 24) & 0xff;
    }

  private:
    static uint64_t U8TO64_LE(const uint8_t *p)
    {
        uint64_t r = 0;
        for (int i = 0; i < 8; ++i)
            r |= (uint64_t)p[i] << (8 * i);
        return r;
    }
};

// =============== AEAD: XChaCha20-Poly1305 ===============
class XChaCha20Poly1305
{
  public:
    static constexpr size_t KeySize = 32;
    static constexpr size_t XNonceSize = 24;
    static constexpr size_t TagSize = 16;

    // Encrypts and authenticates: returns ciphertext||tag
    static ChaCha20Result aead_encrypt(const std::string &plaintext, const std::string &key, const std::string &xnonce, const std::string &aad = "")
    {
        // Derive Poly1305 key using XChaCha20 block with counter=0
        XChaCha20 xchacha;
        std::string block = xchacha.encrypt(std::string(64, 0), key, xnonce, 0).asString();
        const uint8_t *polykey = (const uint8_t *)block.data();

        // Encrypt plaintext with XChaCha20, counter=1
        std::string ciphertext = xchacha.encrypt(plaintext, key, xnonce, 1).asString();

        // Poly1305 MAC: aad | pad | ciphertext | pad | lengths
        std::string mac_data = aad;
        if (aad.size() % 16)
            mac_data.append(16 - (aad.size() % 16), '\0');
        mac_data += ciphertext;
        if (ciphertext.size() % 16)
            mac_data.append(16 - (ciphertext.size() % 16), '\0');
        char lens[16];
        XChaCha20::store64(lens, aad.size());
        XChaCha20::store64(lens + 8, ciphertext.size());
        mac_data.append(lens, 16);

        uint8_t tag[16];
        Poly1305::mac(tag, (const uint8_t *)mac_data.data(), mac_data.size(), polykey);

        std::string out = ciphertext + std::string((char *)tag, 16);
        return ChaCha20Result(out);
    }

    // Decrypts and authenticates: returns plaintext or throws on failure
    static ChaCha20Result aead_decrypt(const std::string &ciphertext_and_tag, const std::string &key, const std::string &xnonce, const std::string &aad = "")
    {
        if (ciphertext_and_tag.size() < 16)
            chacha20_detail::fail("AEAD: Ciphertext too short");
        size_t clen = ciphertext_and_tag.size() - 16;
        std::string ciphertext = ciphertext_and_tag.substr(0, clen);
        const uint8_t *tag = (const uint8_t *)&ciphertext_and_tag[clen];
        // Derive Poly1305 key using XChaCha20 block with counter=0
        XChaCha20 xchacha;
        std::string block = xchacha.encrypt(std::string(64, 0), key, xnonce, 0).asString();
        const uint8_t *polykey = (const uint8_t *)block.data();

        // Poly1305 MAC: aad | pad | ciphertext | pad | lengths
        std::string mac_data = aad;
        if (aad.size() % 16)
            mac_data.append(16 - (aad.size() % 16), '\0');
        mac_data += ciphertext;
        if (ciphertext.size() % 16)
            mac_data.append(16 - (ciphertext.size() % 16), '\0');
        char lens[16];
        XChaCha20::store64(lens, aad.size());
        XChaCha20::store64(lens + 8, ciphertext.size());
        mac_data.append(lens, 16);

        uint8_t computed_tag[16];
        Poly1305::mac(computed_tag, (const uint8_t *)mac_data.data(), mac_data.size(), polykey);

        if (memcmp(tag, computed_tag, 16) != 0)
            chacha20_detail::fail("AEAD: Tag verification failed");

        std::string plaintext = xchacha.encrypt(ciphertext, key, xnonce, 1).asString();
        return ChaCha20Result(plaintext);
    }
};

#endif
