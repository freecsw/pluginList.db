#include <memory.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t key_db[] =  {0x566b7b91, 0x70e7cf96, 0xA4D29E83, 0xF15E0FCE};
uint32_t key_enc[] = {0x463ADEAE, 0x9B47F686, 0x8A9C1D85, 0xF46B7EBF};

uint32_t swapu32(uint32_t n)
{
    return(((n & 0xff000000) >> 24) | ((n & 0x000000ff) << 24) | ((n & 0x00ff0000) >> 8) | ((n & 0x0000ff00) << 8));
}

void crypt_qword(uint32_t *in, uint32_t *key, uint32_t *out,int encrypt = true)
{
    uint32_t code[4];
    register uint32_t i = 16, j = encrypt?0:0xe3779B90, m, n;

    m = swapu32(in[0]);
    n = swapu32(in[1]);

    code[0] = swapu32(key[0]); code[1] = swapu32(key[1]);
    code[2] = swapu32(key[2]); code[3] = swapu32(key[3]);

    while (i-- > 0)
    {
        if(encrypt)
        {
            j -= 0x61c88647;
            m += (n >> 5) + code[1] ^ (n << 4) + code[0] ^ j + n;
            n += (m >> 5) + code[3] ^ (m << 4) + code[2] ^ j + m;
        }
        else
        {
            n -= ((m >> 5) + code[3]) ^ ((m << 4) + code[2]) ^ (j + m);
            m -= ((n >> 5) + code[1]) ^ ((n << 4) + code[0]) ^ (j + n);
            j += 0x61C88647;
        }
    }
    out[0] = swapu32(m);
    out[1] = swapu32(n);
}

uint32_t decrypt_msg(uint8_t *in, uint32_t inlen, uint32_t *key, uint8_t *out, uint32_t *outlen)
{
    uint8_t q[8], mkey[8], *q1, *q2, *outp;
    register int count, i, j, m, p;

    if (inlen % 8 || inlen < 16) return 0;
    /* get basic information of the packet */
    crypt_qword((uint32_t *)in, key, (uint32_t *)q,false);
    j = q[0] & 0x7;
    count = inlen - j - 10;
    if (*outlen < count || count < 0) return 0;
    *outlen = count;

    memset(mkey, 0, 8);
    q2 = mkey;
    i = 8; p = 1;
    q1 = in + 8;
    j++;
    while (p <= 2)
    {
        if (j < 8)
        {
            j ++;
            p ++;
        }
        else if (j == 8)
        {
            q2 = in;
            for (j = 0; j < 8; j ++ )
            {
                if (i + j >= inlen) return 0;
                q[j] ^= q1[j];
            }
            crypt_qword((uint32_t *)q, key, (uint32_t *) q,false);
            i += 8;
            q1 += 8;
            j = 0;
        }
    }
    outp = out;
    while (count != 0)
    {
        if (j < 8)
        {
            outp[0] = q2[j] ^ q[j];
            outp ++;
            count--;
            j ++;
        }
        else if (j == 8)
        {
            q2 = q1 - 8;
            for (j = 0; j < 8; j ++ )
            {
                if (i + j >= inlen) return 0;
                q[j] ^= q1[j];
            }
            crypt_qword((uint32_t *)q, key, (uint32_t *) q,false);
            i += 8;
            q1 += 8;
            j = 0;
        }
    }
    for (p = 1; p < 8; p ++)
    {
        if (j < 8)
        {
            if (q2[j] ^ q[j])
                return 0;
            j ++;
        }
        else if (j == 8 )
        {
            q2 = q1;
            for (j = 0; j < 8; j ++ )
            {
                if (i + j >= inlen) return 0;
                q[j] ^= q1[j];
            }
            crypt_qword((uint32_t *)q, key, (uint32_t *) q,false);
            i += 8;
            q1 += 8;
            j = 0;
        }
    }
    return 1;
}


void encrypt_msg(uint8_t *in, int inlen, uint32_t *key, uint8_t *out, uint32_t *outlen)
{
    register int m, i, j, count, p = 1;
    uint8_t q[12], *q1, *q2, *inp;
    uint8_t mkey[8];

    m = (inlen + 10) % 8;

    if (m)  m = 8 - m;
    q[0] = (rand() & 0xf8) | m;
    i = j = 1;
    while (m > 0)
    {
        q[i++] = rand() & 0xff;
        m--;
    }
    count = *outlen = 0;
    q2 = q1 = out;
    memset(mkey, 0, sizeof(mkey));
    while ( p <= 2 )
    {
        if (i < 8)
        {
            q[i++] = rand() & 0xff;
            p ++;
        }
        if (i == 8)
        {
            for (i = 0; i < 8; i ++)
                q[i] ^= mkey[i];
            crypt_qword((uint32_t *)q, key, (uint32_t *)out);
            for (i = 0; i < 8; i ++)
                q1[i] ^= mkey[i];
            q2 = q1;
            q1 += 8;
            count += 8;
            memcpy(mkey, q, 8);
            j = i = 0;
        }
    }
    inp = in;
    while (inlen > 0)
    {
        if (i < 8)
        {
            q[i] = inp[0];
            inp ++;
            i ++;
            inlen--;
        }
        if (i == 8)
        {
            for (i = 0; i < 8; i ++)
            {
                if (j) q[i] ^= mkey[i];
                else q[i] ^= q2[i];
            }
            j = 0;
            crypt_qword((uint32_t *)q, key, (uint32_t *)q1);
            for (i = 0; i < 8; i ++)
                q1[i] ^= mkey[i];
            count += 8;
            memcpy(mkey, q, 8);
            q2 = q1;
            q1 += 8;
            i = 0;
        }
    }
    p = 1;
    while (p < 8)
    {
        if (i < 8)
        {
            memset(q + i, 0, 4);
            p++;
            i++;
        }
        if (i == 8)
        {
            for (i = 0; i < 8; i ++)
                q[i] ^= q2[i];
            crypt_qword((uint32_t *)q, key, (uint32_t *)q1);
            for (i = 0; i < 8; i ++)
                q1[i] ^= mkey[i];
            memcpy(mkey, q, 8);
            count += 8;
            q2 = q1;
            q1 += 8;
            i = 0;
        }
    }
    *outlen = count;
}
