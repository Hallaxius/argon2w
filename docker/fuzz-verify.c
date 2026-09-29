#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"

int argon2w_verify(const char *encoded, const uint8_t *pwd, uint32_t pwdlen,
                   const uint8_t *secret, uint32_t secretlen,
                   const uint8_t *ad, uint32_t adlen);
int argon2w_hash_raw(uint32_t type, uint32_t version, const uint8_t *pwd,
                     uint32_t pwdlen, const uint8_t *salt, uint32_t saltlen,
                     const uint8_t *secret, uint32_t secretlen,
                     const uint8_t *ad, uint32_t adlen, uint32_t t_cost,
                     uint32_t m_cost, uint32_t lanes, uint8_t *out,
                     uint32_t outlen);

static uint8_t secret8[8] = {9, 9, 9, 9, 9, 9, 9, 9};
static uint8_t ad12[12] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};

int main(int argc, char **argv) {
    FILE *f;
    long size;
    char *buf;
    size_t got;
    int codes[4];
    int i;
    if (argc != 2) {
        fprintf(stderr, "usage: fuzz-verify <file>\n");
        return 2;
    }
    f = fopen(argv[1], "rb");
    if (f == (FILE *)0) {
        fprintf(stderr, "cannot open input\n");
        return 2;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0 || size > 1048576) {
        fclose(f);
        fprintf(stderr, "input too large\n");
        return 2;
    }
    buf = (char *)malloc((size_t)size + 1);
    if (buf == (char *)0) {
        fclose(f);
        return 2;
    }
    got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[got] = '\0';
    {
        static uint8_t pwd3[3] = {'p', 'w', 'd'};
        static uint8_t empty1[1] = {0};
        codes[0] = argon2w_verify(buf, (const uint8_t *)0, UINT32_C(0),
                                  (const uint8_t *)0, UINT32_C(0),
                                  (const uint8_t *)0, UINT32_C(0));
        codes[1] = argon2w_verify(buf, pwd3, UINT32_C(3),
                                  secret8, UINT32_C(8), ad12, UINT32_C(12));
        codes[2] = argon2w_verify(buf, pwd3, UINT32_C(3),
                                  (const uint8_t *)0, UINT32_C(0),
                                  (const uint8_t *)0, UINT32_C(0));
        codes[3] = argon2w_verify("", empty1, UINT32_C(0),
                                  (const uint8_t *)0, UINT32_C(0),
                                  (const uint8_t *)0, UINT32_C(0));
    }
    printf("codes: %d %d %d %d\n", codes[0], codes[1], codes[2], codes[3]);
    for (i = 0; i < 4; ++i) {
        if (codes[i] == 0) {
            printf("unexpected success: an adversarial input authenticated\n");
            free(buf);
            return 1;
        }
        if (codes[i] > 0 || codes[i] < -35) {
            printf("unexpected code range: %d\n", codes[i]);
            free(buf);
            return 1;
        }
    }
    free(buf);
    {
        static uint8_t probe_pwd[3] = {'p', 'w', 'd'};
        static uint8_t probe_salt[8] = {'s', 'a', 'l', 't', '8', 'b', 'y', 't'};
        static uint8_t probe_out[32];
        int rc = argon2w_hash_raw(Argon2_id, ARGON2_VERSION_13,
                                  probe_pwd, UINT32_C(3), probe_salt,
                                  UINT32_C(8), (const uint8_t *)0, UINT32_C(0),
                                  (const uint8_t *)0, UINT32_C(0),
                                  UINT32_C(4294967295), UINT32_C(32),
                                  UINT32_C(1), probe_out, UINT32_C(32));
        if (rc != ARGON2_TIME_TOO_LARGE) {
            printf("t-cap probe: expected ARGON2_TIME_TOO_LARGE, got %d\n", rc);
            return 1;
        }
    }
    return 0;
}
