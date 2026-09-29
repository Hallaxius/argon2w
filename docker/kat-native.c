#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "argon2.h"

int argon2w_hash_raw(uint32_t type, uint32_t version, const uint8_t *pwd,
                     uint32_t pwdlen, const uint8_t *salt, uint32_t saltlen,
                     const uint8_t *secret, uint32_t secretlen,
                     const uint8_t *ad, uint32_t adlen, uint32_t t_cost,
                     uint32_t m_cost, uint32_t parallelism, uint8_t *out,
                     uint32_t outlen);
int argon2w_hash_encoded(uint32_t type, uint32_t version, const uint8_t *pwd,
                         uint32_t pwdlen, const uint8_t *salt,
                         uint32_t saltlen, const uint8_t *secret,
                         uint32_t secretlen, const uint8_t *ad, uint32_t adlen,
                         uint32_t t_cost, uint32_t m_cost,
                         uint32_t parallelism, uint8_t *out, uint32_t outlen,
                         char *encoded, uint32_t encodedlen);
uint32_t argon2w_encoded_len(uint32_t t_cost, uint32_t m_cost,
                             uint32_t parallelism, uint32_t saltlen,
                             uint32_t outlen);
int argon2w_verify(const char *encoded, const uint8_t *pwd, uint32_t pwdlen,
                   const uint8_t *secret, uint32_t secretlen,
                   const uint8_t *ad, uint32_t adlen);

static void print_hex(const uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned)buf[i]);
    }
    printf("\n");
}

int main(void) {
    static uint8_t password[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    };
    static uint8_t salt[16] = {
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
    };
    static uint8_t secret[8] = {0x03, 0x03, 0x03, 0x03,
                                      0x03, 0x03, 0x03, 0x03};
    static uint8_t ad[12] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                                   0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
    uint8_t tag[32] = {0};
    uint8_t tag2[32] = {0};
    char encoded[256] = {0};
    uint8_t pwd2[16];
    uint8_t salt2[16];
    uint32_t encoded_len;
    int status;

    status = argon2w_hash_raw(2, 19, password, 32, salt, 16, secret, 8, ad,
                              12, 3, 32, 4, tag, 32);
    printf("rfc9106 status=%d tag=", status);
    if (status == ARGON2_OK) {
        print_hex(tag, 32);
    } else {
        printf("unavailable\n");
    }

    memcpy(pwd2, "password", 8);
    memcpy(salt2, "somesalt01", 10);
    status = argon2w_hash_raw(2, 19, pwd2, 8, salt2, 10, 0, 0, 0, 0,
                              1, 8, 1, tag2, 32);
    printf("small status=%d tag=", status);
    if (status == ARGON2_OK) {
        print_hex(tag2, 32);
    } else {
        printf("unavailable\n");
    }

    encoded_len = argon2w_encoded_len(1, 8, 1, 10, 32);
    if (encoded_len > (uint32_t)(sizeof(encoded) - 1)) {
        encoded_len = (uint32_t)(sizeof(encoded) - 1);
    }
    printf("encoded_len=%u\n", (unsigned)encoded_len);
    memset(encoded, 0, sizeof(encoded));
    memcpy(pwd2, "password", 8);
    memcpy(salt2, "somesalt01", 10);
    status = argon2w_hash_encoded(
        2, 19, pwd2, 8, salt2, 10, 0, 0, 0, 0, 1, 8, 1, tag2, 32,
        encoded, encoded_len);
    printf("encode status=%d phc=%s\n", status,
           status == ARGON2_OK ? encoded : "unavailable");
    memcpy(pwd2, "password", 8);
    status = argon2w_verify(encoded, pwd2, 8, 0, 0, 0, 0);
    printf("verify-ok status=%d\n", status);
    memcpy(pwd2, "wrongpwd", 8);
    status = argon2w_verify(encoded, pwd2, 8, 0, 0, 0, 0);
    printf("verify-bad status=%d\n", status);
    return 0;
}
