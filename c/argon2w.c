

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"
#include "encoding.h"


uint8_t *argon2w_alloc(uint32_t size) {
    uint8_t *p;
    uint32_t i;
    if (size == UINT32_C(0)) {
        return (uint8_t *)0;
    }
    p = (uint8_t *)malloc((size_t)size);
    if (p == (uint8_t *)0) {
        return (uint8_t *)0;
    }
    for (i = UINT32_C(0); i < size; ++i) {
        p[i] = UINT8_C(0);
    }
    return p;
}


static void argon2w_wipe(volatile uint8_t *ptr, size_t size) {
    size_t i;
    for (i = 0; i < size; ++i) {
        ptr[i] = UINT8_C(0);
    }
}


void argon2w_free(uint8_t *ptr, uint32_t size) {
    if (ptr != (uint8_t *)0) {
        argon2w_wipe(ptr, (size_t)size);
        free(ptr);
    }
}


const char *argon2w_error_message(int code) {
    const char *msg = argon2_error_message(code);
    return msg != (const char *)0 ? msg : "Unknown error code";
}


#define ARGON2W_MAX_M_COST_KIB UINT32_C(65536)


#define ARGON2W_MAX_T_COST UINT32_C(65536)


static int argon2w_validate(uint32_t type, uint32_t version, uint32_t saltlen,
                            uint32_t t_cost, uint32_t m_cost, uint32_t lanes,
                            uint32_t outlen) {
    if (type != (uint32_t)Argon2_id) {
        return ARGON2_INCORRECT_TYPE;
    }
    if (version != (uint32_t)ARGON2_VERSION_13) {
        return ARGON2_INCORRECT_TYPE;
    }
    if (saltlen < ARGON2_MIN_SALT_LENGTH) {
        return ARGON2_SALT_TOO_SHORT;
    }
    if (outlen < ARGON2_MIN_OUTLEN) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }
    if (t_cost < (uint32_t)1) {
        return ARGON2_TIME_TOO_SMALL;
    }
    if (t_cost > ARGON2W_MAX_T_COST) {
        return ARGON2_TIME_TOO_LARGE;
    }
    if (lanes < (uint32_t)1) {
        return ARGON2_LANES_TOO_FEW;
    }
    if (lanes > ARGON2_MAX_LANES) {
        return ARGON2_LANES_TOO_MANY;
    }
    if (m_cost < (uint32_t)(8u * lanes)) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }
    if (m_cost > ARGON2W_MAX_M_COST_KIB) {
        return ARGON2_MEMORY_TOO_MUCH;
    }
    return ARGON2_OK;
}


static void argon2w_fill_context(argon2_context *context, const uint8_t *pwd,
                                 uint32_t pwdlen, const uint8_t *salt,
                                 uint32_t saltlen, const uint8_t *secret,
                                 uint32_t secretlen, const uint8_t *ad,
                                 uint32_t adlen, uint32_t t_cost,
                                 uint32_t m_cost, uint32_t lanes,
                                 uint8_t *out, uint32_t outlen) {
    memset(context, 0, sizeof(argon2_context));
    context->out = out;
    context->outlen = outlen;
    context->pwd = (uint8_t *)(pwdlen == UINT32_C(0) ? (const uint8_t *)0 : pwd);
    context->pwdlen = pwdlen;
    context->salt = (uint8_t *)salt;
    context->saltlen = saltlen;
    context->secret =
        (uint8_t *)(secretlen == UINT32_C(0) ? (const uint8_t *)0 : secret);
    context->secretlen = secretlen;
    context->ad = (uint8_t *)(adlen == UINT32_C(0) ? (const uint8_t *)0 : ad);
    context->adlen = adlen;
    context->t_cost = t_cost;
    context->m_cost = m_cost;
    context->lanes = lanes;
    context->threads = lanes;
    context->version = ARGON2_VERSION_13;
    context->flags =
        ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
}


int argon2w_hash_raw(uint32_t type, uint32_t version, const uint8_t *pwd,
                     uint32_t pwdlen, const uint8_t *salt, uint32_t saltlen,
                     const uint8_t *secret, uint32_t secretlen,
                     const uint8_t *ad, uint32_t adlen, uint32_t t_cost,
                     uint32_t m_cost, uint32_t lanes, uint8_t *out,
                     uint32_t outlen) {
    argon2_context context;
    int status = argon2w_validate(type, version, saltlen, t_cost, m_cost,
                                  lanes, outlen);
    if (status != ARGON2_OK) {
        return status;
    }
    if (out == (uint8_t *)0) {
        return ARGON2_OUT_PTR_MISMATCH;
    }
    
    if (salt == (const uint8_t *)0 && saltlen != UINT32_C(0)) {
        return ARGON2_SALT_PTR_MISMATCH;
    }
    if (pwd == (const uint8_t *)0 && pwdlen != UINT32_C(0)) {
        return ARGON2_PWD_PTR_MISMATCH;
    }
    argon2w_fill_context(&context, pwd, pwdlen, salt, saltlen, secret,
                         secretlen, ad, adlen, t_cost, m_cost, lanes, out,
                         outlen);
    status = argon2_ctx(&context, Argon2_id);
    return status;
}


uint32_t argon2w_encoded_len(uint32_t t_cost, uint32_t m_cost, uint32_t lanes,
                             uint32_t saltlen, uint32_t outlen) {
    size_t need =
        argon2_encodedlen(t_cost, m_cost, lanes, saltlen, outlen, Argon2_id);
    if (need > (size_t)UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)need;
}


int argon2w_hash_encoded(uint32_t type, uint32_t version, const uint8_t *pwd,
                         uint32_t pwdlen, const uint8_t *salt,
                         uint32_t saltlen, const uint8_t *secret,
                         uint32_t secretlen, const uint8_t *ad,
                         uint32_t adlen, uint32_t t_cost, uint32_t m_cost,
                         uint32_t lanes, uint8_t *out, uint32_t outlen,
                         char *encoded, uint32_t encodedlen) {
    argon2_context context;
    int status = argon2w_validate(type, version, saltlen, t_cost, m_cost,
                                  lanes, outlen);
    if (status != ARGON2_OK) {
        return status;
    }
    if (out == (uint8_t *)0) {
        return ARGON2_OUT_PTR_MISMATCH;
    }
    
    if (salt == (const uint8_t *)0 && saltlen != UINT32_C(0)) {
        return ARGON2_SALT_PTR_MISMATCH;
    }
    if (pwd == (const uint8_t *)0 && pwdlen != UINT32_C(0)) {
        return ARGON2_PWD_PTR_MISMATCH;
    }
    if (encoded == (char *)0) {
        return ARGON2_ENCODING_FAIL;
    }
    argon2w_fill_context(&context, pwd, pwdlen, salt, saltlen, secret,
                         secretlen, ad, adlen, t_cost, m_cost, lanes, out,
                         outlen);
    status = argon2_ctx(&context, Argon2_id);
    if (status != ARGON2_OK) {
        return status;
    }
    status = encode_string(encoded, (size_t)encodedlen, &context, Argon2_id);
    return status;
}


int argon2w_verify(const char *encoded, const uint8_t *pwd, uint32_t pwdlen,
                   const uint8_t *secret, uint32_t secretlen,
                   const uint8_t *ad, uint32_t adlen) {
    argon2_context context;
    argon2_type type = Argon2_id;
    uint8_t *desired = (uint8_t *)0;
    uint32_t max_field_len;
    size_t encoded_len;
    int status = ARGON2_OK;
    if (encoded == (const char *)0) {
        return ARGON2_DECODING_FAIL;
    }
    if (pwd == (const uint8_t *)0 && pwdlen != UINT32_C(0)) {
        return ARGON2_PWD_PTR_MISMATCH;
    }
    encoded_len = strlen(encoded);
    if (encoded_len == 0 || encoded_len > (size_t)UINT32_MAX) {
        return ARGON2_DECODING_FAIL;
    }
    
    max_field_len = (uint32_t)encoded_len;
    memset(&context, 0, sizeof(context));
    context.saltlen = max_field_len;
    context.outlen = max_field_len;
    context.salt = (uint8_t *)malloc((size_t)max_field_len);
    context.out = (uint8_t *)malloc((size_t)max_field_len);
    if (context.salt == (uint8_t *)0 || context.out == (uint8_t *)0) {
        status = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto done;
    }
    context.pwd =
        (uint8_t *)(pwdlen == UINT32_C(0) ? (const uint8_t *)0 : pwd);
    context.pwdlen = pwdlen;
    status = decode_string(&context, encoded, type);
    if (status != ARGON2_OK) {
        goto done;
    }
    if (type != Argon2_id || context.version != ARGON2_VERSION_13) {
        status = ARGON2_INCORRECT_TYPE;
        goto done;
    }
    if (context.m_cost > ARGON2W_MAX_M_COST_KIB) {
        status = ARGON2_MEMORY_TOO_MUCH;
        goto done;
    }
    if (context.t_cost > ARGON2W_MAX_T_COST) {
        status = ARGON2_TIME_TOO_LARGE;
        goto done;
    }
    
    desired = context.out;
    context.out = (uint8_t *)malloc((size_t)context.outlen);
    if (context.out == (uint8_t *)0) {
        context.out = desired;
        desired = (uint8_t *)0;
        status = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto done;
    }
    context.secret =
        (uint8_t *)(secretlen == UINT32_C(0) ? (const uint8_t *)0 : secret);
    context.secretlen = secretlen;
    context.ad = (uint8_t *)(adlen == UINT32_C(0) ? (const uint8_t *)0 : ad);
    context.adlen = adlen;
    context.threads = context.lanes;
    context.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
    status = argon2_verify_ctx(&context, (const char *)desired, Argon2_id);
done:
    if (context.salt != (uint8_t *)0) {
        argon2w_wipe(context.salt, (size_t)max_field_len);
        free(context.salt);
    }
    if (context.out != (uint8_t *)0) {
        argon2w_wipe(context.out, (size_t)context.outlen);
        free(context.out);
    }
    if (desired != (uint8_t *)0) {
        argon2w_wipe(desired, (size_t)context.outlen);
        free(desired);
    }
    return status;
}
