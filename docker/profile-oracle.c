
#include <stdio.h>
#include <string.h>
#include "argon2.h"
int main(int argc, char **argv) {
    static const unsigned params[][3] = {
        {19456,3,1}, {19456,2,1}, {12288,3,1}, {9216,4,1}, {7168,5,1},
        {8192,1,1}, {4096,2,1}, {4096,1,1}, {2048,2,1}, {2048,1,1},
        {8,1,1}, {19,2,2}, {35,3,4}, {129,1,16}, {32768,1,4}
    };
    unsigned char pwd[32], salt[16], secret[8], ad[12], out[32];
    unsigned i, j;
    FILE *file;
    if (argc != 2) return 2;
    file = fopen(argv[1], "wb");
    if (!file) return 3;
    for (i=0; i<sizeof(params)/sizeof(params[0]); i++) {
        argon2_context ctx;
        for(j=0;j<32;j++) pwd[j]=(unsigned char)(j*17+i);
        memset(salt,2,sizeof(salt)); memset(secret,3,sizeof(secret));
        memset(ad,4,sizeof(ad)); memset(&ctx,0,sizeof(ctx));
        ctx.out=out; ctx.outlen=32; ctx.pwd=pwd; ctx.pwdlen=32;
        ctx.salt=salt; ctx.saltlen=16; ctx.secret=secret; ctx.secretlen=8;
        ctx.ad=ad; ctx.adlen=12; ctx.m_cost=params[i][0];
        ctx.t_cost=params[i][1]; ctx.lanes=params[i][2]; ctx.threads=1;
        ctx.version=ARGON2_VERSION_13;
        if(argon2_ctx(&ctx,Argon2_id)!=ARGON2_OK) { fclose(file); return 4; }
        if(fwrite(out,1,32,file)!=32) { fclose(file); return 5; }
    }
    return fclose(file)==0 ? 0 : 6;
}
