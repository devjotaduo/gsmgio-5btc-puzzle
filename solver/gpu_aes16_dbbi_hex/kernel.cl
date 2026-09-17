/* Kernel OpenCL: varre bijeções token->dígito hex do dbbi como senha AES do
 * blob SMALL do GSMG.IO. SHA256 e AES-256 escritos à mão.
 *
 * Por candidato:
 *   1. índice ulong -> permutação (Lehmer) -> senha 64B ASCII hex minúsculo
 *   2. key = SHA256(pw||salt)              (72B, 2 blocos)
 *   3. iv  = SHA256(key||pw||salt)[:16]    (104B, 2 blocos)
 *   4. AES-256 (14 rounds), DEcifra C0,C3,C4:
 *        P0 = D(C0) ^ IV ; P3 = D(C3) ^ C2 ; P4 = D(C4) ^ C3
 *   5. sobrevivência: (a) P0 começa com "Salted__" OU
 *        (b) P4 tem PKCS7 válido E P3+P4(antes do pad) imprimíveis.
 *
 * TTI (token_type_index) e HEXC ficam embutidos em __constant (nunca mudam).
 * salt e ct entram como argumentos (ct muda nos controles plantados).
 */

/* ------------------------------------------------------------- SHA-256 */
__constant uint SHA_K[64] = {
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };

inline uint rotr32(uint x, uint n){ return (x >> n) | (x << (32u - n)); }

/* SHA256 de mensagem de até 111 bytes (cabe em 2 blocos de 64B com padding). */
void sha256_2block(const uchar *msg, uint len, uchar *out){
    uchar block[128];
    for (int i=0;i<128;i++) block[i]=0;
    for (uint i=0;i<len;i++) block[i]=msg[i];
    block[len]=0x80;
    ulong bits=(ulong)len*8UL;
    for (int i=0;i<8;i++) block[127-i]=(uchar)(bits >> (8*i));
    uint h[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
               0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    for (int blk=0; blk<2; blk++){
        uint w[64];
        const uchar *p = block + blk*64;
        for (int t=0;t<16;t++)
            w[t]=((uint)p[4*t]<<24)|((uint)p[4*t+1]<<16)|((uint)p[4*t+2]<<8)|((uint)p[4*t+3]);
        for (int t=16;t<64;t++){
            uint s0=rotr32(w[t-15],7)^rotr32(w[t-15],18)^(w[t-15]>>3);
            uint s1=rotr32(w[t-2],17)^rotr32(w[t-2],19)^(w[t-2]>>10);
            w[t]=w[t-16]+s0+w[t-7]+s1;
        }
        uint a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int t=0;t<64;t++){
            uint S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
            uint ch=(e&f)^((~e)&g);
            uint t1=hh+S1+ch+SHA_K[t]+w[t];
            uint S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
            uint maj=(a&b)^(a&c)^(b&c);
            uint t2=S0+maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i=0;i<8;i++){
        out[4*i]  =(uchar)(h[i]>>24); out[4*i+1]=(uchar)(h[i]>>16);
        out[4*i+2]=(uchar)(h[i]>>8);  out[4*i+3]=(uchar)h[i];
    }
}

/* ------------------------------------------------------------- AES-256 */
__constant uchar SBOX[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

__constant uchar INV_SBOX[256]={
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d };

inline uchar xtime(uchar x){ return (uchar)((x<<1) ^ (((x>>7)&1)*0x1b)); }
inline uchar gmul(uchar a, uchar b){
    uchar r=0;
    for (int i=0;i<8;i++){ if(b&1) r^=a; b>>=1; a=xtime(a); }
    return r;
}

/* Expansão de chave AES-256: key[32] -> rk[240] (15 subchaves de 16B). */
void aes256_expand(const uchar *key, uchar *rk){
    for (int i=0;i<32;i++) rk[i]=key[i];
    uchar rcon=1;
    for (int i=8;i<60;i++){
        uchar t0=rk[(i-1)*4+0], t1=rk[(i-1)*4+1], t2=rk[(i-1)*4+2], t3=rk[(i-1)*4+3];
        if (i%8==0){
            uchar u0=SBOX[t1], u1=SBOX[t2], u2=SBOX[t3], u3=SBOX[t0];
            t0=u0^rcon; t1=u1; t2=u2; t3=u3;
            rcon=xtime(rcon);
        } else if (i%8==4){
            t0=SBOX[t0]; t1=SBOX[t1]; t2=SBOX[t2]; t3=SBOX[t3];
        }
        rk[i*4+0]=rk[(i-8)*4+0]^t0;
        rk[i*4+1]=rk[(i-8)*4+1]^t1;
        rk[i*4+2]=rk[(i-8)*4+2]^t2;
        rk[i*4+3]=rk[(i-8)*4+3]^t3;
    }
}

/* Decifra 1 bloco (InvCipher aritmético). state[i] com i=linha+4*coluna.
 * gmul é ALU puro: mais rápido que T-tables em __constant nesta GPU (acesso
 * divergente a tabela grande serializa o warp). */
void aes256_decrypt_block(const uchar *rk, const uchar *in, uchar *out){
    uchar s[16], tmp[16];
    for (int i=0;i<16;i++) s[i]=in[i]^rk[14*16+i];       /* AddRoundKey Nr */
    for (int round=13; round>=1; round--){
        for (int r=0;r<4;r++)                             /* InvShiftRows */
            for (int c=0;c<4;c++)
                tmp[r+4*((c+r)&3)] = s[r+4*c];
        for (int i=0;i<16;i++) s[i]=INV_SBOX[tmp[i]];    /* InvSubBytes */
        for (int i=0;i<16;i++) s[i]^=rk[round*16+i];     /* AddRoundKey */
        for (int c=0;c<4;c++){                            /* InvMixColumns */
            uchar a0=s[4*c],a1=s[4*c+1],a2=s[4*c+2],a3=s[4*c+3];
            s[4*c]  =gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9);
            s[4*c+1]=gmul(a0,9) ^gmul(a1,14)^gmul(a2,11)^gmul(a3,13);
            s[4*c+2]=gmul(a0,13)^gmul(a1,9) ^gmul(a2,14)^gmul(a3,11);
            s[4*c+3]=gmul(a0,11)^gmul(a1,13)^gmul(a2,9) ^gmul(a3,14);
        }
    }
    for (int r=0;r<4;r++)                                 /* round 0 sem InvMixColumns */
        for (int c=0;c<4;c++)
            tmp[r+4*((c+r)&3)] = s[r+4*c];
    for (int i=0;i<16;i++) s[i]=INV_SBOX[tmp[i]];
    for (int i=0;i<16;i++) out[i]=s[i]^rk[0*16+i];
}

/* ------------------------------------------------------------- Lehmer + senha */
/* TTI: índice 0..15 do tipo de token em cada uma das 64 posições (embutido). */
__constant uchar TTI[64] = { TTI_VALUES };
__constant uchar HEXC[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

void lehmer(ulong index, uchar *perm){
    uchar el[16];
    for (int i=0;i<16;i++) el[i]=(uchar)i;
    ulong fact[16];
    fact[0]=1;
    for (int i=1;i<16;i++) fact[i]=fact[i-1]*(ulong)i;
    int cnt=16, k=0;
    for (int i=15;i>=0;i--){
        ulong f=fact[i];
        uint d=(uint)(index/f);
        index -= (ulong)d*f;
        perm[k++]=el[d];
        for (int j=d;j<cnt-1;j++) el[j]=el[j+1];
        cnt--;
    }
}

void build_password(ulong index, uchar *pw){
    uchar perm[16];
    lehmer(index, perm);
    for (int j=0;j<64;j++) pw[j]=HEXC[perm[TTI[j]]];
}

/* key/iv a partir da senha, e as 3 decifras. salt e ct em __global. */
void crypt_core(ulong index, __global const uchar *salt, __global const uchar *ct,
                uchar *key, uchar *iv, uchar *P0, uchar *P3, uchar *P4){
    uchar pw[64];
    build_password(index, pw);
    uchar buf[104];
    /* key = SHA256(pw||salt) */
    for (int i=0;i<64;i++) buf[i]=pw[i];
    for (int i=0;i<8;i++)  buf[64+i]=salt[i];
    sha256_2block(buf, 72, key);
    /* iv = SHA256(key||pw||salt)[:16] */
    uchar ivfull[32];
    for (int i=0;i<32;i++) buf[i]=key[i];
    for (int i=0;i<64;i++) buf[32+i]=pw[i];
    for (int i=0;i<8;i++)  buf[96+i]=salt[i];
    sha256_2block(buf, 104, ivfull);
    for (int i=0;i<16;i++) iv[i]=ivfull[i];
    /* AES */
    uchar rk[240];
    aes256_expand(key, rk);
    uchar c0[16], c3[16], c4[16], d[16];
    for (int i=0;i<16;i++){ c0[i]=ct[i]; c3[i]=ct[48+i]; c4[i]=ct[64+i]; }
    aes256_decrypt_block(rk, c0, d); for (int i=0;i<16;i++) P0[i]=d[i]^iv[i];
    aes256_decrypt_block(rk, c3, d); for (int i=0;i<16;i++) P3[i]=d[i]^ct[32+i];
    aes256_decrypt_block(rk, c4, d); for (int i=0;i<16;i++) P4[i]=d[i]^ct[48+i];
}

inline int is_txt(uchar b){
    return (b>=0x20 && b<=0x7e) || b==0x09 || b==0x0a || b==0x0d;
}

/* ------------------------------------------------------------- kernels */
/* Debug: para cada índice, escreve key(32)+iv(16)+P0(16)+P3(16)+P4(16)=96B. */
__kernel void k_debug(__global const ulong *indices, uint n,
                      __global const uchar *salt, __global const uchar *ct,
                      __global uchar *out){
    int gid=get_global_id(0);
    if (gid>=n) return;
    uchar key[32], iv[16], P0[16], P3[16], P4[16];
    crypt_core(indices[gid], salt, ct, key, iv, P0, P3, P4);
    __global uchar *o = out + (ulong)gid*96;
    for (int i=0;i<32;i++) o[i]=key[i];
    for (int i=0;i<16;i++) o[32+i]=iv[i];
    for (int i=0;i<16;i++) o[48+i]=P0[i];
    for (int i=0;i<16;i++) o[64+i]=P3[i];
    for (int i=0;i<16;i++) o[80+i]=P4[i];
}

/* Scan: percorre [base, base+count) e grava índices sobreviventes. */
__kernel void k_scan(ulong base, ulong count,
                     __global const uchar *salt, __global const uchar *ct,
                     __global ulong *out_idx, __global uint *out_cnt,
                     uint cap, __global int *overflow){
    ulong gid=get_global_id(0);
    if (gid>=count) return;
    ulong index=base+gid;
    uchar key[32], iv[16], P0[16], P3[16], P4[16];
    crypt_core(index, salt, ct, key, iv, P0, P3, P4);

    int surv=0;
    if (P0[0]==0x53&&P0[1]==0x61&&P0[2]==0x6c&&P0[3]==0x74&&
        P0[4]==0x65&&P0[5]==0x64&&P0[6]==0x5f&&P0[7]==0x5f){
        surv=1;                                   /* (a) blob aninhado "Salted__" */
    } else {
        uchar n=P4[15];
        if (n>=1 && n<=16){
            int okpad=1;
            for (int i=0;i<n;i++) if (P4[15-i]!=n){ okpad=0; break; }
            if (okpad){
                int okp=1;
                for (int i=0;i<16 && okp;i++) if(!is_txt(P3[i])) okp=0;
                for (int i=0;i<16-n && okp;i++) if(!is_txt(P4[i])) okp=0;
                if (okp) surv=1;                  /* (b) PKCS7 + imprimível */
            }
        }
    }
    if (surv){
        uint slot=atomic_inc(out_cnt);
        if (slot<cap) out_idx[slot]=index;
        else atomic_or(overflow, 1);
    }
}
