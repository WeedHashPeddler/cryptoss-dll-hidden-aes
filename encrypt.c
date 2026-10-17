/* Author: WeedPeddler */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct { unsigned int rd_key[60]; int rounds; } AES_KEY;
typedef int  (*AES_setkey_fn)(const unsigned char*, int, AES_KEY*);
typedef void (*AES_fn)(const unsigned char*, unsigned char*, const AES_KEY*);
typedef int  (__stdcall *BCryptGenRandomFn)(void*, unsigned char*, unsigned long, unsigned long);

#define KEY_BYTES 32
#define KEY_BITS  256

static unsigned char* read_file(const char* p, long* n){
    FILE* f=fopen(p,"rb"); if(!f){return NULL;}
    fseek(f,0,SEEK_END); long l=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char* b=malloc(l?l:1); if(l)fread(b,1,l,f); fclose(f); *n=l; return b;
}

static void random_key(unsigned char* out, int n){
    HMODULE bc=LoadLibraryA("bcrypt.dll");
    BCryptGenRandomFn gen=(BCryptGenRandomFn)GetProcAddress(bc,"BCryptGenRandom");
    gen(NULL, out, n, 2);
}

int main(int argc, char** argv){
    if(argc<2){ printf("usage: encrypt.exe <input_file> [output_file]\n"); return 1; }
    const char* in = argv[1];
    char out[512]; if(argc>=3) strcpy(out,argv[2]); else snprintf(out,sizeof(out),"%s.enc",in);

    HMODULE h=LoadLibraryA("cryptoss.dll");
    if(!h){printf("[-] cannot load cryptoss.dll\n");return 1;}
    AES_setkey_fn set_enc=(AES_setkey_fn)((unsigned char*)h+0x162270);
    AES_fn aes_enc=(AES_fn)((unsigned char*)h+0x161a00);

    unsigned char key[KEY_BYTES];
    random_key(key, KEY_BYTES);

    AES_KEY k; set_enc(key, KEY_BITS, &k);

    long len; unsigned char* data=read_file(in,&len);
    if(!data){printf("[-] cannot read %s\n",in);return 1;}

    long plen=((len/16)+1)*16;
    unsigned char* buf=calloc(plen,1); memcpy(buf,data,len);
    unsigned char pad=(unsigned char)(plen-len); for(long i=len;i<plen;i++)buf[i]=pad;

    for(long i=0;i<plen;i+=16) aes_enc(buf+i,buf+i,&k);

    FILE* fo=fopen(out,"wb"); fwrite(buf,1,plen,fo); fclose(fo);

    char kf[520]; snprintf(kf,sizeof(kf),"%s.key",out);
    FILE* fk=fopen(kf,"w"); for(int i=0;i<KEY_BYTES;i++)fprintf(fk,"%02x",key[i]); fclose(fk);

    printf("[+] encrypted %s -> %s (%ld bytes)  [AES-256]\n", in, out, plen);
    printf("[+] key (64 hex): ");
    for(int i=0;i<KEY_BYTES;i++)printf("%02x",key[i]);
    printf("\n[+] key saved to %s\n", kf);
    return 0;
}
