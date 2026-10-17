/* Author: WeedPeddler */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct { unsigned int rd_key[60]; int rounds; } AES_KEY;
typedef int  (*AES_setkey_fn)(const unsigned char*, int, AES_KEY*);
typedef void (*AES_fn)(const unsigned char*, unsigned char*, const AES_KEY*);

#define KEY_BYTES 32
#define KEY_BITS  256

static unsigned char* read_file(const char* p, long* n){
    FILE* f=fopen(p,"rb"); if(!f){return NULL;}
    fseek(f,0,SEEK_END); long l=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char* b=malloc(l?l:1); if(l)fread(b,1,l,f); fclose(f); *n=l; return b;
}
static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }

int main(int argc, char** argv){
    if(argc<3){ printf("usage: decrypt.exe <encrypted_file> <key_file_or_hex> [output_file]\n"); return 1; }
    const char* in=argv[1]; const char* keysrc=argv[2];
    char out[512]; if(argc>=4) strcpy(out,argv[3]); else snprintf(out,sizeof(out),"%s.dec",in);

    HMODULE h=LoadLibraryA("C:\\Windows\\System32\\cryptoss.dll");
    if(!h){printf("[-] cannot load cryptoss.dll\n");return 1;}
    AES_setkey_fn set_dec=(AES_setkey_fn)((unsigned char*)h+0x162010);
    AES_fn aes_dec=(AES_fn)((unsigned char*)h+0x161410);

    unsigned char key[KEY_BYTES];
    FILE* fk=fopen(keysrc,"r");
    if(fk){
        char line[128]={0}; fgets(line,sizeof(line),fk); fclose(fk);
        for(int i=0;i<KEY_BYTES;i++){ int a=hexval(line[2*i]),b=hexval(line[2*i+1]); if(a<0||b<0){printf("[-] bad key file\n");return 1;} key[i]=(a<<4)|b; }
    } else {
        if(strlen(keysrc)<KEY_BYTES*2){printf("[-] bad key (need 64 hex chars)\n");return 1;}
        for(int i=0;i<KEY_BYTES;i++){ int a=hexval(keysrc[2*i]),b=hexval(keysrc[2*i+1]); if(a<0||b<0){printf("[-] bad key hex\n");return 1;} key[i]=(a<<4)|b; }
    }

    AES_KEY k; set_dec(key, KEY_BITS, &k);

    long len; unsigned char* data=read_file(in,&len);
    if(!data){printf("[-] cannot read %s\n",in);return 1;}
    if(len%16!=0){printf("[-] not multiple of 16\n");return 1;}

    for(long i=0;i<len;i+=16) aes_dec(data+i,data+i,&k);

    unsigned char pad=data[len-1];
    if(pad<1||pad>16){printf("[-] bad padding\n");return 1;}
    long olen=len-pad;

    FILE* fo=fopen(out,"wb"); fwrite(data,1,olen,fo); fclose(fo);
    printf("[+] decrypted %s -> %s (%ld bytes)  [AES-256]\n", in, out, olen);
    return 0;
}
