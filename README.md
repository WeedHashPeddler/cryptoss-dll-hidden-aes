cryptoss.dll - The Crypto DLL Microsoft Never Exported

A Microsoft-signed DLL ships a complete, hidden crypto library (AES-256, RSA,
and post-quantum algorithms). It exposes only 2 boring functions. By reversing
it, I found the real AES by memory address — and can now encrypt and decrypt
any file with my own key, *with zero crypto code in my binary*.


`cryptoss.dll` ("Crypto Open Source") is a Microsoft-signed DLL in `System32`
that contains a complete OpenSSL — AES, RSA, even post-quantum algorithms.

It exports only 2 boring functions. The AES functions are **not exported**, so
`GetProcAddress` can't find them by name — that's why I located them by their
memory offset and call `base + offset` directly:

| Function              | Offset (RVA) |
|-----------------------|--------------|
| `AES_set_encrypt_key` | `0x162270`   |
| `AES_set_decrypt_key` | `0x162010`   |
| `AES_encrypt`         | `0x161a00`   |
| `AES_decrypt`         | `0x161410`   |

Call them like this — **zero crypto code in your own binary**:

```c
HMODULE h = LoadLibraryA("cryptoss.dll");
AES_setkey_fn set_enc = (AES_setkey_fn)((unsigned char*)h + 0x162270);
AES_fn       aes_enc = (AES_fn)((unsigned char*)h + 0x161a00);

AES_KEY k;
set_enc(key, 256, &k);
aes_enc(data, out, &k);
```

## Usage

```bash
encrypt.exe file.txt           # random 256-bit key, -> file.txt.enc + .key
decrypt.exe file.txt.enc <key> # -> file.txt.dec
```

**Note:** offsets are for `cryptoss.dll` v10.0.26100.9549 (tested on Windows 11 26H2, build 26300).

## Disclaimer
**For security research and education only.**
