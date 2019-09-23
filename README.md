# switch-ldn-tool

## Struct

Header: (40 Bytes + 32 Bytes Hash, 18 Words):

| Word  | Bits  | Description |
| ----  | ----  | ----------- |
| 0     |       | UNK1 Big endian |
| 1     |       | unused |
| 2     | 15-0  | UNK2 Big endian |
| 2     | 31-16 | unused |
| 3     |       | unused |
| 4-7   |       | SSID |
| 8     | 15-0  | UNK3 |
| 8     | 31-16 | Content size |
| 9     |       | aes 128 ctr nonce |
| 10-17 |       | SHA256 of action frame, should be filled with 0 when calculating |
| 18-   |       | Content |

## Encryption

```
kek = GenerateAesKek(<hardcoded keydata>, 0, 0)
hash = sha256(Header[0..32])
key = GenerateAesKey(kek, hash)

frame[10..] = aes_128_ctr(key, nonce, frame[10..])
```
