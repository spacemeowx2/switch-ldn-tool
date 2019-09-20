# switch-ldn-tool

## Struct

Header (32Bytes):

| Word  | Bits  | Description |
| ----  | ----  | ----------- |
| 0     |       | UNK1 Big endian |
| 1     |       | unused |
| 2     | 15-0  | UNK2 Big endian |
| 2     | 31-16 | unused |
| 3     |       | unused |
| 4-5   |       | UNK3 |
| 6-7   |       | UNK4 |

Transformed Header (32Bytes):

| Word  | Description |
| ----  | ----------- |
| 0-1   | UNK1 |
| 2     | UNK2 |
| 3     | 0    |
| 4-5   | UNK3 |
| 6-7   | UNK4 |

## Encryption

```
kek = GenerateAesKek(<hardcoded keydata>, 0, 0)
hash = sha256(transformed_header)
key = GenerateAesKey(kek, hash)
```
