# SecureFileKit

Sistema de criptografia, decriptografia e hash para **qualquer tipo de arquivo** (binário ou texto).
Inclui **chave simétrica (AES‑256‑GCM)**, **chave assimétrica (RSA‑4096 + OAEP‑SHA‑256)**, **hash (SHA‑256)**,
**geração de chaves**, **CLI unificada** e **testes com pytest**.

> Extensões de saída exigidas:
> - `.sim` → saída de criptografia simétrica
> - `.asi` → saída de criptografia assimétrica
> - `.has` → arquivo contendo o hash

## Requisitos

- Python 3.9+
- Pacotes: `cryptography>=42.0`, `pytest` (somente para testes)

```bash
pip install -r requirements.txt
```

## Como usar (CLI)

```bash
python -m securefilekit --help
```

### 1) Geração de chaves

**Chave simétrica (AES‑256)**:
```bash
python -m securefilekit gen-sym-key --out key_aes.json
```

**Par de chaves RSA (4096 bits)**:
```bash
python -m securefilekit gen-keypair --private rsa_private.pem --public rsa_public.pem
```

### 2) Criptografia / Decriptografia

**Simétrica (gera `.sim`)**:
```bash
python -m securefilekit enc-sym --key key_aes.json --in arquivo.pdf --out arquivo.pdf.sim
python -m securefilekit dec-sym --key key_aes.json --in arquivo.pdf.sim --out arquivo.pdf.dec
```

**Assimétrica (gera `.asi`)** — cifra com a **pública** e decifra com a **privada**:
```bash
python -m securefilekit enc-asym --pub rsa_public.pem --in dados.bin --out dados.bin.asi
python -m securefilekit dec-asym --priv rsa_private.pem --in dados.bin.asi --out dados.bin.dec
```

### 3) Hash (gera `.has`)

```bash
python -m securefilekit hash --in video.mp4 --out video.mp4.has
```

O arquivo `.has` guarda o algoritmo e o valor hexadecimal (ex.: SHA-256).

## Formatos dos artefatos

- **.sim (binário):** `magic(4)="SIM1" | nonce(12) | ciphertext+tag` (AES‑GCM 256 bits)
- **.asi (JSON binário-safe):**
  ```json
  {
    "v":"ASI1",
    "kdf":"RSA-OAEP-SHA256",
    "ekey": "<Base64 do AES efêmero cifrado com RSA>",
    "nonce": "<Base64>",
    "ct": "<Base64 (ciphertext+tag AES-GCM)>"
  }
  ```
  > Modo *hybrid crypto*: arquivo é cifrado em AES‑GCM com chave efêmera; a chave efêmera é cifrada com RSA‑OAEP.

- **.has (texto):** `SHA256:<hex>`

## Testes

Execute:
```bash
pytest -q
```

Coberturas:
- Round‑trip simétrico (enc → dec)
- Round‑trip assimétrico (enc → dec)
- Cálculo de hash estável

## Segurança (resumo rápido)

- AES‑256‑GCM com *nonce* aleatório por arquivo
- RSA‑4096 OAEP (MGF1+SHA256) para empacotar a chave simétrica efêmera
- Sem uso de ECB, sem IV fixo, sem padding inseguro
- Arquivos de chave privada PEM **não** são criptografados por padrão; opcionalmente use `--passphrase`.

## Licença

MIT
