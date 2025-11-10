import argparse, base64, json, os, sys, hashlib, getpass
from typing import Tuple
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

MAGIC_SIM = b"SIM1"

def _read_all(p: str) -> bytes:
    with open(p, "rb") as f:
        return f.read()

def _write_all(p: str, data: bytes) -> None:
    with open(p, "wb") as f:
        f.write(data)

def gen_sym_key(out_path: str):
    key = AESGCM.generate_key(bit_length=256)
    obj = {"kty":"oct", "k": base64.urlsafe_b64encode(key).decode("ascii")}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    print(f"[OK] Chave simétrica salva em {out_path}")

def load_sym_key(path: str) -> bytes:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    return base64.urlsafe_b64decode(obj["k"].encode("ascii"))

def enc_sym(key_path: str, in_path: str, out_path: str):
    key = load_sym_key(key_path)
    data = _read_all(in_path)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data, None)
    blob = MAGIC_SIM + nonce + ct
    _write_all(out_path, blob)
    print(f"[OK] {in_path} -> {out_path}")

def dec_sym(key_path: str, in_path: str, out_path: str):
    key = load_sym_key(key_path)
    blob = _read_all(in_path)
    if not blob.startswith(MAGIC_SIM) or len(blob) < 4+12+16:
        raise ValueError("Arquivo .sim inválido")
    nonce = blob[4:16]
    ct = blob[16:]
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    _write_all(out_path, pt)
    print(f"[OK] {in_path} -> {out_path}")

def gen_keypair(priv_path: str, pub_path: str, passphrase: str = None):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    encryption_algorithm = serialization.NoEncryption()
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    pem_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _write_all(priv_path, pem_priv)
    _write_all(pub_path, pem_pub)
    print(f"[OK] Privada: {priv_path} | Pública: {pub_path}")

def _load_pub(path: str):
    return serialization.load_pem_public_key(_read_all(path), backend=default_backend())

def _load_priv(path: str, passphrase: str = None):
    pwd = passphrase.encode("utf-8") if passphrase else None
    return serialization.load_pem_private_key(_read_all(path), password=pwd, backend=default_backend())

def enc_asym(pub_path: str, in_path: str, out_path: str):
    data = _read_all(in_path)
    eph_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(eph_key).encrypt(nonce, data, None)
    pub = _load_pub(pub_path)
    ekey = pub.encrypt(
        eph_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    obj = {
        "v":"ASI1",
        "kdf":"RSA-OAEP-SHA256",
        "ekey": base64.b64encode(ekey).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    print(f"[OK] {in_path} -> {out_path}")

def dec_asym(priv_path: str, in_path: str, out_path: str, passphrase: str = None):
    obj = json.loads(Path(in_path).read_text(encoding="utf-8"))
    if obj.get("v") != "ASI1":
        raise ValueError("Arquivo .asi inválido")
    priv = _load_priv(priv_path, passphrase)
    eph_key = priv.decrypt(
        base64.b64decode(obj["ekey"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    nonce = base64.b64decode(obj["nonce"])
    ct = base64.b64decode(obj["ct"])
    pt = AESGCM(eph_key).decrypt(nonce, ct, None)
    _write_all(out_path, pt)
    print(f"[OK] {in_path} -> {out_path}")

def do_hash(in_path: str, out_path: str, algo: str = "sha256"):
    h = hashlib.new(algo)
    with open(in_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    line = f"{algo.upper()}:{h.hexdigest()}"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(line + "\n")
    print(f"[OK] {in_path} -> {out_path} ({algo.upper()})")

def main(argv=None):
    p = argparse.ArgumentParser(prog="securefilekit", description="Criptografia (simétrica/assimétrica) e hash para arquivos.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("gen-sym-key", help="Gera chave simétrica (AES‑256)")
    s1.add_argument("--out", required=True)

    s2 = sub.add_parser("gen-keypair", help="Gera par RSA‑4096 (PEM)")
    s2.add_argument("--private", required=True)
    s2.add_argument("--public", required=True)
    s2.add_argument("--passphrase", required=False, help="Opcional: protege a privada")

    s3 = sub.add_parser("enc-sym", help="Criptografa (AES‑GCM) -> .sim")
    s3.add_argument("--key", required=True)
    s3.add_argument("--in", dest="inp", required=True)
    s3.add_argument("--out", required=True)

    s4 = sub.add_parser("dec-sym", help="Decriptografa .sim")
    s4.add_argument("--key", required=True)
    s4.add_argument("--in", dest="inp", required=True)
    s4.add_argument("--out", required=True)

    s5 = sub.add_parser("enc-asym", help="Criptografa (RSA‑OAEP + AES‑GCM) -> .asi")
    s5.add_argument("--pub", required=True)
    s5.add_argument("--in", dest="inp", required=True)
    s5.add_argument("--out", required=True)

    s6 = sub.add_parser("dec-asym", help="Decriptografa .asi")
    s6.add_argument("--priv", required=True)
    s6.add_argument("--in", dest="inp", required=True)
    s6.add_argument("--out", required=True)
    s6.add_argument("--passphrase", required=False)

    s7 = sub.add_parser("hash", help="Gera hash (.has)")
    s7.add_argument("--in", dest="inp", required=True)
    s7.add_argument("--out", required=True)
    s7.add_argument("--algo", default="sha256")

    args = p.parse_args(argv)

    if args.cmd == "gen-sym-key":
        gen_sym_key(args.out)
    elif args.cmd == "gen-keypair":
        gen_keypair(args.private, args.public, args.passphrase)
    elif args.cmd == "enc-sym":
        enc_sym(args.key, args.inp, args.out)
    elif args.cmd == "dec-sym":
        dec_sym(args.key, args.inp, args.out)
    elif args.cmd == "enc-asym":
        enc_asym(args.pub, args.inp, args.out)
    elif args.cmd == "dec-asym":
        dec_asym(args.priv, args.inp, args.out, args.passphrase)
    elif args.cmd == "hash":
        do_hash(args.inp, args.out, args.algo)
    else:
        p.error("Comando inválido")

if __name__ == "__main__":
    main()
