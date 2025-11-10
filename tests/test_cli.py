import os, json, base64, tempfile, pathlib, subprocess, sys

# Executa a CLI do pacote localmente
PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = [sys.executable, "-m", "securefilekit"]

def test_sym_roundtrip(tmp_path):
    key = tmp_path/"key.json"
    data = tmp_path/"data.bin"
    enc = tmp_path/"data.bin.sim"
    dec = tmp_path/"data.dec"

    # 1MB pseudo-rand
    data.write_bytes(os.urandom(1024*1024))

    subprocess.check_call(RUN + ["gen-sym-key", "--out", str(key)], cwd=PKG_ROOT)
    subprocess.check_call(RUN + ["enc-sym", "--key", str(key), "--in", str(data), "--out", str(enc)], cwd=PKG_ROOT)
    subprocess.check_call(RUN + ["dec-sym", "--key", str(key), "--in", str(enc), "--out", str(dec)], cwd=PKG_ROOT)

    assert data.read_bytes() == dec.read_bytes()

def test_asym_roundtrip(tmp_path):
    prv = tmp_path/"prv.pem"
    pub = tmp_path/"pub.pem"
    data = tmp_path/"d.bin"
    enc = tmp_path/"d.bin.asi"
    dec = tmp_path/"d.dec"

    data.write_bytes(os.urandom(333_333))

    subprocess.check_call(RUN + ["gen-keypair", "--private", str(prv), "--public", str(pub)], cwd=PKG_ROOT)
    subprocess.check_call(RUN + ["enc-asym", "--pub", str(pub), "--in", str(data), "--out", str(enc)], cwd=PKG_ROOT)
    subprocess.check_call(RUN + ["dec-asym", "--priv", str(prv), "--in", str(enc), "--out", str(dec)], cwd=PKG_ROOT)

    assert data.read_bytes() == dec.read_bytes()

def test_hash(tmp_path):
    f = tmp_path/"x.txt"
    f.write_text("abc", encoding="utf-8")
    has = tmp_path/"x.txt.has"
    subprocess.check_call(RUN + ["hash", "--in", str(f), "--out", str(has)], cwd=PKG_ROOT)
    line = has.read_text(encoding="utf-8").strip()
    assert line.startswith("SHA256:")
    assert line.split(":")[1] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
