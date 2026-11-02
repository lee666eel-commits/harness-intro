"""把 _src/content.md 加密成 index.html（邀请码＝_src/invite-code.txt）。
_src/ 不进 git：公开仓里只有密文。用法：python build.py
ponytail: 纯前端 AES-GCM＋PBKDF2，安全性取决于邀请码强度；要按人撤销权限得换成有后端的方案。
"""
import base64, json, os, pathlib
import markdown
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = pathlib.Path(__file__).parent
ITER = 310_000


def key(code: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(code.encode())


def main():
    code = (ROOT / "_src/invite-code.txt").read_text(encoding="utf-8").strip()
    md = (ROOT / "_src/content.md").read_text(encoding="utf-8")
    body = markdown.markdown(md, extensions=["tables"])
    body = body.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(key(code, salt)).encrypt(iv, body.encode(), None)
    assert AESGCM(key(code, salt)).decrypt(iv, ct, None).decode() == body  # 自检：能解回原文
    payload = base64.b64encode(salt + iv + ct).decode()
    html = (ROOT / "template.html").read_text(encoding="utf-8")
    html = html.replace("__PAYLOAD__", payload).replace("__ITER__", str(ITER))
    (ROOT / "index.html").write_text(html, encoding="utf-8")
    assert code not in html, "邀请码外泄"
    assert "策之" not in html and "白箱" not in html, "明文外泄"
    print("OK", len(html), "bytes")


if __name__ == "__main__":
    main()
