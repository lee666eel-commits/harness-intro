"""把 _src/content.md 加密成 index.html（邀请码＝_src/invite-code.txt）。
_src/ 不进 git：公开仓里只有密文。用法：python build.py
ponytail: 纯前端 AES-GCM＋PBKDF2，安全性取决于邀请码强度；要按人撤销权限得换成有后端的方案。
"""
import base64, os, pathlib, re
import markdown
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = pathlib.Path(__file__).parent
ITER = 310_000


def key(code: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(code.encode())


def shape(body: str) -> str:
    """h1＋副标＋署名 → 星空信头；表格每格加 data-label（手机上转成卡片用）。"""
    m = re.match(r"\s*<h1>(.*?)</h1>\s*<p>(.*?)</p>", body, re.S)
    head = (f'<header class="head"><img class="ridge" src="assets/ridge.webp" alt="">'
            f'<div class="kicker">HARNESS · CORE</div><h1 class="g">{m[1]}</h1>'
            f'<p class="sub">{m[2]}</p><p class="by">林子策 主理　·　飞鑫 撰文</p></header>'
            f'<div class="gold-rule"></div><article class="body">')
    body = head + body[m.end():] + "</article>"

    def table(t):
        ths = [re.sub(r"<small>.*?</small>|<[^>]+>", "", h).strip()
               for h in re.findall(r"<th[^>]*>(.*?)</th>", t[0], re.S)]
        def row(r):
            i = iter(range(99))
            return re.sub(r"<td([^>]*)>", lambda c: f'<td{c[1]} data-label="{ths[next(i)]}">', r[0])
        t2 = re.sub(r"<tr>.*?</tr>", row, t[0], flags=re.S)
        cls = "cmp" if len(ths) > 2 else "plain"
        return f'<div class="table-wrap {cls}">{t2}</div>'
    return re.sub(r"<table>.*?</table>", table, body, flags=re.S)


def main():
    code = (ROOT / "_src/invite-code.txt").read_text(encoding="utf-8").strip()
    md = (ROOT / "_src/content.md").read_text(encoding="utf-8")
    body = markdown.markdown(md, extensions=["tables"])
    body = shape(body)
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
