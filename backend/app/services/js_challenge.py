"""
边缘 WAF 透明 200 HTML/JS 动态令牌挑战服务（js_challenge.py）。

灵感与教学目标：
- 复刻国内商业站（如阿里云 ESA/WAF Bot 防御）经典的 `timestamp__xxxx` 动态挑战机制：
  首次请求或缺少合法令牌时不直接返回 403，而是返回 HTTP 200 的混淆 HTML/JS 挑战页，
  要求客户端在真实浏览器 DOM/JS 运行时内完成环境检查与动态摘要计算，并在 URL 拼接
  `?timestamp__1366=...` 自动重试后放行 JSON 数据。
检测什么 / 防御什么：
- 阻断仅能发起 HTTP 请求但无法解析/执行 JS 的纯协议爬虫（requests / Scrapy / curl）。
- 挑战脚本同时校验轻量浏览器环境特征（webdriver/document），并在服务端实行 60s 有效期与一次性原子消费。
安全边界：
- 本模块仅用于本地 AntiCrawl Lab 教学靶场演示，严禁用于外部站点对抗。
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Dict, Tuple

from app.cache import get_cache

WAF_PARAM_NAME = "timestamp__1366"
WAF_CHALLENGE_TTL_SECONDS = 60


def compute_waf_digest(nonce_id: str, salt: str, ts_str: str, env_tag: str) -> str:
    """计算服务端与挑战 JS 约定的 SHA-256 截断摘要。"""
    raw = f"{nonce_id}:{salt}:{ts_str}:{env_tag}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def issue_js_challenge(effective_ip: str, target_path: str) -> Tuple[str, str]:
    """
    签发一次性 WAF JS 挑战参数，并返回 (nonce_id, 混淆挑战 HTML)。
    参数存于 cache.py (`waf_chal:{nonce_id}`)，TTL=60s。
    """
    nonce_id = secrets.token_hex(8)
    salt = secrets.token_hex(6)
    ts_str = str(int(time.time()))

    cache = get_cache()
    payload = json.dumps(
        {"salt": salt, "ts": ts_str, "ip": effective_ip, "path": target_path},
        ensure_ascii=False,
    )
    cache.set(f"waf_chal:{nonce_id}", payload, ex=WAF_CHALLENGE_TTL_SECONDS)

    # 【教学声明】此处使用字符数组 + 异或偏移构造刻意混淆的挑战脚本，演示 WAF 动态参数生成过程
    xor_key = 0x2A
    encoded_nonce = [ord(c) ^ xor_key for c in nonce_id]
    encoded_salt = [ord(c) ^ xor_key for c in salt]
    encoded_param = [ord(c) ^ xor_key for c in WAF_PARAM_NAME]

    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>Security Verification · AntiCrawl Lab WAF</title>
  <style>
    body {{ background:#060a12; color:#94a3b8; font-family: ui-monospace, monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
    .box {{ border:1px solid #1e2c48; background:#0d1422; padding:2rem; border-radius:12px; max-width:480px; text-align:center; }}
    .badge {{ color:#00f5a0; font-size:0.85rem; margin-bottom:0.75rem; }}
  </style>
</head>
<body>
  <div class="box">
    <div class="badge">[ESA-STYLE JS CHALLENGE · {WAF_PARAM_NAME}]</div>
    <p>正在验证浏览器执行环境并计算一次性动态访问令牌，请稍候...</p>
    <p id="status" style="font-size:12px;color:#00d9f5;">Computing SHA-256 challenge...</p>
  </div>
  <script>
  (function(_0xK,_0xN,_0xS,_0xP){{
    function _dec(arr){{return arr.map(function(c){{return String.fromCharCode(c^_0xK);}}).join('');}}
    function _sha256(str){{
      var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
      var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
      var bytes=new TextEncoder().encode(str),bitLen=bytes.length*8,pLen=Math.ceil((bytes.length+9)/64)*64;
      var pad=new Uint8Array(pLen);pad.set(bytes);pad[bytes.length]=0x80;
      var dv=new DataView(pad.buffer);dv.setUint32(pLen-4,bitLen>>>0,false);dv.setUint32(pLen-8,Math.floor(bitLen/4294967296),false);
      var w=new Uint32Array(64);function rotr(x,n){{return(x>>>n)|(x<<(32-n));}}
      for(var off=0;off<pLen;off+=64){{
        for(var i=0;i<16;i++)w[i]=dv.getUint32(off+i*4,false);
        for(var i=16;i<64;i++){{var s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);var s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;}}
        var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for(var i=0;i<64;i++){{
          var S1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^(~e&g),t1=(h+S1+ch+K[i]+w[i])>>>0;
          var S0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&b)^(a&c)^(b&c),t2=(S0+maj)>>>0;
          h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
        }}
        H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
        H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
      }}
      return Array.from(H).map(function(v){{return ('00000000'+v.toString(16)).slice(-8);}}).join('');
    }}
    var nid=_dec(_0xN),slt=_dec(_0xS),pm=_dec(_0xP),ts='{ts_str}';
    var envTag=(typeof document!=='undefined'&&navigator&&navigator.webdriver===true)?'wd1':'dom1';
    var sig=_sha256(nid+':'+slt+':'+ts+':'+envTag).slice(0,24);
    var token=nid+'-'+ts+'-'+sig+'-'+envTag;
    var u=new URL(window.location.href);
    u.searchParams.set(pm,token);
    document.getElementById('status').textContent='Token ready: '+token.slice(0,22)+'... redirecting';
    window.setTimeout(function(){{window.location.replace(u.toString());}},120);
  }})({xor_key},{json.dumps(encoded_nonce)},{json.dumps(encoded_salt)},{json.dumps(encoded_param)});
  </script>
</body>
</html>"""
    return nonce_id, html


def verify_js_challenge_token(token: str, effective_ip: str) -> Dict[str, Any]:
    """
    校验并一次性消费 `timestamp__1366` 令牌。
    格式：`{nonce_id}-{ts}-{digest24}-{env_tag}`（亦兼容省略 `-{env_tag}` 默认 `dom1`）。
    """
    if not token:
        return {"ok": False, "reason": "missing_token"}

    parts = token.strip().split("-")
    if len(parts) not in (3, 4):
        return {"ok": False, "reason": "malformed_token"}

    nonce_id = parts[0]
    ts_str = parts[1]
    digest = parts[2]
    env_tag = parts[3] if len(parts) == 4 else "dom1"

    if env_tag not in {"dom1", "wd1"}:
        return {"ok": False, "reason": "invalid_env_tag"}

    cache = get_cache()
    raw = cache.get(f"waf_chal:{nonce_id}")
    if not raw:
        return {"ok": False, "reason": "challenge_expired_or_reused"}

    try:
        stored = json.loads(raw)
        salt = str(stored["salt"])
        issued_ts = str(stored["ts"])
    except Exception:
        return {"ok": False, "reason": "corrupted_challenge"}

    if ts_str != issued_ts:
        return {"ok": False, "reason": "timestamp_mismatch"}

    try:
        if abs(int(time.time()) - int(ts_str)) > WAF_CHALLENGE_TTL_SECONDS:
            return {"ok": False, "reason": "challenge_expired"}
    except ValueError:
        return {"ok": False, "reason": "invalid_ts"}

    expected = compute_waf_digest(nonce_id, salt, ts_str, env_tag)
    if not secrets.compare_digest(digest.lower(), expected.lower()):
        return {"ok": False, "reason": "signature_mismatch"}

    # 一次性原子消费，防止同一 timestamp__1366 被爬虫脚本复用重放
    cache.delete(f"waf_chal:{nonce_id}")
    solved_ms = max(1, (int(time.time()) - int(ts_str)) * 1000)
    return {
        "ok": True,
        "nonce_id": nonce_id,
        "env_tag": env_tag,
        "ip": effective_ip,
        "solved_in_ms": solved_ms,
    }
