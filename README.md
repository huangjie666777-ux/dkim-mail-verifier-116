# DKIM Mail Verifier

纯后端 DKIM 邮件验签服务（RFC 6376 子集）。接收原始 `.eml` 字节，逐条返回每个
`DKIM-Signature` 的验签结论。不收发邮件、不联网查钥、不存储邮件，请求之间互不干扰。

## 支持范围

- 仅接受 **CRLF** 换行的邮件（出现裸 LF / 裸 CR 返回 400）
- `v=1`、`a=rsa-sha256`
- 头部/正文规范化：`simple`、`relaxed`，`c=` 缺省为 `simple/simple`
- 正文摘要 `bh` 按**传输字节**计算，不解码 MIME；正确处理空正文、尾部空行与空白规范化
- 按 `h=` 从头部**底部向上**逐次选取同名字段，每个字段只消费一次；允许超额列出缺失字段；
  `h=` 必须覆盖 `From`
- 验签时**仅清空当前 DKIM-Signature 的 `b=` 值**，其余字节原样参与，不重建邮件
- RSA PKCS#1 v1.5 + SHA-256 验签；不会仅凭正文摘要匹配就判通过
- 明确拒绝：`l=` 部分正文签名、重复/非法标签、不支持的版本/算法/规范化、未知域名或 selector

## 目录结构

```
app/
  parser.py        # 原始字节解析：保留头部顺序、折行、重复项；强制 CRLF
  canonicalize.py  # simple / relaxed 头部与正文规范化
  dkim.py          # DKIM-Signature 标签解析、h= 选头、单条验签流程
  keystore.py      # 本地 JSON 公钥库（域名 -> selector -> RSA 公钥 PEM）
  crypto.py        # RSA PKCS#1 v1.5 + SHA-256 验签原语
  main.py          # FastAPI HTTP 层（限制、错误码、逐条结果）
scripts/
  dkim_signer.py   # 演示/测试用签名工具（复用验证端逻辑）
  make_demo.py     # 生成演示密钥、公钥库与样例邮件
tests/             # pytest 测试（27 个用例）
keys/keys.json     # 公钥库（由 make_demo.py 生成）
demo/              # valid.eml / tampered.eml（由 make_demo.py 生成）
```

## 安装与启动

```bash
python3.10 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/make_demo.py          # 生成 keys/keys.json 与 demo/*.eml
.venv/bin/python -m uvicorn app.main:app --port 8376
```

## 接口

### `POST /verify`

请求体为原始 `.eml` 字节（建议 `Content-Type: message/rfc822`）。

响应：

```json
{
  "overall": "pass | fail | none",
  "signatures": [
    {
      "domain": "example.com",
      "selector": "s1",
      "canonicalization": "relaxed/simple",
      "signed_headers": ["received", "received", "from", "..."],
      "covered_headers": ["Received", "Received", "From", "..."],
      "body_hash_match": true,
      "result": "pass | fail | error",
      "reason": ""
    }
  ]
}
```

- 每条签名独立出结果：`pass`（验签通过）、`fail`（摘要或签名不匹配）、
  `error`（标签非法/重复、算法不支持、未知密钥等，`reason` 给出明确原因）
- 一条坏签名不阻断其他签名；`overall` 任一条 `pass` 即为 `pass`
- 邮件无 `DKIM-Signature` 时：`{"overall": "none", "signatures": [], "reason": "..."}`
- 超过签名数限制时多余签名被跳过，响应带 `note` 说明

错误码：`400`（非 CRLF、头部畸形、头部数超限等）、`413`（邮件超过大小限制）。

### `GET /health`

返回 `{"status": "ok"}`。

## 公钥库配置

默认读取 `keys/keys.json`（可用环境变量 `DKIM_KEY_STORE` 覆盖），格式：

```json
{
  "example.com": {
    "s1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
  }
}
```

域名匹配不区分大小写。未知域名、未知 selector、非法 PEM 都会在对应签名的
`reason` 中返回明确原因。

## 限制（环境变量可调）

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `DKIM_MAX_MESSAGE_BYTES` | `10485760` | 邮件最大字节数，超限 413 |
| `DKIM_MAX_HEADERS` | `500` | 头部字段数上限，超限 400 |
| `DKIM_MAX_SIGNATURES` | `20` | 每封邮件最多验签的签名条数 |
| `DKIM_KEY_STORE` | `keys/keys.json` | 公钥库路径 |

## 演示

```bash
.venv/bin/python scripts/make_demo.py
.venv/bin/python -m uvicorn app.main:app --port 8376 &

# 有效签名 -> overall: pass
curl -s -X POST --data-binary @demo/valid.eml \
  -H "Content-Type: message/rfc822" http://127.0.0.1:8376/verify | python3 -m json.tool

# 正文被篡改 -> overall: fail, body_hash_match: false
curl -s -X POST --data-binary @demo/tampered.eml \
  -H "Content-Type: message/rfc822" http://127.0.0.1:8376/verify | python3 -m json.tool
```

## 测试

```bash
.venv/bin/python -m pytest -q
```

覆盖：simple/relaxed 组合、空正文、尾部空行、正文空白规范化、篡改正文/头部、
重复与非法标签、不支持的版本/算法/规范化、`l=` 拒绝、`h=` 未覆盖 From、
未知域名/selector、多签名互不影响、无签名标识、裸 LF/CR 拒绝、
大小/头部数/签名数限制。

> 注意：`keys/demo_private.pem` 仅为本地演示生成的临时私钥（已被 .gitignore 排除），
> 请勿用于任何真实场景。
