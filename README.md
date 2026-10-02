# DKIM 邮件验签服务

纯后端 DKIM（DomainKeys Identified Mail）验签服务。HTTP 接收原始 `.eml`
字节，本地读取 RSA 公钥，按 RFC 6376 子集完成验签。不收发邮件、不联网
查钥、不存储邮件。

## 功能与 RFC 子集

- 仅接受 **CRLF** 行结尾的邮件（裸 LF / 裸 CR 直接拒绝）。
- 支持 `v=1`、`rsa-sha256`、头部与正文的 `simple` / `relaxed` 规范化，
  `c` 缺省为 `simple/simple`。
- 保留头部顺序、折行与重复项；按 `h=` 从底部逐次选取同名字段，不重复
  消费；允许超额列出缺失字段；`h=` 必须覆盖 `From`。
- 头部验签时仅清空当前 DKIM-Signature 的 `b=` 值，保留其余所有字节，
  不重建邮件。
- 正文按传输字节计算 `bh`，不解码 MIME；处理空正文、尾部空行与空白
  规范化。
- 拒绝带 `l=` 的部分正文签名；使用 PKCS1v15 + SHA256 验签，**不仅凭
  正文摘要判定通过**。
- 逐条返回域名、selector、规范化模式、覆盖头部、正文摘要是否匹配及
  验签结论；坏签名不阻断其他条；无签名单独标识。
- 限制邮件大小、头部数与签名数；请求互不干扰。

不支持：`rsa-sha1`、`l=` 部分正文、`q=` 联网查钥、`z=` 复制头部、
过期时间 `x=` 校验。

## 项目结构

```
dkim_verifier/
  parser.py            # 原始邮件与 DKIM-Signature 标签解析
  canonicalization.py  # simple/relaxed 头部与正文规范化（RFC 6376 3.4）
  keys.py              # 本地 JSON 公钥存储
  verifier.py          # 验签编排
  app.py               # FastAPI HTTP 层
scripts/
  make_demo.py         # 生成演示密钥与签名邮件
tests/
  test_verifier.py     # pytest 测试套件
keys.example.json      # 公钥配置模板
```

## 环境

- Python 3.10+
- FastAPI 0.115.12、cryptography 46.0.5、uvicorn 0.34.2、pytest 8.3.5
  （已在 `.venv` 中安装）

## 配置

公钥存储为本地 JSON，域名 → selector → PEM 公钥：

```json
{
  "example.com": {
    "selector1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
  }
}
```

也接受顶层 `{"keys": {...}}` 包裹格式。未知域名或 selector 返回明确
原因。

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DKIM_KEYS_PATH` | `keys.json` | 公钥 JSON 文件路径 |
| `DKIM_MAX_MESSAGE_SIZE` | `10485760` (10 MiB) | 邮件大小上限（字节） |
| `DKIM_MAX_HEADERS` | `100` | 头部字段数上限 |
| `DKIM_MAX_SIGNATURES` | `10` | DKIM-Signature 字段数上限 |

## 运行

```bash
# 1. 生成演示密钥与签名邮件（写入 keys.json、valid.eml、tampered.eml）
.venv/bin/python scripts/make_demo.py

# 2. 启动服务
DKIM_KEYS_PATH=keys.json .venv/bin/uvicorn dkim_verifier.app:create_app \
  --factory --host 127.0.0.1 --port 8765
```

### curl 演示

有效邮件：

```bash
curl -s -X POST http://127.0.0.1:8765/verify --data-binary @valid.eml
```

```json
{
  "status": "pass",
  "signatures": [
    {
      "index": 0,
      "domain": "example.com",
      "selector": "selector1",
      "canonicalization": {"header": "simple", "body": "simple"},
      "covered_headers": ["from", "to", "subject", "date"],
      "body_hash_match": true,
      "status": "pass",
      "reason": null
    }
  ]
}
```

篡改正文后的邮件：

```bash
curl -s -X POST http://127.0.0.1:8765/verify --data-binary @tampered.eml
```

```json
{
  "status": "fail",
  "signatures": [
    {
      "index": 0,
      "domain": "example.com",
      "selector": "selector1",
      "canonicalization": {"header": "simple", "body": "simple"},
      "covered_headers": ["from", "to", "subject", "date"],
      "body_hash_match": false,
      "status": "fail",
      "reason": "body hash mismatch"
    }
  ]
}
```

无签名邮件：

```bash
curl -s -X POST http://127.0.0.1:8765/verify --data-binary @unsigned.eml
# {"status":"no_signature","signatures":[]}
```

## 接口

### `POST /verify`

- 请求体：原始 `.eml` 字节（CRLF 行结尾）。
- 响应：`200` + JSON。

顶层 `status`：

| 值 | 含义 |
| --- | --- |
| `pass` | 所有签名均通过 |
| `fail` | 至少一条签名未通过或处理出错 |
| `no_signature` | 邮件无 DKIM-Signature 字段 |
| `error` | 请求级错误（过大、裸 LF、头部/签名数超限等） |

单条签名 `status`：

| 值 | 含义 |
| --- | --- |
| `pass` | 正文摘要匹配且 RSA 验签通过 |
| `fail` | 正文摘要不匹配或 RSA 验签失败 |
| `error` | 标签非法、重复标签、未知密钥、不支持算法等 |

请求级错误返回 `413`（过大）或 `200` + `status: "error"`。

### `GET /healthz`

健康检查，返回 `{"status": "ok"}`。

## 测试

```bash
.venv/bin/python -m pytest tests/ -q
```

测试覆盖：有效 simple/relaxed 签名、空正文、尾部空行、超额 `h=` 列表、
未知标签、正文/头部篡改、未知域名/selector、重复标签、不支持算法、
缺失 `From`、`l=` 拒绝、无签名、裸 LF、头部/签名数超限、多条签名、
RFC 6376 规范化已知向量、HTTP 接口。
