# CIDR Policy Normalizer

基于 **Python + FastAPI + 标准库 `ipaddress`** 的 CIDR 策略规范化 API。

接收 `allow` 与 `deny` 两个 CIDR 列表，分别对 **IPv4 / IPv6** 计算集合差
**allow − deny**，返回与原策略**等价、互不重叠且数量最少**的 CIDR 集合。

- deny 前缀切穿 allow 网段时，按二叉前缀树**递归对半拆分**直到边界对齐；
- 仅当两个网段构成**完整相邻的兄弟前缀**（同一父网的左右两半）时才合并，
  借助 `ipaddress.collapse_addresses` 实现，保证最小化且不会跨边界聚合；
- 输出按 **地址族（IPv4 → IPv6）→ 网络地址 → 前缀长度** 稳定排序；
- 统计 allow / deny 的输入数量、去重后数量（按族拆分）与最终输出数量；
- 非法 CIDR（格式错误、越界前缀、主机位非零）统一返回 **HTTP 422**。

## 一条命令启动

依赖在镜像构建时安装完成，容器启动即提供服务：

```bash
docker compose up -d --build
```

服务监听宿主机 **8000** 端口（容器内固定 8000）。

健康检查：

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

交互式文档：<http://localhost:8000/docs>

## 配置

无需任何必填配置。唯一可选项是宿主机映射端口（容器内始终为 8000）：

```bash
HOST_PORT=9000 docker compose up -d --build   # 宿主机改用 9000
```

默认端口：**8000**（见 `docker-compose.yml` 的 `${HOST_PORT:-8000}:8000`）。

## API

### `POST /normalize`

请求体：

| 字段   | 类型       | 说明                                   |
| ------ | ---------- | -------------------------------------- |
| `allow` | `string[]` | 允许列表，IPv4/IPv6 可混填，可省略（默认 `[]`） |
| `deny`  | `string[]` | 拒绝列表，规则同上                     |

CIDR 规则：

- 标准 CIDR：`10.0.0.0/24`、`2001:db8::/32`；
- 裸地址按主机前缀处理：`10.0.0.1` ≡ `10.0.0.1/32`，`::1` ≡ `::1/128`；
- 主机位非零（如 `10.0.0.1/24`）视为非法，返回 422。

示例：

```bash
curl -s -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
        "deny":  ["10.0.0.128/25", "2001:db8:1::/48"]
      }'
```

响应：

```json
{
  "ipv4": ["10.0.0.0/25"],
  "ipv6": ["2001:db8::/48", "2001:db8:2::/47", "... 共 16 段 ..."],
  "stats": {
    "allow": {"input": 3, "unique": 2, "duplicates_removed": 1, "ipv4": 1, "ipv6": 1},
    "deny":  {"input": 2, "unique": 2, "duplicates_removed": 0, "ipv4": 1, "ipv6": 1},
    "output": {"ipv4": 1, "ipv6": 16, "total": 17}
  }
}
```

字段说明：

- `ipv4` / `ipv6`：allow − deny 的最小 CIDR 列表，按网络地址、前缀长度排序；
- `stats.allow` / `stats.deny`：
  - `input`：请求中的原始条目数；
  - `unique`：去重后的网络数；
  - `duplicates_removed`：被去掉的重复条目数；
  - `ipv4` / `ipv6`：去重后各地址族的网络数；
- `stats.output`：最终输出的 IPv4 / IPv6 及总网段数。

非法输入返回 422：

```bash
curl -i -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{"allow": ["10.0.0.1/24"], "deny": []}'
# HTTP/1.1 422 Unprocessable Entity
# {"detail":[{"type":"value_error","loc":["body","allow"],
#   "msg":"Value error, 10.0.0.1/24 has host bits set", ...}]}
```

### `POST /evaluate`

接收与 `/normalize` 相同的 `allow` / `deny` CIDR 列表，外加一个 `addresses`
裸地址列表，对每个地址做**最长前缀匹配**，并按 `addresses` 的原顺序逐条返回
判定结果。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `allow`     | `string[]` | 允许列表，IPv4/IPv6 可混填，可省略（默认 `[]`） |
| `deny`      | `string[]` | 拒绝列表，规则同上                     |
| `addresses` | `string[]` | 待判定的**裸 IP 地址**（不接受 CIDR 记法），顺序即返回顺序 |

匹配优先级（逐级决胜）：

1. **前缀长度最长者胜**；
2. 前缀长度相同 → **deny 胜过 allow**；
3. 仍相同（同一列表内的重复项）→ 按该列表中的**原顺序**取第一条；
4. 没有任何条目包含该地址 → `unmatched`。

示例：

```bash
curl -s -X POST http://localhost:8000/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/24", "10.0.0.0/25", "2001:db8::/32"],
        "deny":  ["10.0.0.0/25"],
        "addresses": ["10.0.0.1", "10.0.0.200", "192.0.2.1", "2001:db8::1"]
      }'
```

响应（与 `addresses` 等长、同序）：

```json
[
  {"decision": "deny",      "matched_cidr": "10.0.0.0/25", "matched_side": "deny"},
  {"decision": "allow",     "matched_cidr": "10.0.0.0/24", "matched_side": "allow"},
  {"decision": "unmatched", "matched_cidr": null,           "matched_side": null},
  {"decision": "allow",     "matched_cidr": "2001:db8::/32", "matched_side": "allow"}
]
```

字段说明：

- `decision`：`allow` / `deny` / `unmatched`；
- `matched_cidr`：获胜条目的规范 CIDR（裸地址条目规范化为主机前缀
  `10.0.0.1/32`），未匹配时为 `null`；
- `matched_side`：获胜条目来自 `allow` 还是 `deny`，未匹配时为 `null`。

非法 CIDR 或非法地址（包括给 `addresses` 传入 `10.0.0.1/24` 这样的 CIDR
记法）统一返回 **HTTP 422**。

### `POST /compare`

在**单个 `scope` CIDR** 范围内，比较 **baseline（基线）** 与
**candidate（候选）** 两组 allow/deny 策略的判定差异。两组策略各自沿用
`/evaluate` 的**最长前缀、同长度 deny 优先**规则。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `scope`     | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），限定比较区域；主机位非零返回 422 |
| `baseline`  | `object`   | 基线策略，形如 `{"allow": [...], "deny": [...]}`，省略视为两个空列表 |
| `candidate` | `object`   | 候选策略，结构同 `baseline`            |

处理过程：

1. 分别把 scope 对 baseline、candidate **递归切分为判定恒定的互不重叠
   CIDR**（只有更具体的条目边界才触发对半拆分）；
2. **叠加（求交）两侧分区**，只保留两侧判定不同的区域；
3. 对差异区域中**相邻且转换类型相同的完整兄弟网段递归合并**（转换不同的
   兄弟、不等长的相邻网段不合并）。

示例：

```bash
curl -s -X POST http://localhost:8000/compare \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "baseline":  {"allow": ["10.0.0.0/24"], "deny": []},
        "candidate": {"allow": ["10.0.0.0/25"], "deny": ["10.0.0.128/26"]}
      }'
```

响应（按 IPv4→IPv6、网络地址、前缀长度稳定排序）：

```json
{
  "differences": [
    {"cidr": "10.0.0.128/26", "baseline_decision": "allow", "candidate_decision": "deny"},
    {"cidr": "10.0.0.192/26", "baseline_decision": "allow", "candidate_decision": "unmatched"}
  ],
  "transition_counts": {
    "allow->deny": "64",
    "allow->unmatched": "64",
    "deny->allow": "0",
    "deny->unmatched": "0",
    "unmatched->allow": "0",
    "unmatched->deny": "0"
  }
}
```

字段说明：

- `differences[].cidr`：判定发生变化的互不重叠区域；
- `differences[].baseline_decision` / `candidate_decision`：该区域内
  恒定的两侧判定，取值 `allow` / `deny` / `unmatched`，二者必不相同；
- `transition_counts`：六种转换类型 `"baseline->candidate"` 各自覆盖的
  **地址数（十进制字符串）**，未出现的转换为 `"0"`；计数与
  `differences` 覆盖的地址一一对应（例如两个 `/26` 各 64 个地址）。

说明：

- 与 scope 不同地址族的条目自动忽略；等于或包含 scope 的条目在整个
  scope 上生效（例如 scope 为 `10.0.0.0/25` 时，两侧相同的
  `10.0.0.0/24` 不产生差异）；
- 两组策略完全一致（或 scope 内判定一致）时 `differences` 为空数组；
- `scope` 缺失、非法、主机位非零，或嵌套的 baseline/candidate 中存在
  非法 CIDR，统一返回 **HTTP 422**。

## 算法说明

1. **解析校验**：`ipaddress.ip_network(value, strict=True)` 严格解析；
2. **族拆分 + 输入折叠**：IPv4、IPv6 独立处理，先对 allow / deny 各自
   `collapse_addresses` 去重、去重叠、去包含；
3. **递归差集**（`app/policy.py::_diff`）：对每个 allow 网络：
   - deny 等于或包含该网络 → 整个删除；
   - deny 与其不相交 → 整段保留；
   - deny 是其严格子网（切穿）→ 拆成左右两个兄弟半区递归处理，
     被整段拒绝的半区丢弃，未触及的半区整体保留；
4. **兄弟合并**：结果再次 `collapse_addresses`，只有完整相邻兄弟前缀
   才能合并回父前缀，从而保证等价性、互不重叠与最少数量；
5. **稳定排序**：按地址族、`network_address.packed`、前缀长度排序。

`/compare` 在同一套判定规则之上另走一条路径（`app/policy.py` 中
`_decision_partition` / `_overlay_partitions` / `_merge_labelled`）：

1. 对每组策略，自 scope 起按前缀树递归：scope 上的获胜条目（最长前缀、
   同长度 deny 优先）作为继承判定，严格子网把当前节点对半切开，判定
   恒定的半区整体保留；
2. 两侧分区叠加求交（任意两个相交的对齐前缀，交集必为较细者），只保留
   `baseline_decision != candidate_decision` 的瓦片；
3. 按转换标签做**带标签的完整兄弟合并**（不动点循环）：同一父网的左右
   两半都在、且转换类型完全相同时才合并，合并后的父网段继续向上合并。

## 本地开发（不使用 Docker）

需要 Python 3.11+：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

运行测试（仅核心测试依赖标准库；API 测试需安装 fastapi、httpx、pytest）：

```bash
pip install -r requirements.txt pytest httpx
pytest -q
```

测试包含与 `ipaddress.address_exclude` 参考实现对拍的 IPv4/IPv6 随机性质
用例，验证结果的等价性与最小性。

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 应用：GET /health、POST /normalize、/evaluate、/compare
│   ├── policy.py      # 解析、递归拆分、兄弟合并、统计、最长前缀匹配、分区对比（仅 ipaddress）
│   └── schemas.py     # Pydantic 请求/响应模型与 422 校验
├── tests/
│   ├── test_policy.py # 核心算法单测 + 随机对拍（含 /compare 逐地址对拍）
│   └── test_api.py    # API 层测试（422、统计、空请求等）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
