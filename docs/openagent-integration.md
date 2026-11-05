# OpenAgent 平台对接指南（Audit 数据接入）

> 读者：OpenAgent 平台的开发/运维人员。读完本文即可知道：OpenAgent 的会话数据
> 如何进入审计平台、用户身份如何打通、有哪些接口可以调用、如何验收。
>
> 术语：本仓库（OpenAgent.Audit）以下简称 **audit 平台**。

---

## 0. 总览：数据怎么流、谁跟谁通信

```
┌─────────────────────────── OpenAgent 平台 ───────────────────────────┐
│  用户/权限体系        业务会话库（自有 Postgres，存完整明文）          │
└──────┬──────────────────────────┬────────────────────────────────────┘
       │ ①身份：token 内省          │  业务存储不动，双方只以 conversation id 关联
       ▼                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│ OpenAgent Agent 进程（唯一的数据出入口，部署在 OpenAgent 侧）           │
│  • attach_openagent() 一行接入（文本/媒体/标识符全在此处理）            │
│  • 明文只存在于本进程内存；出进程前必然已脱敏                          │
└───┬──────────────┬───────────────────┬───────────────────────────────┘
    │② trace       │③ 加密媒体直传       │④ 服务日志/审计事件副本
    ▼              ▼                   ▼
 Langfuse        S3 对象存储          Loki（仅告警）
 (trace 主数据)   (SeaweedFS/MinIO)     │
    │              │                   │
    └──────┬───────┴───────────────────┘
           ▼
┌────────────────── audit 平台（本仓库）───────────────────────────────┐
│ audit-api/audit-web（掩码浏览、检索、还原审批）                        │
│ decrypt-svc（唯一能解密，独立部署） · 审计域 Postgres（密文+审计日志）   │
│ 前端 Vue3 SPA（frontend/，参考实现）                                  │
└──────────────────────────────────────────────────────────────────────┘
```

三条**硬性边界**（改不了、也不要绕）：

1. **trace 唯一通道是 Langfuse Python SDK**。audit 平台不提供 REST 明文上报——
   任何"再开一个上报接口"都会重新打开明文旁路，属设计禁止。
2. **audit 平台不是业务数据源**。会话业务存储（会话恢复/续聊）留在 OpenAgent
   平台自有库中，audit 平台只承载审计与观测数据（append-only）。
3. **OpenAgent 侧只拿公钥**。私钥只在 audit 平台的 decrypt-svc（或 KMS）。

---

## 1. 身份打通（用户数据接口）

audit 平台**不维护用户表**。OpenAgent 平台是用户/角色的唯一来源。

### 1.1 角色模型（固定三种，权限矩阵不可变）

| 审计角色 | 对应权限 | 典型人群 |
|---|---|---|
| `auditor` 审计员 | 掩码会话浏览、审计日志查看 | 合规抽查人员 |
| `compliance_lead` 合规主管 | 上述 + 还原申请/审批/查看原文 | 争议处理、安全调查 |
| `developer` 开发者（只读管理员） | 全站只读（会话/还原/审计日志）+ 运行指标；**无任何写/批/还原操作** | 平台开发/运维 |

OpenAgent 侧负责把自己的用户映射到这三种角色（如：合规部→compliance_lead）。
注意：`developer` 虽可读全部掩码数据，但解密仍只能走合规主管的四眼审批流，
只读权限在结构上无法绕过。

### 1.2 对接方式：OpenAgent 实现 Token 内省（introspection）端点

OpenAgent 平台需暴露一个 HTTP 端点，audit 平台用它把访问令牌解析成身份：

```
请求
  GET {AUDIT_AUTH_INTROSPECT_URL}
  Authorization: Bearer <访问令牌>          # OpenAgent 平台下发的审计访问令牌

响应（三种之一）
  200 {"username": "zhang.san", "role": "compliance_lead"}   # 成功
  401 / 403                                                  # 令牌无效或无审计权限
  （非 200 一律按未认证处理；introspect 服务不可用时同样 fail-closed）
```

要求：
- 响应 `role` 必须是上表三个值之一，其他值会被拒绝；
- 令牌建议短期有效、可撤销（审计平台有 60s 结果缓存，撤销最迟约 1 分钟生效）；
- `username` 用工号/账号名，**不要**用手机号、身份证号（它们属于被审计的敏感数据，
  不应出现在身份字段里）。

### 1.3 audit 平台侧配置（零代码改动）

```bash
AUDIT_AUTH_PROVIDER=http
AUDIT_AUTH_INTROSPECT_URL=https://openagent.example.com/api/audit/token-introspect
AUDIT_AUTH_CACHE_SECONDS=60
```

代码位置：`src/openagent_audit/services/auth.py`（`HttpIntrospectionAuthenticator`）。
开发/演示环境用 `AUDIT_AUTH_PROVIDER=static` + `AUDIT_USERS=令牌:用户名:角色,...`。

### 1.4 权限不足时的行为

被拒绝的请求返回 `403`，报文为可读的专业提示（含角色、缺失权限、处理建议），
例如开发者访问会话数据时：

```
权限不足：当前角色「开发者」（developer）未被授予「审计会话查看（掩码视图）」
权限（view_masked）。如需相应访问能力，请联系系统管理员调整角色授权。
```

---

## 2. 会话数据接入（OpenAgent → audit 平台）

### 2.0 .NET 后端接入方式（OpenAgent 实际形态，推荐）

OpenAgent 后端是 .NET 8（Router → Engine.Host → Core），无法内嵌 Langfuse
Python SDK。audit 平台为此提供 **Masking Gateway**（OTLP 脱敏网关）：
OpenAgent 侧指向网关，业务代码零改动。

```text
OpenAgent (OTEL_EXPORTER_OTLP_ENDPOINT=http://masking-gateway:8102
           OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer <AUDIT_GATEWAY_TOKEN>")
   │  OTLP（http/protobuf 默认、http/json、或 gRPC 帧）
   ▼
Masking Gateway（audit 平台组件，同集群部署）
   ① 解析 OTLP 三种传输形态 → 对内容属性跑与 Python 路径完全相同的 PII 管线
      （识别 → ⟦TYPE#编号|掩码⟧ + AES-256-GCM 信封加密 → 密文写密文表）
   ② 从 span 属性映射标识符：conversation_id→langfuse.session.id、
      user_id→langfuse.user.id、agent_id→langfuse.tag.agent
   ③ 统一重编码为 OTLP/JSON 转发 Langfuse 原生端点（/api/public/otel/v1/traces）
   ④ fail-closed：脱敏/密文入库失败 → 整批丢弃、绝不转发、计数告警
```

**网关接受的传输形态**（不必先把 OpenAgent 侧改成 JSON）：

| OpenAgent exporter 设置 | 落到网关的路由 | 说明 |
|---|---|---|
| `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`（**ASP.NET Core 默认**） | `POST /v1/traces` | 用 `opentelemetry-proto` 解码；镜像已装 `[otlp]` extra |
| `OTEL_EXPORTER_OTLP_PROTOCOL=http/json` | `POST /v1/traces` | 原生处理 |
| endpoint 写成 `...:8102/v1/traces` | `POST /v1/traces/v1/traces` | 兼容 SDK 自动追加信号路径 |
| `OTEL_EXPORTER_OTLP_PROTOCOL=grpc` | `POST /opentelemetry.proto.collector.trace.v1.TraceService/Export` | 解 5 字节帧头；压缩帧拒绝 |

网关侧配置（docker-compose 已内置 `masking-gateway` 服务）：

| 变量 | 说明 |
|---|---|
| `AUDIT_GATEWAY_TOKEN` | OpenAgent → 网关的令牌（必填）；compose 设 `AUDIT_GATEWAY_REQUIRE_AUTH=true`，留空时网关拒绝全部请求而不是静默放行 |
| `AUDIT_GATEWAY_CONTENT_PREFIXES` | 需要脱敏的 span 属性键前缀（逗号分隔，默认覆盖 gen_ai.*/llm.*/content 等） |
| `AUDIT_GATEWAY_SESSION_ATTRS` / `_USER_ATTRS` / `_AGENT_ATTRS` | 标识符属性候选键（默认已覆盖 openagent.conversation_id / user_id / agent.id） |
| `OPENAGENT_APP_NETWORK` | 网关加入的 OpenAgent 应用网络名（默认 `openagent`），须等于平台的 `OPENAGENT_APP_NETWORK` |

令牌两种写法都接受：`Authorization: Bearer <token>`（推荐）或
`x-api-key: <token>`；比较使用常量时间，避免时序侧信道。

OpenAgent 侧配置（环境变量，或 `appsettings.json` 的 `OpenTelemetry:OtlpEndpoint`）：

```bash
OPENAGENT_OTLP_ENDPOINT=http://masking-gateway:8102
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <AUDIT_GATEWAY_TOKEN>
```

信任边界说明：明文 span 会经网络到达网关（同集群、同信任域，与明文进入
Langfuse worker 的假设等价），网关内存处理不落盘、令牌认证、fail-closed。
这是对技术方案“进程内脱敏”的一处明示偏差，仅适用于非 Python Agent。

**网络拓扑**：网关同时挂在 audit 网络与 OpenAgent 应用网络上，平台侧用服务名
`masking-gateway:8102` 直连；audit-db、Langfuse、decrypt-svc 仍只在 audit
网络内，对平台不可见。

**Python Agent 仍走原路径**（Langfuse Python SDK + mask_otel_spans 进程内
脱敏）；两条路径共享同一套 PII 管线与密文表，掩码结果完全一致。

#### 2.0.1 OpenAgent 侧仍需配合的三处改动

网关只解决“传输与脱敏”，以下三点必须由 OpenAgent 仓库补齐，否则审计视图不可用：

1. **给 span 带会话/用户标识**。网关只从 span 属性读取
   `openagent.conversation_id` / `openagent.user_id` / `agent.id`。
   OpenAgent 现在只打了 `openagent.route` 与 `openagent.agent.id`；且
   conversation id 在端点内才生成（middleware 早于它），应改用子 span 或
   执行作用域补打。缺这一项时 `langfuse.session.id` 为空 → 会话视图无法聚合，
   密文行也无法按保留期关联删除。
2. **只把 traces 发往网关**。OpenAgent 的 OTLP 配置是全局一个地址，
   traces/logs/metrics 会一起发过来；日志属 Loki 通道，不应进入审计网关，
   需支持按信号分开配置（或在 Collector 侧分流）。
3. **内省端点与审计角色**（见 1.2 / 1.3），平台目前尚未实现。

#### 2.0.2 trace_id 形态

OTLP/JSON 里 trace id 是 base64，Protobuf 里是原始字节。网关在写密文表前统一
归一为 **32 位小写 hex**——这正是保留期任务按 `trace_id` 匹配删除时使用的形态，
也与 OpenAgent 日志里的 `X-Trace-Id`/`traceparent` 一致，便于双方对账。

### 2.1 前置条件

| 组件 | 说明 |
|---|---|
| audit 平台已部署 | `docker compose --env-file .env up -d`（Langfuse 栈 + audit-db + audit-api + decrypt-svc） |
| 公钥已签发 | `python scripts/provision_keys.py`，`AUDIT_PUBLIC_KEY_PATH` 指向公钥；**私钥文件绝不下发到 OpenAgent 侧** |
| Langfuse 项目凭据 | `LANGFUSE_HOST` / `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` |
| 密文库账号 | audit-db 的 `agent_writer` 角色（对密文表仅 INSERT，由 `deploy/audit_db_init.sql` 保证） |

### 2.2 Agent 进程接入（一行装配）

```bash
pip install "openagent-audit[langfuse,postgres,s3]"
```

```python
from openagent_audit.integrations.openagent import attach_openagent

# 进程启动时装配一次（读取 AUDIT_* 环境变量，见 2.4）
instrument = attach_openagent()
```

`attach_openagent()` 帮你装好：写侧信封加密（仅公钥）、密文入库（带重试）、
PII 识别管线、Langfuse 客户端与导出线程脱敏钩子（fail-closed）、媒体加密直传、
丢弃计数监控。

### 2.3 每次用户请求的埋点（唯一需要写的代码）

```python
@app.post("/agent/run")
def agent_run(req: RunRequest):
    # ① 可选：先脱敏地记录请求（含媒体替换）
    prepared_messages, media_refs = instrument.prepare_messages(req.messages)

    # ② 业务逻辑照常：调 LLM、跑工具（明文只在进程内存里）
    answer = my_agent_logic(req.messages)

    # ③ 落 trace：会话/用户/agent 标识符一次带齐
    instrument.report_request(
        trace_id=req.request_id,              # 请求级 id，与 OpenAgent 请求 id 对齐
        conversation_id=req.conversation_id,  # → Langfuse sessionId（会话回放锚点）
        internal_user_id=req.user.internal_id,# → userId（业务内部 ID，禁用手机号/邮箱）
        agent_id="cs-bot",                    # → tags: agent:cs-bot
        name="POST /agent/run",
        messages=req.messages,                # 可含 base64 媒体 → 自动加密替换为 s3:// 引用
        llm_calls=[{                          # 每轮 LLM 调用一条 generation
            "name": "LLM 调用 #1",
            "model": "glm-4.7",
            "input": prompt_text, "output": answer_text,
            "usage": {"input": 1248, "output": 356},
            "latency_ms": 1100,
        }],
    )
    return answer
```

自研框架无需改造成 SDK 装饰器风格——上面的三个关键点（请求入口、LLM 调用、
工具调用）各打一条记录即可。

### 2.4 Agent 进程环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `AUDIT_PUBLIC_KEY_PATH` | ✅ | 公钥路径（只分发公钥） |
| `LANGFUSE_HOST` / `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | ✅ | Langfuse 项目凭据 |
| `AUDIT_DB_URL` | ✅ | `postgresql://agent_writer:***@audit-db:5432/openagent_audit` |
| `AUDIT_OBJECT_STORE` | ✅ | `s3`（生产）或 `local`（开发） |
| `AUDIT_MEDIA_BUCKET` / `AUDIT_S3_*` | S3 时 | 媒体桶与凭据 |
| `AUDIT_PII_BACKEND` | – | `rules`（内置规则，默认）或 `presidio`（中文 spaCy 模型） |

### 2.5 发生了什么（你不需要实现，但应理解）

1. **文本**：明文只在 Agent 进程内存；Langfuse 导出线程中的 `mask_otel_spans`
   钩子识别敏感实体（手机号/身份证/银行卡/邮箱/中文人名）→ 每个实体生成
   `⟦TYPE#随机编号|掩码⟧` 写进 trace，同时把 AES-256-GCM 密文写入审计域密文表。
   **钩子抛异常时整批丢弃（fail-closed），绝无明文出进程**；丢弃数进入指标，
   `dropped_batches > 0` 必须告警（`deploy/alerting/` 已内置规则）。
2. **媒体**：base64/文件先在 Agent 端公钥加密、直传对象存储，trace 里只留
   `s3://key + sha256 + mime` 引用；查看原件走与文本相同的审批流。
3. **多轮对话**：同一文本的识别结果按哈希缓存（性能），但编号与密文每次随机生成，
   无法跨会话反查关联。

### 2.6 接入验收清单

- [ ] Langfuse UI 中每条请求都有 trace，敏感值只以 `⟦TYPE#编号|掩码⟧` 出现；
- [ ] 审计域密文表有对应行且 `trace_id`/`session_id` 已填（保留期联动删除依赖它）；
- [ ] 媒体在对象存储中为密文，trace 中只有 `s3://` 引用；
- [ ] audit-web 用平台令牌登录后能看到对应会话（掩码视图），浏览有留痕；
- [ ] 压测通过：导出丢弃数为 0；`/internal/metrics` 无异常计数；
- [ ] 各实体类型在标注测试集上的召回率/精确率达到合规确认的门槛。

---

## 3. 读取与审批（OpenAgent 平台 ↔ audit-api REST）

OpenAgent 后台/工单系统要嵌审计能力时，直接调 audit-api（同一令牌体系）：

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/me` | 任意已认证 | 令牌 → {username, role}（SPA 会话引导） |
| GET | `/v1/sessions`、`/v1/sessions/{id}` | view_masked | 会话列表 / 掩码 trace（浏览写审计日志） |
| GET | `/v1/traces?user_id&session_id&from_ts&to_ts` | view_masked | 检索仅限这三个维度（无敏感值反查） |
| GET | `/v1/audit-log?verify=true` | view_audit_log | 审计日志 + 哈希链校验 |
| POST | `/v1/restore-requests` | manage_restore | 提交还原申请（必填理由） |
| POST | `/v1/restore-requests/{id}/approve` `/reject` | manage_restore | 四眼审批（申请人不能自批） |
| POST | `/v1/restore-requests/{id}/reveal` | manage_restore | 查看原文（TTL 内，默认 5 分钟，全程留痕） |
| GET | `/internal/metrics`（`/prometheus`） | view_metrics | 运行指标（仅 developer） |

错误约定：`401` 令牌无效；`403` 权限不足（返回专业中文提示，见 1.4）；
`410` 还原查看窗口过期（需重新申请审批）。

前端 `frontend/`（Vue3 + Tailwind）即这组接口的完整参考实现，可整站内嵌
（iframe 或改造）进 OpenAgent 平台。

## 4. 常见问题

**Q：为什么不能直接把明文会话 POST 给 audit 平台？**
写入侧的脱敏是强制环节：Python Agent 在进程内脱敏，.NET Agent 经 Masking
Gateway 在转发前脱敏。任何绕过这条管线直灌 Langfuse 的通道都不允许。

**Q：接入后，本地的演示数据（sess-demo-*）会混进生产视图吗？**
不会。演示数据仅在 `AUDIT_DEMO_SEED=1` 且本地存储为空时注入一次；一旦存在任何
真实会话，会话审计视图自动隐藏全部演示会话（接口返回 `demo_hidden: true`，
可用 `include_demo=true` 强制查看），生产模式（`AUDIT_TRACE_STORE=langfuse`）
根本不注入演示数据。

**Q：会话删除（用户行使删除权）怎么办？**
audit 平台保留期任务（`python -m openagent_audit.services.retention`，建议
cron/CronJob 调度）到期删除 trace 与对应密文行、归档审计日志；OpenAgent 平台
删除业务会话后，audit 侧数据随保留期自动消亡，双方以 conversation id 关联。

**Q：OpenAgent 平台自己的运维能看 Langfuse 吗？**
可以，Langfuse 里只有「编号 + 掩码 + 技术元数据」，用于排障；但无审计角色、
无还原能力，不能替代 audit-web。
