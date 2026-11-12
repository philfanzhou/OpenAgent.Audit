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

### 1.1 角色模型（固定两种）

audit 平台只有两种身份，OpenAgent 侧只需要回答"这个人是谁"，不需要映射角色：

| 审计身份 | 权限 | 说明 |
|---|---|---|
| `user` 普通用户 | 浏览会话、查看脱敏内容 | **所有**平台鉴权通过的用户 |
| `admin` 管理员 | 上述 + 点击脱敏项查看原文 | 在已登录会话内输入管理员密码临时解锁 |

**关键设计**：管理员权限**不由令牌携带**。内省端点返回的任何角色声明都会被忽略，
平台用户一律是 `user`；同理 `AUDIT_USERS` 里声明非 `user` 角色会直接启动报错。
解密能力只能通过"会话内输入管理员密码"获得，因此**即使某人的平台令牌泄露，
也不等于可以解密审计数据**。

管理员解锁策略（可在 audit 侧配置）：

| 设置 | 默认 | 作用 |
|---|---|---|
| `AUDIT_ADMIN_SESSION_MINUTES` | 5 | 解锁有效期，到期自动退回普通用户 |
| `AUDIT_ADMIN_COOLDOWN_MINUTES` | 10 | 解锁结束后同账号需等待此时长才能再次登录 |

**每一次揭示都留痕**：先写 `ENTITY_REVEAL_REQUESTED`，解密成功再写 `ENTITY_REVEALED`，
记录账号、时间、实体编号以及当时登录的会话用户（`session_user`）。若日志写入失败，
**不返回明文**。日志为 append-only 哈希链，任何应用角色都无 UPDATE/DELETE 权限。

**本地测试兜底账号**：OpenAgent 尚未转发身份时，可用 `test` / `test@123456` 进入
系统，仅用于确认页面正常。它的限制是硬性的：

- 只能是普通用户，**不能**登录管理员（按钮不渲染，直接请求返回 403 并记
  `ADMIN_LOGIN_REFUSED`）；
- 登录 1 小时后自动失效（`AUDIT_TEST_SESSION_MINUTES`）；
- `AUDIT_TEST_USERNAME` / `AUDIT_TEST_PASSWORD` 留空即完全禁用；
- 该账号名不能与 `AUDIT_ADMIN_USERNAME` 相同，否则按未配置处理。

### 1.2 身份来源：复用 OpenAgent 已有的 `/me` 端点

不需要新写端点。OpenAgent Engine 已提供当前用户查询，直接用它：

```
GET {AUDIT_AUTH_INTROSPECT_URL}
Authorization: Bearer <访问令牌>

200  {
       "userId": "u-123",
       "username": "zhang.san",
       "email": "zhang.san@example.com",
       "tenantId": "corp",
       "roles": ["user"],
       "isAuthenticated": true
     }
401 / 403                     # 令牌无效
```

audit 侧按 `username` → `userName` → `name` → `userId` → `sub` → `email` 的顺序
取第一个非空值作为显示名。**响应里的 `role`/`roles` 一律忽略**：平台只能证明
"你是谁"，不能授予"能解密"。

要点：
- 非 200 一律按未认证处理；端点不可达时同样 fail-closed；
- 令牌建议短期有效、可撤销（审计平台有 60s 结果缓存，撤销最迟约 1 分钟生效）；
- 显示名用工号/账号名，**不要**用手机号、身份证号（它们属于被审计的敏感数据，
  不应出现在身份字段里）。

### 1.3 audit 平台侧配置

```bash
AUDIT_AUTH_PROVIDER=http
# 经容器网络直连 Engine，避免走外链 HTTPS 的证书问题
AUDIT_AUTH_INTROSPECT_URL=http://engine:8083/api/v1/agent/me
AUDIT_AUTH_CACHE_SECONDS=60

# 本地测试兜底账号：OpenAgent 未传身份时使用，只能是普通用户
AUDIT_TEST_USERNAME=test
AUDIT_TEST_PASSWORD=test@123456
AUDIT_TEST_SESSION_MINUTES=60
```

代码位置：`src/openagent_audit/services/auth.py`（`IdentityResolver`）。
平台不可用时用 `AUDIT_AUTH_PROVIDER=static` + `AUDIT_USERS=令牌:用户名:user,...`
把审计台跑起来（仅限本地）。

### 1.3.1 登录方式：公司 SSO（不再依赖 OpenAgent 跳转）

审计台接入**公司 SSO**（OIDC Authorization Code + PKCE），与 OpenAgent
工作台的企业登录同源。用户打开审计台登录页，点「用企业账号登录」跳转 SSO，
用域账号登录后自动回到审计台——OpenAgent 前端**不需要任何配合改动**。

审计台需要的配置（向 SSO 管理员申请）：

| 配置 | 说明 |
|---|---|
| `AUDIT_SSO_AUTHORITY` | SSO 服务地址 |
| `AUDIT_SSO_CLIENT_ID` / `AUDIT_SSO_CLIENT_SECRET` | 为审计台注册的 client |
| 回调地址 | `http://<审计台地址>/ui/login/sso/callback`（需在 SSO 登记该地址）|
| `AUDIT_SSO_STATE_SECRET` | 建议 `openssl rand -base64 32` 生成，使进行中的登录在重启后仍有效 |

审计台从 SSO 的 userinfo 端点获取 `preferred_username` 作为审计身份，
一律映射为普通用户 `user`；查看原文仍需管理员 step-up 密码。
test 测试账号保留作为 SSO 故障时的应急入口。

> 注：OpenAgent 工作台的「会话审计」跳转入口已从工作台移除。
> 数据对接（trace 推送到掩码网关）与登录无关，不受影响。
### 1.4 权限不足时的行为

被拒绝的请求返回 `403`，报文为可读的专业提示（含角色、缺失权限、处理建议），
例如普通用户尝试查看原文时：

```
权限不足：当前身份「普通用户」没有「查看原文（解密）」权限。查看原文需要管理员登录。
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

#### 2.0.4 HTTPS / 内网 CA 场景

两种接法都能用，取决于网关是否暴露到 TLS 反向代理之后：

| 接法 | 端点示例 | 说明 |
|---|---|---|
| 容器网络直连（推荐） | `http://masking-gateway:8102` | 同主机同 Docker 网络，不经代理，无 TLS 开销 |
| 经反向代理（HTTPS） | `https://agent.monolithicpower.com:444/audit-otlp` | 网关不直接发布端口时使用 |

经 HTTPS 接入时注意两点：

1. **OpenAgent 侧要能信任内网证书**。OTLP exporter 自建 HttpClient，
   默认走系统证书库；内网自签名证书会被拒绝且**导出静默失败**（服务照常健康）。
   部署侧用 `OPENAGENT_ALLOW_INSECURE_TLS=true` 放开，或把内网 CA 装进容器的
   信任库（更推荐）。
2. **audit 侧出站调用同理**。设置 `AUDIT_CA_BUNDLE` 指向公司 CA 文件；
   `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` 也认。`AUDIT_TLS_VERIFY=false`
   可完全关闭校验，但会在启动时打警告，应作为最后手段。

已用真实自签名 TLS 代理（`:444`，模拟 `agent.monolithicpower.com`）端到端验证：
未开信任开关时不崩溃、仅不转发；打开后 trace 正常入库并完成脱敏与标识映射。

**Python Agent 仍走原路径**（Langfuse Python SDK + mask_otel_spans 进程内
脱敏）；两条路径共享同一套 PII 管线与密文表，掩码结果完全一致。

#### 2.0.1 OpenAgent 侧配套改动（已完成于 OpenAgent 仓库）

以下三项由 OpenAgent 仓库实现，audit 侧不再需要绕过或兜底：

1. **span 携带会话/用户标识（已实现）**。网关从 span 属性读取
   `openagent.conversation_id` / `openagent.user_id` / `openagent.agent_id` /
   `openagent.tenant_id`。OpenAgent 在
   `AgentExecutor.CreateTurn` → `AuditActivityEnrichment.Publish` 处把这些
   坐标打到当前 Activity 上（`TurnContext.ToAuditAttributes()` 是唯一投影），
   并对不经过执行器的请求由 `RequestTelemetryMiddleware` 兜底回填。
2. **按信号分流（已实现）**。新增 `OpenTelemetry:TracesEndpoint` /
   `LogsEndpoint` / `MetricsEndpoint`：只有 traces 指向网关，
   logs/metrics 继续走 `OtlpEndpoint`。日志绝不会进入审计网关。
3. **exporter 认证头（已实现）**。`OpenTelemetry:TracesHeaders` 及标准
   `OTEL_EXPORTER_OTLP_HEADERS` / `OTEL_EXPORTER_OTLP_TRACES_HEADERS` 会被显式
   绑定；此前端点用代码赋值时 SDK 的默认 headers 读取被绕过，令牌根本发不出去。

> 审计角色映射与 token 内省端点（1.2 / 1.3）暂缓，属已知未接项目：
> 在此之前 audit 侧使用 `AUDIT_AUTH_PROVIDER=static`。

#### 2.0.2 trace_id 形态

OTLP/JSON 里 trace id 是 base64，Protobuf 里是原始字节。网关在写密文表前统一
归一为 **32 位小写 hex**——这正是保留期任务按 `trace_id` 匹配删除时使用的形态，
也与 OpenAgent 日志属性 `Properties.TraceId`（业务 `X-Trace-Id`）一致，便于双方对账。

注意 OpenAgent 的 Serilog 事件里有两个 TraceId：
`TraceId`（顶层，W3C Activity id）与 `Properties.TraceId`（业务 trace id）。
审计对账应使用 **`Properties.TraceId`**；`X-Trace-Id` 由前端带入，与网关记录的业务
trace id 同源。Promtail 已按此分别抽取为 `activity_trace_id` 与 `source_trace_id`。

#### 2.0.3 日志通道（已实测校正）

OpenAgent 的 Serilog 默认输出是**纯文本模板**，`Enrich.WithProperty` 的
ServiceName/InstanceId 与 `BeginScope` 的 TraceId/ConversationId 都不出现。
OpenAgent 仓库已把 Engine/Router 的 `appsettings.json` 改为：

```json
"Serilog": {
  "ConsoleFormat": "Json",
  "WriteTo": [ { "Name": "Console",
                 "Args": { "formatter": "Serilog.Formatting.Json.JsonFormatter, Serilog" } } ]
}
```

产出单行 JSON（实测样本）：

```json
{"Timestamp":"...","Level":"Information",
 "MessageTemplate":"LLM interaction recorded. ConversationId={ConversationId} ...",
 "TraceId":"ea83bb32...","SpanId":"09842bda...",
 "Properties":{"ConversationId":"conv-e2e-1","TraceId":"trace-e2e-1",
               "AgentId":"cs-bot","ServiceName":"agent-engine","InstanceId":"..."}}
```

`deploy/promtail/promtail-config.yml` 按该结构从 `Properties.*` 抽取字段，
并由 `tests/test_deployment_contracts.py` 用上面这份真实样本做回归校验。

### 2.1 前置条件

| 组件 | 说明 |
|---|---|
| audit 平台已部署 | `docker compose --env-file .env up -d`（Langfuse 栈 + audit-db + audit-api + decrypt-svc） |
| 公钥已签发 | `python scripts/provision_keys.py`，`AUDIT_PUBLIC_KEY_PATH` 指向公钥；**私钥文件绝不下发到 OpenAgent 侧** |
| Langfuse 项目凭据 | `LANGFUSE_HOST` / `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` |
| 密文库账号 | audit-db 的 `agent_writer` 角色（对密文表仅 INSERT，由 `deploy/10_audit_schema.sql` 保证） |

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
| GET | `/v1/me` | 任意已认证 | 令牌 → `{username, role, is_admin}`（SPA 会话引导） |
| GET | `/v1/sessions?q&from_ts&to_ts&agent&page` | view_masked | 会话列表；每页 10 条、最多 20 页（200 条），更早数据需用筛选 |
| GET | `/v1/sessions/{id}` | view_masked | 掩码 trace（浏览本身写审计日志） |
| GET | `/v1/traces?user_id&session_id&from_ts&to_ts` | view_masked | 检索限这三个维度（无敏感值反查） |
| GET | `/v1/audit-log?q&from_ts&to_ts&role&action&page&verify` | view_audit_log | 审计日志 + 哈希链校验；分页同上 |
| POST | `/v1/reveal/{entity_id}` | **reveal（管理员）** | 解密单个实体查看原文；先写日志再返回明文 |
| POST | `/v1/admin/login` | 已登录会话 | 输入管理员密码解锁（有效期见 1.1） |
| POST | `/v1/admin/logout` | 管理员 | 立即退出管理员，并开始冷却计时 |
| GET | `/internal/metrics`（`/prometheus`） | view_metrics | 运行指标（仅管理员） |

错误约定：`401` 令牌无效或未登录；`403` 权限不足（返回专业中文提示，见 1.4）；
`404` 会话/实体不存在；`422` 解密失败或参数格式错误；
`429` 管理员登录处于冷却期（响应体含剩余等待时间）。

**分页约定**：`page_size` 固定按 10 处理（传入更大值会被压到 10），`page` 上限 20。
响应包含 `total`、`total_pages`、`max_visible` 与 `truncated`；`truncated=true`
表示还有更早的数据，必须用筛选条件才能取到。

**时间约定**：`from_ts`/`to_ts` 按 `AUDIT_DISPLAY_TIMEZONE` 解释（默认东八区）；
返回的 `ts` 是 UTC，`ts_display` 是本地时间。

audit-web 的页面（服务端渲染，见 `services/templates/`）即这组接口的参考实现，
可用 iframe 或改造为内嵌页面接入 OpenAgent 平台。

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
