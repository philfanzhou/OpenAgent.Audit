# 在 10.51.4.45 上部署 Audit 并升级 OpenAgent

> 读者：在服务器上执行部署的工程师。
> 目标机器：`10.51.4.45`（已运行 OpenAgent）。
> 本文所有命令均在 **服务器上** 执行；外网机器只用来中转部署包。

---

## 0. 先看清三个硬约束

1. **audit 栈必须先启动**。两个栈共用 `openagent` 与 `openagent-audit` 两个 Docker
   网络，由 audit 栈创建、OpenAgent 栈以 `external` 接入。顺序反了会报
   `network openagent-audit declared as external, but could not be found`。

2. **台账端口**：audit 会占用宿主机 `3000`（Langfuse UI）、`8100`（audit-web）、
   `8102`（脱敏网关）、`3100`（Loki）。先确认没有冲突：

   ```bash
   ss -lntp | grep -E ':(3000|3100|8100|8102)\b' || echo "端口空闲"
   ```

3. **升级 OpenAgent 不会重建数据**。`scripts/deploy.sh` 执行的是
   `compose up -d --no-build --pull never`，只替换容器；数据卷、网络、
   Data Protection 密钥卷都保留。

> 已验证：即使审计网关暂时不可达，OpenAgent 仍能正常启动和对外服务，
> trace 导出失败只记日志。因此"先升级 OpenAgent、后装 audit"也不会造成业务中断。

---

## 1. 把代码送到服务器

外网机器无法直连 10.51.4.45，按公司既有方式任选其一（`scp` / 跳板机 / 内网镜像仓库）。

### 1.1 Audit 仓库

```bash
# 在外网机器上：打包（不要带 .git / .venv / data / keys）
cd OpenAgent.Audit
git archive --format=tar.gz -o /tmp/openagent-audit.tar.gz HEAD

# 传到服务器（按公司方式）
scp /tmp/openagent-audit.tar.gz user@10.51.4.45:/opt/
```

```bash
# 服务器上解压到 /opt/OpenAgent.Audit
# 注意：git archive 不带顶层目录，直接 -C 到目标目录即可，不要加 --strip-components
sudo mkdir -p /opt/OpenAgent.Audit
sudo tar -xzf /opt/openagent-audit.tar.gz -C /opt/OpenAgent.Audit
cd /opt/OpenAgent.Audit && ls
```

### 1.2 OpenAgent 仓库（升级用）

```bash
# 外网机器
cd OpenAgent
git fetch origin feat/audit-integration
git archive --format=tar.gz -o /tmp/openagent.tar.gz origin/feat/audit-integration
scp /tmp/openagent.tar.gz user@10.51.4.45:/opt/
```

> 该分支尚未合并进 `main`（PR #313）。若已合并，改用 `origin/main`。

⚠️ **不要解压覆盖已有目录**。服务器上的 OpenAgent 目录可能已有本地 `deploy/openagent/docker-compose.yml`
改动；解压到新目录后做差异核对：

```bash
sudo mkdir -p /opt/OpenAgent.new
sudo tar -xzf /opt/openagent.tar.gz -C /opt/OpenAgent.new
cd /opt/OpenAgent.new && git init -q 2>/dev/null || true
diff -u /opt/OpenAgent/deploy/openagent/docker-compose.yml /opt/OpenAgent.new/deploy/openagent/docker-compose.yml
```

---

## 2. 部署 Audit（必须先做）

### 2.1 生成密钥对

```bash
cd /opt/OpenAgent.Audit
python3 scripts/provision_keys.py --out keys --passphrase "$(openssl rand -base64 24)"
```

把输出的口令随手记下（decrypt-svc 需要它，丢了历史数据就解不开）。校验：

```bash
ls -l keys/           # audit_public_key.pem + audit_private_key.pem
chmod 600 keys/audit_private_key.pem
```

> 只有 `decrypt-svc` 用私钥；`masking-gateway` 只读公钥。私钥不要外发。

### 2.2 生成 .env

```bash
cd /opt/OpenAgent.Audit
cp .env.example .env
chmod 600 .env

# 生成各项密钥（逐个替换）
openssl rand -base64 32    # -> NEXTAUTH_SECRET
openssl rand -base64 32    # -> SALT
openssl rand -hex 32       # -> ENCRYPTION_KEY
openssl rand -hex 32       # -> AUDIT_SERVICE_TOKEN
openssl rand -hex 32       # -> AUDIT_GATEWAY_TOKEN   ← 记下来，第 3 步要用
openssl rand -hex 32       # -> AUDIT_OWNER_PASSWORD
openssl rand -hex 32       # -> AUDIT_AGENT_WRITER_PASSWORD
openssl rand -hex 32       # -> AUDIT_API_PASSWORD
openssl rand -hex 32       # -> AUDIT_DECRYPT_PASSWORD
openssl rand -hex 32       # -> AUDIT_RETENTION_PASSWORD
```

`.env` 里必须填的非空项：

| 变量 | 说明 |
|---|---|
| `NEXTAUTH_SECRET` / `SALT` / `ENCRYPTION_KEY` | Langfuse 三项，缺一不启动 |
| `LANGFUSE_DB_PASSWORD` / `CLICKHOUSE_PASSWORD` / `REDIS_PASSWORD` / `MINIO_ROOT_PASSWORD` | 基础组件密码 |
| `AUDIT_OWNER_PASSWORD` | 建库账号，仅初始化用，不下发给服务 |
| `AUDIT_AGENT_WRITER_PASSWORD` / `AUDIT_API_PASSWORD` / `AUDIT_DECRYPT_PASSWORD` / `AUDIT_RETENTION_PASSWORD` | 各服务独立密码，**必须互不相同** |
| `AUDIT_SERVICE_TOKEN` | 审计域 |
| `AUDIT_GATEWAY_TOKEN` | 平台→网关令牌，**必须与 OpenAgent 侧一致** |
| `AUDIT_PRIVATE_KEY_PASSPHRASE` | 第 2.1 步的口令 |
| `AUDIT_USERS` | 静态账号，至少留一个 `developer` 用于看指标 |

> `.env` 里**不要写行内注释**（`KEY=value  # 说明` 会把注释当值）。模板已改成注释独立成行。
>
> `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` 要先启动一次 Langfuse，
> 在 UI 创建项目后才能拿到，见 2.4。

### 2.3 启动

```bash
cd /opt/OpenAgent.Audit
docker compose --env-file .env up -d --build
```

首次会构建 `openagent-audit` 镜像并拉取 postgres/clickhouse/redis/minio/langfuse，
耗时较长。观察：

```bash
docker compose ps
docker compose logs -f audit-db masking-gateway
```

`langfuse-web` 只等待 postgres，首次启动可能短暂重启，属正常，几分钟内自愈。

### 2.4 创建 Langfuse 项目并回填凭据

1. 浏览器打开 `http://10.51.4.45:3000`，注册初始账号
2. 新建 organization / project
3. Project Settings → API Keys → 复制 public/secret key
4. 写回 `/opt/OpenAgent.Audit/.env` 的 `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY`
5. 重启读取凭据的服务：

```bash
cd /opt/OpenAgent.Audit
docker compose --env-file .env up -d audit-api masking-gateway
```

### 2.5 验收

```bash
# 网关存活
curl -fsS http://127.0.0.1:8102/healthz
# 审计 API 存活 + 记录数
curl -fsS http://127.0.0.1:8100/healthz
# 网关计数器（预期全 0）
curl -fsS http://127.0.0.1:8102/internal/metrics
# 审计 web 能登录
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8100/ui/login   # 200
```

确认网络已创建（第 3 步依赖它们）：

```bash
docker network ls | grep -E 'openagent(-audit)?$'
# 预期两行：openagent、openagent-audit
```

---

## 3. 升级 OpenAgent

### 3.1 先备份现场

```bash
cd /opt/OpenAgent
cp deploy/openagent/docker-compose.yml deploy/openagent/docker-compose.yml.bak.$(date +%F)
cp .env .env.bak.$(date +%F)
docker compose -p openagent-app -f deploy/openagent/docker-compose.yml ps > /tmp/oa-before.txt
```

### 3.2 合并新代码

把 1.2 解压出的 `/opt/OpenAgent.new` 内容覆盖到现有目录（保留 `.env`、证书、数据卷）：

```bash
cd /opt/OpenAgent
rsync -a --exclude '.env' --exclude 'deploy/openagent/nginx/certs/*' \
      /opt/OpenAgent.new/ /opt/OpenAgent/
```

确认 `.env` 和证书仍在：

```bash
ls -l .env deploy/openagent/nginx/certs/tls.crt deploy/openagent/nginx/certs/tls.key
```

### 3.3 补三个审计变量

在 `/opt/OpenAgent/.env` 追加（`AUDIT_GATEWAY_TOKEN` 用第 2.2 步生成的值）：

```dotenv
OPENAGENT_AUDIT_NETWORK=openagent-audit
OPENAGENT_OTLP_TRACES_ENDPOINT=http://masking-gateway:8102
OPENAGENT_OTLP_TRACES_HEADERS=Authorization=Bearer <第2.2步的AUDIT_GATEWAY_TOKEN>
OPENAGENT_OTLP_PROTOCOL=http/protobuf
```

> 只想先升级、暂不接审计：把 `OPENAGENT_OTLP_TRACES_ENDPOINT` 留空即可，
> 其余三项可保留。但 `OPENAGENT_AUDIT_NETWORK` 必须有值。

校验配置能解析（不启动）：

```bash
docker compose -p openagent-app -f deploy/openagent/docker-compose.yml \
  --env-file .env config --quiet && echo "配置有效"
```

### 3.4 构建镜像

```bash
cd /opt/OpenAgent
scripts/build-images.sh --env-file .env --docker-mode docker
```

> 若走内网镜像仓库，改成 `docker pull` 对应标签，并确认 `.env` 的
> `OPENAGENT_ENGINE_IMAGE` / `OPENAGENT_ROUTER_IMAGE` / `OPENAGENT_CHAT_IMAGE` 指向新标签。

### 3.5 部署

```bash
cd /opt/OpenAgent
scripts/deploy.sh --env-file .env --docker-mode docker
```

### 3.6 验收

```bash
# 1) 业务仍正常
curl -fsS http://127.0.0.1:5208/health     # engine
curl -fsS http://127.0.0.1:5001/health     # router

# 2) 日志已变成 JSON（应看到 "ServiceName":"agent-engine"）
docker logs --tail 5 $(docker ps -qf name=engine) | head -3

# 3) 网关收到 trace（发一条对话后观察计数增长）
curl -fsS http://127.0.0.1:8102/internal/metrics
#    batches_received / forwarded_batches 应递增，batches_unauthorized 应为 0
```

**关键判读**：

| 计数 | 含义 | 处理 |
|---|---|---|
| `forwarded_batches` 增长 | 正常 | 继续 |
| `batches_unauthorized` 增长 | 两边令牌不一致 | 核对 `AUDIT_GATEWAY_TOKEN` 与 `OPENAGENT_OTLP_TRACES_HEADERS` |
| `batches_received` 一直 0 | engine 没发到网关 | `docker logs engine \| grep -i otlp`，检查端点与网络 |
| `batches_dropped` 增长 | 脱敏或写库失败 | 查 `docker compose logs masking-gateway audit-db`，这是必须告警的状态 |

**端到端确认**：在 Chat 里发一条含手机号的对话，然后

```bash
# Langfuse 里能看到该 trace，且号码显示为 ⟦PHONE_NUMBER#...|138****5678⟧
# 审计密文表有记录
docker exec -it $(docker ps -qf name=audit-db) psql -U audit_owner -d openagent_audit \
  -c "select entity_type, trace_id, session_id, created_at from entity_ciphertext order by created_at desc limit 5;"
```

`session_id` 应等于平台的 conversation id，且**必须是 32 位 hex 的 `trace_id`**（不是 base64）。

---

## 4. 回滚

### 4.1 回滚 OpenAgent

```bash
cd /opt/OpenAgent
cp deploy/openagent/docker-compose.yml.bak.<日期> deploy/openagent/docker-compose.yml
cp .env.bak.<日期> .env
scripts/deploy.sh --env-file .env --docker-mode docker
```

镜像回退：把 `.env` 里 `*_IMAGE` 改回旧标签后重新 `deploy.sh`。数据卷不动，业务数据无损。

### 4.2 停用审计接入（保留审计数据）

```bash
cd /opt/OpenAgent
sed -i 's|^OPENAGENT_OTLP_TRACES_ENDPOINT=.*|OPENAGENT_OTLP_TRACES_ENDPOINT=|' .env
scripts/deploy.sh --env-file .env --docker-mode docker
```

### 4.3 整体停掉 audit（OpenAgent 可继续运行）

```bash
cd /opt/OpenAgent.Audit
docker compose --env-file .env stop
```

⚠️ **不要执行 `docker compose down -v`**，那会删除审计数据卷。
同理不要删 `openagent` / `openagent-audit` 网络，否则下次启动 OpenAgent 栈会因
external 网络缺失而失败。

---

## 5. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `network openagent-audit declared as external, but could not be found` | 先启动了 OpenAgent 栈 | 先起 audit 栈，或删掉 OpenAgent 栈已创建的容器再重来 |
| `AUDIT_GATEWAY_TOKEN` 为空导致启动失败 | compose 设了 `REQUIRE_AUTH=true` | 填好令牌；这是有意的 fail-closed |
| Langfuse 启动失败、报 secret 长度错误 | `.env` 里写了行内注释 | 注释独立成行，重新填值 |
| audit-web 会话页 500 | `LANGFUSE_*` 为空 | 完成 2.4 后重启 `audit-api` |
| 端口冲突 | 3000/8100/8102 被占 | 停占用方，或改 `docker-compose.yml` 的 `ports` |
| `keys/` 缺失导致 decrypt-svc 起不来 | 没跑 2.1 | 补跑 `provision_keys.py` |

---

## 6. 部署后仍需人工决策

- `AUDIT_USERS` 里的示例令牌必须换成真实值；普通用户只看到脱敏内容，管理员权限靠密码解锁（见 `DEPLOY-INTRANET-10.51.4.45.md`），**不要**把管理员密码发给普通业务人员
- 保留期、还原 TTL、掩码深度属合规决策，见 `.env` 的 retention 段落
- 平台账号登录 audit-web（token 内省）**尚未实现**，当前用 `AUDIT_AUTH_PROVIDER=static`
- `deploy/alerting/` 的 Prometheus 规则需接入你们现有监控，`batches_dropped > 0` 必须告警