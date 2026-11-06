# 内网部署手册：10.51.4.45 更新 OpenAgent 并部署 Audit

> **读者**：在**内网电脑**上操作、能访问 `10.51.4.45` 的工程师。
> **目标机**：`10.51.4.45`，已运行 OpenAgent，对外地址 `https://agent.monolithicpower.com:444`。
> **前置事实**：外网机器无法访问服务器，所以所有命令都在**内网电脑**或**经由内网电脑 SSH 到服务器**后执行。

---

## 0. 先确认三件事

在开始之前，先在服务器上执行，确认现状：

```bash
# 1) Docker 与权限
docker version --format '{{.Server.Version}}'
docker compose version
sudo -n docker ps >/dev/null 2>&1 && echo "docker 免密可用" || echo "需要 sudo docker"

# 2) 现有 OpenAgent 部署位置与方式
ls -d /opt/OpenAgent* 2>/dev/null
cd /opt/OpenAgent && git rev-parse --abbrev-ref HEAD && git log --oneline -1

# 3) 端口是否被占用（audit 要用 3000 / 3100 / 8100 / 8102）
ss -lntp | grep -E ':(3000|3100|8100|8102)\b' || echo "端口空闲"
```

> ⚠️ **如果第 3 步显示端口被占用**，先停掉占用方，或修改 audit 的 `docker-compose.yml` 里的 `ports` 映射。

**记录下**：OpenAgent 目录路径（下文用 `/opt/OpenAgent` 代指）、当前分支、当前提交号（回滚要用）。

---

## 1. 在内网电脑上取代码并打包

外网机器拿不到代码，需要在内网电脑上从 GitHub 拉取，再用 `scp` 传到服务器。

> 若内网电脑不能直连 GitHub，用公司既有的镜像仓库/跳板机方式获取，步骤等价。

### 1.1 拉取 Audit

```bash
cd ~
git clone https://github.com/philfanzhou/OpenAgent.Audit.git
cd OpenAgent.Audit
git log --oneline -1        # 应为 cd677ba 或更新
```

### 1.2 拉取 OpenAgent（含审计集成）

```bash
cd ~
git clone https://github.com/philfanzhou/OpenAgent.git
cd OpenAgent
git checkout feat/audit-integration
git log --oneline -3
```

应看到这三个提交：
```
546f6299 fix(otlp): apply the deployment TLS policy to the exporters
b2be4957 fix(deploy): own the audit network instead of waiting for the audit stack
cc1ed0e5 fix(audit-integration): make OTLP export, span correlation and log format actually work
```

> **若 PR #313 已合并进 `main`**，改用 `git checkout main && git pull`，效果相同。

### 1.3 打包（排除本地密钥、虚拟环境、构建产物）

```bash
cd ~
tar --exclude='.git' --exclude='.venv' --exclude='keys' \
    --exclude='__pycache__' --exclude='node_modules' --exclude='data' \
    -czf openagent-audit.tar.gz OpenAgent.Audit

tar --exclude='.git' --exclude='node_modules' --exclude='dist' \
    -czf openagent.tar.gz OpenAgent

ls -lh openagent*.tar.gz
```

### 1.4 传到服务器

```bash
scp openagent-audit.tar.gz openagent.tar.gz <你的用户名>@10.51.4.45:/tmp/
```

---

## 2. 部署 Audit（先做）

> **顺序很重要**：两边共用 `openagent` 与 `openagent-audit` 两个 Docker 网络。虽然两边都用网络名声明、谁先启动都能复用，但**先起 audit 再去升级 OpenAgent** 能让每次变更的影响范围更小。

### 2.1 解压

```bash
ssh <你的用户名>@10.51.4.45

sudo mkdir -p /opt/OpenAgent.Audit
sudo tar -xzf /tmp/openagent-audit.tar.gz -C /opt/OpenAgent.Audit --strip-components=1
cd /opt/OpenAgent.Audit && ls
```

> `--strip-components=1` 是因为压缩包里有一层 `OpenAgent.Audit/` 目录。

### 2.2 生成加密密钥对

```bash
cd /opt/OpenAgent.Audit
sudo mkdir -p keys

# 先生成并安全保存口令（这一步的产物要写进 .env）
PASSPHRASE=$(openssl rand -base64 24)
echo "AUDIT_PRIVATE_KEY_PASSPHRASE=$PASSPHRASE" > /tmp/audit-passphrase.txt
chmod 600 /tmp/audit-passphrase.txt
echo "口令已保存到 /tmp/audit-passphrase.txt，稍后写入 .env"

sudo python3 scripts/provision_keys.py --out keys --passphrase "$PASSPHRASE"
sudo chmod 600 keys/audit_private_key.pem
sudo ls -l keys/
```

> **必须**先保存口令再生成密钥。口令丢失 = 历史密文永久无法解密。
> 如果服务器没有 `cryptography` 库：`sudo pip3 install cryptography` 或用容器执行：
> `docker run --rm -v "$PWD:/w" -w /w python:3.12-slim sh -c "pip install -q cryptography && python scripts/provision_keys.py --out keys --passphrase '...'"`

### 2.3 生成 `.env`

```bash
cd /opt/OpenAgent.Audit
sudo cp .env.example .env
sudo chmod 600 .env
```

逐项填值。**每条命令生成一个**，把结果填进 `.env`：

```bash
openssl rand -base64 32   # NEXTAUTH_SECRET
openssl rand -base64 32   # SALT
openssl rand -hex 32      # ENCRYPTION_KEY
openssl rand -hex 32      # LANGFUSE_DB_PASSWORD
openssl rand -hex 32      # CLICKHOUSE_PASSWORD
openssl rand -hex 32      # REDIS_PASSWORD
openssl rand -hex 32      # MINIO_ROOT_PASSWORD
openssl rand -hex 32      # AUDIT_OWNER_PASSWORD
openssl rand -hex 32      # AUDIT_AGENT_WRITER_PASSWORD
openssl rand -hex 32      # AUDIT_API_PASSWORD
openssl rand -hex 32      # AUDIT_DECRYPT_PASSWORD
openssl rand -hex 32      # AUDIT_RETENTION_PASSWORD
openssl rand -hex 32      # AUDIT_SERVICE_TOKEN
openssl rand -hex 32      # AUDIT_GATEWAY_TOKEN  ← 记下来，第 3 步要用
```

**必填清单**（留空会导致容器起不来）：

| 键 | 说明 |
|---|---|
| `NEXTAUTH_SECRET` / `SALT` / `ENCRYPTION_KEY` | Langfuse 三项，缺一不启动 |
| `LANGFUSE_DB_PASSWORD` / `CLICKHOUSE_PASSWORD` / `REDIS_PASSWORD` / `MINIO_ROOT_PASSWORD` | 基础组件 |
| `AUDIT_OWNER_PASSWORD` | 建库账号，**只给初始化用** |
| `AUDIT_AGENT_WRITER_PASSWORD` / `AUDIT_API_PASSWORD` / `AUDIT_DECRYPT_PASSWORD` / `AUDIT_RETENTION_PASSWORD` | 四个服务角色，**必须互不相同**（脚本会校验，重复即拒绝启动） |
| `AUDIT_SERVICE_TOKEN` | audit-api → decrypt-svc |
| `AUDIT_GATEWAY_TOKEN` | 平台 → 网关，**必须与第 3.3 步一致** |
| `AUDIT_PRIVATE_KEY_PASSPHRASE` | 第 2.2 步的口令；**丢失则历史密文永久不可解** |

#### 身份来源与管理员账号

审计台只有两种身份：普通用户（只看脱敏内容）与管理员（可点击脱敏项查看原文）。
**审计台不自建用户表**，身份来自 OpenAgent。

| 身份来源 | 何时使用 | 结果 |
|---|---|---|
| OpenAgent `/api/v1/agent/me` | 正常路径：浏览器携带平台令牌 | 取平台返回的 `username`/`userId`，一律为 `user` |
| `AUDIT_USERS` | 本地测试、无平台时 | 配置中的用户名，一律为 `user` |
| 本地测试账号 `test` | OpenAgent 未传递身份时的兜底 | `test`，标记 `ephemeral` |

平台令牌里声明的任何角色**都会被忽略**——它只能证明"你是谁"，不能授予"能解密"。

**开启平台身份对接**：

```
AUDIT_AUTH_PROVIDER=http
AUDIT_AUTH_INTROSPECT_URL=https://agent.monolithicpower.com:444/api/v1/agent/me
```

> 该地址由 audit-api 容器访问。若走内网直连，用 `http://engine:8083/api/v1/agent/me`
> 这类容器网络地址更稳妥；外链 HTTPS 且证书不受信时需按第 3.3 步处理 CA。

**测试账号**（OpenAgent 未传身份时用）：

```
AUDIT_TEST_USERNAME=test
AUDIT_TEST_PASSWORD=test@1233456
AUDIT_TEST_SESSION_MINUTES=60
```

它的限制是硬性的：只能以普通用户浏览，**不能**登录管理员（按钮不显示，直接请求返回
403 并记为 `ADMIN_LOGIN_REFUSED`），登录 1 小时后自动失效。两个变量留空即完全禁用。

**管理员密码用哈希存储**：

```bash
python3 scripts/hash_admin_password.py --password '你的管理员密码'
# 输出形如 pbkdf2_sha256$210000$<salt>$<hash>，填进 AUDIT_ADMIN_PASSWORD_HASH
```

| 键 | 默认 | 说明 |
|---|---|---|
| `AUDIT_ADMIN_USERNAME` | `admin` | 管理员账号名 |
| `AUDIT_ADMIN_PASSWORD_HASH` | 空 | **推荐**；与明文二选一，哈希优先 |
| `AUDIT_ADMIN_PASSWORD` | 空 | 仅本地调试；两者都留空则**完全关闭**管理员登录 |
| `AUDIT_ADMIN_SESSION_MINUTES` | `5` | 解锁有效期；到期自动退回普通用户 |
| `AUDIT_ADMIN_COOLDOWN_MINUTES` | `10` | 解锁结束后同账号需等待此时长才能再次登录 |
| `AUDIT_TEST_USERNAME` / `AUDIT_TEST_PASSWORD` | 空 | 兜底测试账号；留空禁用 |
| `AUDIT_TEST_SESSION_MINUTES` | `60` | 测试账号会话时长 |
| `AUDIT_DISPLAY_TIMEZONE` | `Asia/Shanghai` | 页面显示与日期筛选时区；**存储始终为 UTC** |

**审计日志的不可篡改性**：每次揭示先写 `ENTITY_REVEAL_REQUESTED`，解密成功后再写
`ENTITY_REVEALED`，两条都记下是哪个账号（`session_user`）在什么时间看了哪一条。
写入失败则**不返回明文**。日志表是 append-only + 哈希链，任何应用角色都没有
UPDATE/DELETE 权限。

**搜索与分页**：会话列表与审计日志均为每页 10 条、最多 20 页（200 条）。更早的数据
需用搜索框的条件（时间范围、角色、动作、账号、关键字）定位。日期筛选按
`AUDIT_DISPLAY_TIMEZONE` 解释。

`LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` 先留空，第 2.5 步再填。

> ⚠️ `.env` 里**不要写行内注释**。`KEY=value  # 说明` 会把注释当成值的一部分。

如果服务器访问外网受限、Docker 拉镜像需要代理，Docker 守护进程要单独配置代理（`/etc/systemd/system/docker.service.d/proxy.conf`）。

```bash
# 若需要镜像加速/代理，确认已生效
sudo systemctl show docker --property=Environment | tr ' ' '\n' | grep -i proxy
```

### 2.4 启动 Audit

```bash
cd /opt/OpenAgent.Audit
sudo docker compose --env-file .env up -d --build
```

首次会构建 `openagent-audit` 镜像并拉取 postgres / clickhouse / redis / minio / langfuse，耗时较长。观察：

```bash
sudo docker compose ps
sudo docker compose logs -f --tail=50 audit-db masking-gateway
```

> `langfuse-web` 只等待 postgres，首次启动可能短暂重启，属正常，几分钟内自愈。
> 若 `audit-db` 报 `privilege verification failed`，说明角色密码有重复或权限脚本有问题，看 `docker compose logs audit-db`。

初始化会打印权限自检结果，应可见：

```
[ok]   agent_writer cannot SELECT ciphertext
[ok]   audit_api cannot SELECT ciphertext
[ok]   decrypt_svc can SELECT ciphertext
[ok]   decrypt_svc can read audit_log hash chain
[ok]   decrypt_svc cannot read audit_log.detail
[ok]   audit_api cannot DELETE audit_log
privilege split verified
```

### 2.5 创建 Langfuse 项目并回填凭据

1. 浏览器打开 `https://agent.monolithicpower.com:3000`（或 `http://10.51.4.45:3000`），注册初始账号
2. 新建 Organization → Project
3. Project Settings → API Keys → 复制 public / secret
4. 写回 `.env`：

```bash
cd /opt/OpenAgent.Audit
sudo sed -i 's|^LANGFUSE_PUBLIC_KEY=.*|LANGFUSE_PUBLIC_KEY=pk-lf-xxx|' .env
sudo sed -i 's|^LANGFUSE_SECRET_KEY=.*|LANGFUSE_SECRET_KEY=sk-lf-xxx|' .env
sudo docker compose --env-file .env up -d audit-api masking-gateway
```

### 2.6 验收 Audit

```bash
curl -fsS http://127.0.0.1:8102/healthz            # {"ok":true,"service":"masking-gateway"}
curl -fsS http://127.0.0.1:8100/healthz            # {"ok":true,"service":"audit-api",...}
curl -fsS http://127.0.0.1:8102/internal/metrics   # 计数器应全为 0
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8100/ui/login   # 200
```

确认两个网络已存在：

```bash
docker network ls | grep -E 'openagent(-audit)?$'
# 预期两行：openagent、openagent-audit
```

---

## 3. 更新部署 OpenAgent

### 3.1 备份现场

```bash
cd /opt/OpenAgent
TS=$(date +%F-%H%M)
sudo cp deploy/openagent/docker-compose.yml "deploy/openagent/docker-compose.yml.bak.$TS"
sudo cp .env ".env.bak.$TS"
sudo docker compose -p openagent-app -f deploy/openagent/docker-compose.yml ps > "/tmp/oa-before-$TS.txt"
echo "备份后缀：$TS"
```

### 3.2 合并新代码（保留 `.env` 和证书）

```bash
# 解压到临时目录
sudo rm -rf /opt/OpenAgent.new
sudo mkdir -p /opt/OpenAgent.new
sudo tar -xzf /tmp/openagent.tar.gz -C /opt/OpenAgent.new --strip-components=1

# 先看差异，确认没有意外覆盖
diff -u /opt/OpenAgent/deploy/openagent/docker-compose.yml \
        /opt/OpenAgent.new/deploy/openagent/docker-compose.yml | head -60
```

确认无误后覆盖，**排除 `.env` 与证书**：

```bash
sudo rsync -a \
  --exclude '.env' \
  --exclude 'deploy/openagent/nginx/certs/*' \
  --exclude '.git' \
  /opt/OpenAgent.new/ /opt/OpenAgent/

# 确认关键文件还在
ls -l /opt/OpenAgent/.env
ls -l /opt/OpenAgent/deploy/openagent/nginx/certs/tls.crt \
      /opt/OpenAgent/deploy/openagent/nginx/certs/tls.key
```

> **如果 `/opt/OpenAgent` 不是 git 工作区**（第 0 步确认过），rsync 前建议先整体备份：
> `sudo tar -czf /opt/openagent-backup-$TS.tar.gz -C /opt OpenAgent`

### 3.3 补充审计相关变量

编辑 `/opt/OpenAgent/.env`，确保存在以下四项：

```bash
sudo tee -a /opt/OpenAgent/.env >/dev/null <<'EOF'

# ---- 审计平面（OpenAgent.Audit）----
OPENAGENT_AUDIT_NETWORK=openagent-audit
OPENAGENT_OTLP_TRACES_ENDPOINT=http://masking-gateway:8102
OPENAGENT_OTLP_TRACES_HEADERS=Authorization=Bearer <粘贴第2.3步的AUDIT_GATEWAY_TOKEN>
OPENAGENT_OTLP_PROTOCOL=http/protobuf
EOF
```

> ⚠️ **必须直接粘贴令牌原文**。Compose **不会**展开 `.env` 里值的 `${...}`；
> 写成 `Bearer ${AUDIT_GATEWAY_TOKEN}` 会把这段字面量当令牌发出去，网关一律返回 401，
> 所有 trace 被丢弃（已实测验证）。
>
> 只想先升级、暂不接审计：把 `OPENAGENT_OTLP_TRACES_ENDPOINT` 留空即可。

如果源站是外链 TLS 且有自签证书问题，按需补充：

```bash
# 仅在 Collector / 网关走 HTTPS 且证书不被容器信任时才需要
# OPENAGENT_ALLOW_INSECURE_TLS=true
```

### 3.4 校验配置能解析（不启动）

```bash
cd /opt/OpenAgent
sudo docker compose -p openagent-app -f deploy/openagent/docker-compose.yml \
  --env-file .env config --quiet && echo "配置有效"
```

### 3.5 构建镜像

```bash
cd /opt/OpenAgent
sudo scripts/build-images.sh --env-file .env --docker-mode docker
```

脚本会构建 `openagent-engine` / `openagent-router` / `openagent-runner` 三个镜像。

**关于 Chat 镜像**：前端工作台已拆到独立仓库（OpenAgent-Frontend），本仓库不含
`Frontend/OpenAgent.Chat`。脚本检测到目录缺失且本地无该镜像时会**打印警告并跳过**，
不中断后端构建。因此：

- 若你们已在别处构建好 Chat 镜像，确保 `.env` 的 `OPENAGENT_CHAT_IMAGE` 指向它；
- 若暂时不需要 Chat，把 `deploy/openagent/docker-compose.yml` 里 `chat` 服务及其相关
  依赖（nginx 的 `depends_on: chat`）注释掉，或先 `docker tag` 一个占位镜像。

> 走内网镜像仓库时改为 `sudo docker pull <镜像标签>`，并确认 `.env` 中
> `OPENAGENT_ENGINE_IMAGE` / `OPENAGENT_ROUTER_IMAGE` / `OPENAGENT_CHAT_IMAGE` 指向新标签。

**若报 `syntax error near unexpected token`**：脚本行尾是 CRLF（Windows 检出）。
本次更新已加入 `.gitattributes` 并转为 LF；若是旧检出，执行：

```bash
sudo sed -i 's/\r$//' scripts/*.sh
```

### 3.6 部署

```bash
cd /opt/OpenAgent
sudo scripts/deploy.sh --env-file .env --docker-mode docker
```

该脚本执行的是 `compose up -d --no-build --pull never`：只替换容器，**不动数据卷、网络与 Data Protection 密钥卷**。

### 3.7 验收

```bash
# 1) 业务仍正常
curl -fsS http://127.0.0.1:5208/health        # engine
curl -fsS http://127.0.0.1:5001/health        # router
curl -fsS -o /dev/null -w '%{http_code}\n' https://agent.monolithicpower.com:444/health

# 2) 日志已变 JSON（应出现 "ServiceName":"agent-engine"）
sudo docker logs --tail 5 $(sudo docker ps -qf name=engine) | head -3

# 3) 网关收到 trace
curl -fsS http://127.0.0.1:8102/internal/metrics
```

**发一条对话后**，再看计数器判读：

| 计数 | 含义 | 处理 |
|---|---|---|
| `forwarded_batches` 增长 | ✅ 正常 | 继续 |
| `batches_unauthorized` 增长 | ❌ 两边令牌不一致 | 核对 `AUDIT_GATEWAY_TOKEN` 与 `OPENAGENT_OTLP_TRACES_HEADERS` |
| `batches_received` 一直 0 | ❌ engine 没发到网关 | `docker logs engine \| grep -i otlp`，检查端点与网络 |
| `batches_dropped` 增长 | ❌ 脱敏或写库失败（**必须告警**） | `docker compose logs masking-gateway audit-db` |

**端到端确认**：

```bash
# 在 Chat 里发一条含手机号的对话，然后：
sudo docker exec -it $(sudo docker ps -qf name=audit-db) psql -U audit_owner -d openagent_audit \
  -c "select entity_type, trace_id, session_id, created_at from entity_ciphertext order by created_at desc limit 5;"
```

期望：`session_id` 等于平台的 conversation id，`trace_id` 是 **32 位小写 hex**（不是 base64）。

再到 Langfuse（`https://agent.monolithicpower.com:3000`）确认该 trace 中手机号显示为 `⟦PHONE_NUMBER#…|138****5678⟧`。

---

## 4. 回滚

### 4.1 回滚 OpenAgent

```bash
cd /opt/OpenAgent
sudo cp deploy/openagent/docker-compose.yml.bak.<TS> deploy/openagent/docker-compose.yml
sudo cp .env.bak.<TS> .env
sudo scripts/deploy.sh --env-file .env --docker-mode docker
```

镜像回退：把 `.env` 里 `*_IMAGE` 改回旧标签后重新 `deploy.sh`。数据卷不动，业务数据无损。

### 4.2 停用审计接入（保留审计数据）

```bash
cd /opt/OpenAgent
sudo sed -i 's|^OPENAGENT_OTLP_TRACES_ENDPOINT=.*|OPENAGENT_OTLP_TRACES_ENDPOINT=|' .env
sudo scripts/deploy.sh --env-file .env --docker-mode docker
```

### 4.3 停掉 Audit（OpenAgent 可继续运行）

```bash
cd /opt/OpenAgent.Audit
sudo docker compose --env-file .env stop
```

> ⚠️ **绝对不要执行 `docker compose down -v`** —— 那会删除审计数据卷（密文库、审计日志、Langfuse 全部数据）。
> 也不要删除 `openagent` / `openagent-audit` 网络，否则另一个栈的容器会失去连通性。

---

## 5. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `network openagent-audit declared as external, but could not be found` | 用了旧版 compose（那份两边互相等 external） | 确认已用本次更新后的 `docker-compose.yml` |
| `every audit role needs a DISTINCT password` | 四个角色密码有重复 | 每个角色单独 `openssl rand -hex 32` |
| `audit database schema is missing` | `init_db.sh` 未执行（非首次启动的旧卷） | 手工：`docker compose exec audit-db bash /docker-entrypoint-initdb.d/20_init_db.sh` |
| 网关 401，`batches_unauthorized` 增长 | `.env` 里写了 `${AUDIT_GATEWAY_TOKEN}` 字面量 | 粘贴令牌原文 |
| Langfuse 启动报 secret 长度错误 | `.env` 里有行内注释 | 注释独立成行 |
| audit-web 会话页 500 | `LANGFUSE_*` 为空 | 完成 2.5 后重启 `audit-api` |
| engine 日志里 `langfuse forward failed` / TLS 错误 | 目标证书不被信任 | 装公司 CA 到容器信任库，或临时 `OPENAGENT_ALLOW_INSECURE_TLS=true` |
| 端口冲突 | 3000 / 3100 / 8100 / 8102 被占 | 停占用方或改 compose 的 `ports` |
| `build-images.sh: syntax error near unexpected token` | 脚本是 CRLF 行尾 | `sudo sed -i 's/\r$//' scripts/*.sh`；本次更新已自带 `.gitattributes` |
| `unable to prepare context: path ".../Backend/src/..." not found` | 用了拆分前的旧脚本 | 本次更新已改为 `src/...`，确认已拉最新代码 |
| `warning: Frontend/OpenAgent.Chat/Dockerfile not found` | 前端已拆到 OpenAgent-Frontend 仓库 | 正常，后端镜像照常构建；需要 Chat 时另行准备镜像 |
| CI 报 `Backend/OpenAgent.sln` 或前端 job 失败 | 拆分后路径未同步 | 本次更新已修复并加检测 job |

---

## 6. 上线后仍需人工处理

- `AUDIT_USERS` 里的示例令牌必须换成真实值（平台侧下发的访问令牌）；普通用户只看到脱敏内容，管理员权限靠密码解锁而非令牌，因此**不要**把管理员密码发给普通业务人员
- 保留期、还原 TTL、掩码深度是合规决策，见 `.env` 的 retention 段
- 平台账号登录 audit-web（token 内省）**尚未实现**，当前用 `AUDIT_AUTH_PROVIDER=static`
- `deploy/alerting/` 的 Prometheus 规则需接入现有监控；`batches_dropped > 0` 必须告警
- 备份策略：`audit-pg` 卷（密文库 + 审计日志）、`audit-archive` 对象桶、`/opt/OpenAgent.Audit/keys/`（**私钥丢失则历史密文永久不可解**）

---

## 附：命令速查

```bash
# 一键确认 audit 侧全部健康
curl -fsS http://127.0.0.1:8102/healthz && \
curl -fsS http://127.0.0.1:8100/healthz && \
curl -fsS http://127.0.0.1:8102/internal/metrics

# 一键确认 OpenAgent 侧
curl -fsS http://127.0.0.1:5208/health && \
curl -fsS http://127.0.0.1:5001/health && \
curl -fsS -o /dev/null -w 'public=%{http_code}\n' https://agent.monolithicpower.com:444/health

# 网络拓扑
docker network inspect openagent --format '{{range .Containers}}{{.Name}} {{end}}'
docker network inspect openagent-audit --format '{{range .Containers}}{{.Name}} {{end}}'
```