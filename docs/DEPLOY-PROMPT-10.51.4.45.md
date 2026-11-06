# 部署任务：在 10.51.4.45 上部署 OpenAgent.Audit 并升级 OpenAgent

> 这份文件是**给内网电脑上的 AI agent 执行的任务提示词**。
> 请把它整份读完后，按步骤执行。遇到不确定的地方先停下来问人，不要猜。

---

## 0. 角色与目标

你是部署执行者。目标是把两套系统部署到公司内网 Linux 服务器 `10.51.4.45`：

| 系统 | 仓库 | 目标目录 | 状态 |
|---|---|---|---|
| OpenAgent.Audit（审计平面） | `https://github.com/philfanzhou/OpenAgent.Audit.git`（分支 `main`） | `/opt/OpenAgent.Audit` | **首次部署** |
| OpenAgent（业务平台） | `https://github.com/philfanzhou/OpenAgent.git`（分支 `feat/audit-integration`） | 已存在于服务器 | **升级** |

**服务器登录方式**（特权账号）：

```
主机：10.51.4.45
账号：sinzoli
密码：Welc0me2
```

对外服务地址：`https://agent.monolithicpower.com:444`

---

## 1. 执行顺序（重要）

**先部署 audit，再升级 OpenAgent。** 原因：

1. 两边共用 Docker 网络 `openagent` 与 `openagent-audit`。先起 audit 会自动创建
   `openagent-audit` 网络，OpenAgent 侧的容器直接复用即可。
2. audit 部署完就有了网关（masking-gateway），OpenAgent 升级时直接连它，
   一次到位，避免"先连一个不存在的地址"。
3. 如果先升级 OpenAgent 而 audit 还没起，OpenAgent 的 OTLP 导出会持续失败
   （日志刷错误，不影响业务，但会污染日志）。

---

## 2. 前置检查（在服务器上执行）

```bash
# 2.1 确认能登录、有 sudo
ssh sinzoli@10.51.4.45
sudo -n true && echo "sudo OK"

# 2.2 Docker 可用
docker version --format '{{.Server.Version}}'
docker compose version

# 2.3 现有 OpenAgent 位置
ls -d /opt/OpenAgent* 2>/dev/null
cd /opt/OpenAgent && git rev-parse --abbrev-ref HEAD && git log --oneline -1
```

**记录 OpenAgent 的当前提交号**（回滚要用）。

```bash
# 2.4 端口是否空闲（audit 需要 3000 / 3100 / 8100 / 8102）
ss -lntp | grep -E ':(3000|3100|8100|8102)\b' || echo "端口空闲"
```

> ⚠️ **如果端口被占用**：停下来报告占用的进程，不要擅自 kill 别人的服务。

```bash
# 2.5 磁盘空间（ClickHouse + 对象存储需要空间，建议 ≥20G）
df -h /opt /var/lib/docker
```

---

## 3. 获取代码（在内网电脑上，不是服务器）

> 服务器可能无法直接访问 GitHub。先在**内网电脑**上拉取，再 scp 上传。

```bash
# 3.1 拉取两个仓库
cd ~
git clone https://github.com/philfanzhou/OpenAgent.Audit.git
cd OpenAgent.Audit && git log --oneline -1     # 确认是 173b5fa 或更新

cd ~
git clone https://github.com/philfanzhou/OpenAgent.git
cd OpenAgent && git checkout feat/audit-integration && git log --oneline -3
```

**预期看到 OpenAgent 的最新提交是 `ef58ba48` 或更新。**

```bash
# 3.2 打包（排除本地密钥、虚拟环境、构建产物）
cd ~
tar --exclude='.git' --exclude='.venv' --exclude='keys' \
    --exclude='__pycache__' --exclude='node_modules' --exclude='data' \
    -czf openagent-audit.tar.gz OpenAgent.Audit

tar --exclude='.git' --exclude='node_modules' --exclude='dist' \
    -czf openagent.tar.gz OpenAgent

ls -lh openagent*.tar.gz
```

```bash
# 3.3 传到服务器
scp openagent-audit.tar.gz openagent.tar.gz sinzoli@10.51.4.45:/tmp/
```

---

## 4. 部署 audit

### 4.1 解压

```bash
ssh sinzoli@10.51.4.45
sudo mkdir -p /opt/OpenAgent.Audit
sudo tar -xzf /tmp/openagent-audit.tar.gz -C /opt/OpenAgent.Audit --strip-components=1
cd /opt/OpenAgent.Audit && ls
```

### 4.2 生成加密密钥对

> ⚠️ **必须先保存口令再生成密钥。口令丢失 = 历史密文永久无法解密。**

```bash
cd /opt/OpenAgent.Audit
sudo mkdir -p keys

PASSPHRASE=$(openssl rand -base64 24)
echo "AUDIT_PRIVATE_KEY_PASSPHRASE=$PASSPHRASE" > /tmp/audit-passphrase.txt
chmod 600 /tmp/audit-passphrase.txt

sudo python3 scripts/provision_keys.py --out keys --passphrase "$PASSPHRASE"
sudo chmod 600 keys/audit_private_key.pem
sudo ls -l keys/
```

若服务器无 `cryptography` 库，用容器执行：

```bash
sudo docker run --rm -v "$PWD:/w" -w /w python:3.12-slim \
  sh -c "pip install -q cryptography && python scripts/provision_keys.py --out keys --passphrase '$PASSPHRASE'"
```

### 4.3 生成 `.env`

```bash
cd /opt/OpenAgent.Audit
sudo cp .env.example .env
sudo chmod 600 .env
```

逐项生成密钥（**每条命令生成一个，互不相同**）：

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
openssl rand -hex 32      # AUDIT_GATEWAY_TOKEN   ← 记下来，第 5 步要用
```

**必填清单**（留空会导致容器起不来）：

| 键 | 说明 |
|---|---|
| `NEXTAUTH_SECRET` / `SALT` / `ENCRYPTION_KEY` | Langfuse 三项，缺一不启动 |
| `LANGFUSE_DB_PASSWORD` / `CLICKHOUSE_PASSWORD` / `REDIS_PASSWORD` / `MINIO_ROOT_PASSWORD` | 基础组件 |
| `AUDIT_OWNER_PASSWORD` | 建库账号，**只给初始化用** |
| `AUDIT_AGENT_WRITER_PASSWORD` / `AUDIT_API_PASSWORD` / `AUDIT_DECRYPT_PASSWORD` / `AUDIT_RETENTION_PASSWORD` | 四个服务角色，**必须互不相同**（重复即拒绝启动） |
| `AUDIT_SERVICE_TOKEN` | audit-api → decrypt-svc |
| `AUDIT_GATEWAY_TOKEN` | 平台 → 网关，**必须与第 5.3 步一致** |
| `AUDIT_PRIVATE_KEY_PASSPHRASE` | 第 4.2 步的口令 |

**管理员账号**（哈希存储）：

```bash
python3 scripts/hash_admin_password.py --password 'admin@123456'
# 把输出填进 .env 的 AUDIT_ADMIN_PASSWORD_HASH=
```

**测试账号**（OpenAgent 未传身份时的兜底）：

```
AUDIT_TEST_USERNAME=test
AUDIT_TEST_PASSWORD=test@123456
AUDIT_TEST_SESSION_MINUTES=60
```

**身份来源**（接 OpenAgent）：

```
AUDIT_AUTH_PROVIDER=http
AUDIT_AUTH_INTROSPECT_URL=http://engine:8083/api/v1/agent/me
```

> `engine` 是 OpenAgent 在 `openagent` 网络里的服务名。如果实际服务名不同，
> 先用 `docker network inspect openagent --format '{{range .Containers}}{{.Name}} {{end}}'`
> 确认，再改这里。

> ⚠️ `.env` 里**不要写行内注释**。`KEY=value  # 说明` 会把注释当成值的一部分。

**OpenAgent 用户自动登录 audit**（推荐，需要 OpenAgent 前端配合一处小改动）：

OpenAgent 前端在跳转审计台时带上当前用户令牌即可，用户无需输入任何东西：

```
http://10.51.4.45:8100/ui/login?token={当前用户的 OpenAgent 访问令牌}
```

这一步**不是部署必需**：不接也能用测试账号进审计台。若本次不接，请在最终报告里
注明"自动登录未对接，当前靠测试账号"，交给后续前端迭代处理。

### 4.4 启动

```bash
cd /opt/OpenAgent.Audit
sudo docker compose --env-file .env up -d --build
```

首次会构建镜像并拉取 PostgreSQL / ClickHouse / Redis / MinIO / Langfuse，耗时较长。

```bash
sudo docker compose ps
sudo docker compose logs --tail=50 audit-db masking-gateway
```

**期望在 audit-db 日志里看到权限自检通过**：

```
[ok]   agent_writer cannot SELECT ciphertext
[ok]   decrypt_svc can read audit_log hash chain
privilege split verified
```

### 4.5 创建 Langfuse 项目并回填凭据

1. 浏览器打开 `http://10.51.4.45:3000`，注册初始账号
2. 新建 Organization → Project
3. Project Settings → API Keys → 复制 public / secret

```bash
cd /opt/OpenAgent.Audit
sudo sed -i 's|^LANGFUSE_PUBLIC_KEY=.*|LANGFUSE_PUBLIC_KEY=pk-lf-xxx|' .env
sudo sed -i 's|^LANGFUSE_SECRET_KEY=.*|LANGFUSE_SECRET_KEY=sk-lf-xxx|' .env
sudo docker compose --env-file .env up -d audit-api masking-gateway
```

### 4.6 验收 audit

```bash
curl -fsS http://127.0.0.1:8102/healthz        # {"ok":true,"service":"masking-gateway"}
curl -fsS http://127.0.0.1:8100/healthz        # {"ok":true,"service":"audit-api"}
curl -fsS http://127.0.0.1:8102/internal/metrics
docker network ls | grep -E 'openagent(-audit)?$'   # 应有两行
```

**浏览器验收**：`http://10.51.4.45:8100/ui/login`
- 用测试账号 `test` / `test@123456` 登录 → 应只看到「普通用户」，**没有**「登录管理员」按钮
- 能浏览会话列表（会是空的或演示数据）

> 此时 OpenAgent 还没接进来，audit 里不会有真实数据，这是正常的。

---

## 5. 升级 OpenAgent

### 5.1 备份

```bash
cd /opt/OpenAgent
TS=$(date +%F-%H%M)
sudo cp deploy/openagent/docker-compose.yml "deploy/openagent/docker-compose.yml.bak.$TS"
sudo cp .env ".env.bak.$TS"
sudo docker compose -p openagent-app -f deploy/openagent/docker-compose.yml ps > "/tmp/oa-before-$TS.txt"
echo "备份后缀：$TS"      # 记下来，回滚要用
```

### 5.2 替换代码（保留 `.env` 和证书）

```bash
sudo rm -rf /opt/OpenAgent.new
sudo mkdir -p /opt/OpenAgent.new
sudo tar -xzf /tmp/openagent.tar.gz -C /opt/OpenAgent.new --strip-components=1

# 先看差异
diff -u /opt/OpenAgent/deploy/openagent/docker-compose.yml \
        /opt/OpenAgent.new/deploy/openagent/docker-compose.yml | head -60
```

确认无误后覆盖：

```bash
sudo rsync -a \
  --exclude '.env' \
  --exclude 'deploy/openagent/nginx/certs/*' \
  --exclude '.git' \
  /opt/OpenAgent.new/ /opt/OpenAgent/

ls -l /opt/OpenAgent/.env
ls -l /opt/OpenAgent/deploy/openagent/nginx/certs/tls.crt \
      /opt/OpenAgent/deploy/openagent/nginx/certs/tls.key
```

### 5.3 补充审计相关变量

编辑 `/opt/OpenAgent/.env`，加入：

```bash
sudo tee -a /opt/OpenAgent/.env >/dev/null <<'EOF'

# ---- 审计平面 ----
OPENAGENT_AUDIT_NETWORK=openagent-audit
OPENAGENT_OTLP_TRACES_ENDPOINT=http://masking-gateway:8102
OPENAGENT_OTLP_TRACES_HEADERS=Authorization=Bearer <粘贴第 4.3 步的 AUDIT_GATEWAY_TOKEN>
OPENAGENT_OTLP_PROTOCOL=http/protobuf
EOF
```

> ⚠️ **必须粘贴令牌原文**。Docker Compose **不会**展开 `.env` 里值的 `${...}`；
> 写成 `Bearer ${AUDIT_GATEWAY_TOKEN}` 会把这段字面量当令牌发出去，网关一律 401，
> 所有 trace 被丢弃，而两边服务看起来都正常。

### 5.4 校验并构建

```bash
cd /opt/OpenAgent
sudo docker compose -p openagent-app -f deploy/openagent/docker-compose.yml \
  --env-file .env config --quiet && echo "配置有效"

sudo scripts/build-images.sh --env-file .env --docker-mode docker
```

> 脚本会构建 engine / router / runner 三个镜像。前端工作台在独立仓库
> （OpenAgent-Frontend），脚本检测到缺失会**警告并跳过**，不中断后端构建。

### 5.5 部署

```bash
sudo scripts/deploy.sh --env-file .env --docker-mode docker
```

该脚本执行 `compose up -d --no-build --pull never`：只替换容器，**不动数据卷**。

### 5.6 验收 OpenAgent

```bash
curl -fsS http://127.0.0.1:5208/health        # engine
curl -fsS http://127.0.0.1:5001/health        # router
curl -fsS -o /dev/null -w '%{http_code}\n' https://agent.monolithicpower.com:444/health   # 期望 200

# 日志应变成 JSON
sudo docker logs --tail 5 $(sudo docker ps -qf name=engine) | head -3
```

---

## 6. 端到端验收

1. 在 OpenAgent 平台发一条含手机号的对话
2. 查看网关计数器：

```bash
curl -fsS http://127.0.0.1:8102/internal/metrics
```

| 计数 | 含义 | 处理 |
|---|---|---|
| `forwarded_batches` 增长 | ✅ 正常 | 继续 |
| `batches_unauthorized` 增长 | ❌ 令牌不一致 | 核对 `AUDIT_GATEWAY_TOKEN` 与 `OPENAGENT_OTLP_TRACES_HEADERS` |
| `batches_received` 一直 0 | ❌ engine 没发到网关 | `docker logs engine \| grep -i otlp` |
| `batches_dropped` 增长 | ❌ **必须告警** | `docker compose logs masking-gateway audit-db` |

3. 确认数据落库：

```bash
sudo docker exec -it $(sudo docker ps -qf name=audit-db) psql -U audit_owner -d openagent_audit \
  -c "select entity_type, trace_id, session_id, created_at from entity_ciphertext order by created_at desc limit 5;"
```

期望 `trace_id` 是 **32 位小写 hex**，`session_id` 等于平台的 conversation id。

4. 打开审计台 `http://10.51.4.45:8100/ui/login`：
   - 用测试账号 `test` 登录 → 能看到刚才的会话，内容是脱敏的
   - 用 OpenAgent 正常账号登录 → 点「登录管理员」输入 `admin@123456` → 点击脱敏项可看原文
   - 进「审计日志」→ 能看到 `LOGIN`、`ADMIN_LOGIN`、`ENTITY_REVEALED`

---

## 7. 回滚

**OpenAgent**：

```bash
cd /opt/OpenAgent
sudo cp deploy/openagent/docker-compose.yml.bak.<TS> deploy/openagent/docker-compose.yml
sudo cp .env.bak.<TS> .env
sudo scripts/deploy.sh --env-file .env --docker-mode docker
```

**停用审计接入（保留审计数据）**：

```bash
cd /opt/OpenAgent
sudo sed -i 's|^OPENAGENT_OTLP_TRACES_ENDPOINT=.*|OPENAGENT_OTLP_TRACES_ENDPOINT=|' .env
sudo scripts/deploy.sh --env-file .env --docker-mode docker
```

**停掉 audit（OpenAgent 可继续跑）**：

```bash
cd /opt/OpenAgent.Audit
sudo docker compose --env-file .env stop
```

---

## 8. 红线（绝对不能做）

| ❌ 禁止 | 原因 |
|---|---|
| `docker compose down -v`（audit） | **删除审计数据卷**（密文库、审计日志、Langfuse 全部数据） |
| 删除 `openagent` / `openagent-audit` 网络 | 另一个栈的容器会失去连通性 |
| 用 `docker system prune -a --volumes` | 会删掉审计卷与镜像 |
| 覆盖 `/opt/OpenAgent/.env` 或 `nginx/certs/` | 丢失现网配置与证书 |
| 把 `AUDIT_OWNER_PASSWORD` 写进任何服务容器 | 破坏权限隔离 |
| 在 `.env` 里写行内注释 | 注释会被当成值的一部分 |
| 跳过备份直接 rsync | 回滚会没有依据 |

---

## 9. 已知问题排查

| 现象 | 原因 | 处理 |
|---|---|---|
| `network openagent-audit declared as external, but could not be found` | 用了旧版 compose | 用最新代码 |
| `every audit role needs a DISTINCT password` | 四个角色密码有重复 | 每个角色单独生成 |
| 网关 401，`batches_unauthorized` 增长 | `.env` 写了 `${AUDIT_GATEWAY_TOKEN}` 字面量 | 粘贴令牌原文 |
| `build-images.sh: syntax error near unexpected token` | 脚本是 CRLF | `sudo sed -i 's/\r$//' scripts/*.sh` |
| `unable to prepare context: path ".../Backend/src/..."` | 用了拆分前的旧脚本 | 确认已拉最新代码 |
| `warning: Frontend/OpenAgent.Chat/Dockerfile not found` | 前端在独立仓库 | 正常，后端照常构建 |
| audit-web 会话页 500 | `LANGFUSE_*` 为空 | 完成 4.5 后重启 `audit-api` |
| 测试账号登录后仍能看到「登录管理员」 | 代码不是最新版 | 确认 audit 提交为 `173b5fa` 或更新 |

---

## 10. 交付清单

请逐项确认并在最后报告：

- [ ] audit 容器全部 running（`docker compose ps`）
- [ ] audit 权限自检输出 `privilege split verified`
- [ ] `curl http://127.0.0.1:8102/healthz` 与 `:8100/healthz` 均 200
- [ ] OpenAgent health 全部 200，外链 `https://agent.monolithicpower.com:444/health` 为 200
- [ ] `forwarded_batches` 有增长且 `batches_dropped` 为 0
- [ ] 审计台能看到真实会话，且内容是脱敏的
- [ ] 审计台里**没有**演示数据（会话编号不以 `sess-demo-` 开头）；若有，说明真实数据已到但演示数据未清除，立即报告
- [ ] 管理员登录后可查看原文，审计日志有对应记录
- [ ] 备份文件路径已记录

**报告中请附上**：audit 与 OpenAgent 的最终提交号、`internal/metrics` 输出、
任何偏离本提示词的操作。