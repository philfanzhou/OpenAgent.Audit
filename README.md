# OpenAgent.Audit

OpenAgent 的审计与观测数据面：记录用户请求细节、prompt 与模型的每一次返回，承载对话审计与敏感信息的展示时脱敏。

- **trace 主数据**：Langfuse 自托管（Postgres + ClickHouse + Redis），SDK / OTLP 异步批量上报，不阻塞业务请求
- **多模态媒体**：图片 / 文件直传 S3 兼容对象存储（SeaweedFS / MinIO，SSE-KMS），trace 只存 `s3://` key + sha256 引用
- **展示时脱敏（模式 B）**：Presidio encrypt（AES-256-GCM）将敏感实体转为可逆密文 token 入库；审计界面默认渲染掩码，合规主管经 KMS 授权按条解密并全程留痕
- **存储边界**：会话业务存储（恢复 / 继续会话，业务自有在线库如 Postgres）与本库的审计存储分离，双方以 conversation id 关联；本库不作为业务数据源

Loki 仅承载普通服务日志（错误、审计事件、元数据），不承担 prompt 存储。

## 文档

- [技术方案报告（单页 HTML，可直接浏览器打开）](docs/design/agent-logging-audit-solution.html)
  - 推荐架构与数据传递通路（Agent → Langfuse / S3 / Loki）
  - trace 树示例与标识符映射（conversation / user / agent id）
  - Loki 局限与候选方案对比
  - 展示时脱敏：三视图演示、角色权限、防旁路与中文识别要点
  - 落地清单与分阶段实施路径（配置 / 轻量编码 / 自研开发）

## License

[MIT](LICENSE)
