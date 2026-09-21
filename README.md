# worker-assets-auth

## W8 生产收尾结果（2026-09-18 00:06:11 +08:00）

新版本已完成本地门禁、跨仓库契约校验、生产 dry-run、远程图片健康采样和博客联动回归后发布。图片 URL 现在必须使用 `key + etag + exp` 的版本化签名；旧 `key + exp` 兼容分支已从 Worker 和签名模块移除。

### 已清理的 Preview 测试资产

- 已移除故障注入 Worker、Preview 专用 Wrangler 配置、Preview 临时密钥文件及相关验证脚本和测试。
- 已删除远程 `assets-auth-preview` 与 `assets-auth-g4-preview` 测试 Worker；生产 Worker `assets-auth` 未被删除。
- 历史交接文档中的 Preview 记录仅作为审计轨迹保留，不代表当前仍有活动配置或流量。

### 保留的运维边界

- Cloudflare Cache Rule 由项目方后续自行添加，本仓库未修改控制面配置。
- 生产 Worker 的 R2、Token 和签名 Secret 绑定未撤销；它们仍由 Wrangler 生产配置管理。
- 同 key 覆盖的 ETag 隔离、旧版本 410、缓存命中、Range 和错误响应门禁已通过。

## 本地验证

```bash
pnpm install
pnpm test
pnpm check
pnpm verify:gallery-contract
pnpm benchmark:dimensions
```

本地运行前请将真实的 `GALLERY_API_TOKEN` 与 `SIGNING_SECRET` 写入未纳入版本控制的 `.dev.vars`，不要把密钥提交到仓库。生产环境的 Worker bindings、版本发布、回滚与 Secret 更新均通过 Wrangler 执行。

### 最终放行（2026-09-18 00:06:11 +08:00）

本地门禁、新签名契约、远程生产图片健康采样、博客联合回归和清理后仓库扫描均通过；当前生产功能按负责人单轮验收口径 GO。Cache Rule 仍由项目方后续自行添加。
