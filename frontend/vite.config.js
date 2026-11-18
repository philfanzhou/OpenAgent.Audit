import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发期把 API 请求代理到本机 audit-api（run_local.py 默认 8100）；
// 生产构建产出纯静态文件，由 audit-api 直接托管（离线部署可用）。
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/v1': 'http://127.0.0.1:8100',
      '/ui': 'http://127.0.0.1:8100',
      '/console': 'http://127.0.0.1:8100'
    }
  },
  build: {
    outDir: 'dist'
  }
})
