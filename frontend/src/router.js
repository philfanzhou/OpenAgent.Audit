import { createRouter, createWebHistory } from 'vue-router'
import { api } from './api'
import { auth, setPrincipal, clearPrincipal } from './store'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/sessions' },
    { path: '/login', name: 'login', component: () => import('./views/LoginView.vue'), meta: { public: true } },
    { path: '/sessions', name: 'sessions', component: () => import('./views/SessionsView.vue') },
    { path: '/sessions/:id', name: 'session-detail', component: () => import('./views/SessionDetailView.vue') },
    { path: '/audit-log', name: 'audit-log', component: () => import('./views/AuditLogView.vue') },
    { path: '/:pathMatch(.*)*', redirect: '/sessions' }
  ]
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  if (!auth.loaded) {
    try {
      setPrincipal(await api.me())
    } catch {
      clearPrincipal()
      return { path: '/login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : {} }
    }
  }
  if (auth.isAdmin) return true
  if (to.path === '/audit-log') return { path: '/sessions' }
  return true
})

export default router