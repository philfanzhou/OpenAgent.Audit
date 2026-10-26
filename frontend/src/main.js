import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import App from "./App.vue";
import "./style.css";

import LoginView from "./views/LoginView.vue";
import SessionsView from "./views/SessionsView.vue";
import SessionDetailView from "./views/SessionDetailView.vue";
import RequestsView from "./views/RequestsView.vue";
import AuditLogView from "./views/AuditLogView.vue";
import MetricsView from "./views/MetricsView.vue";
import { auth } from "./store.js";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/login", component: LoginView },
    { path: "/", redirect: "/sessions" },
    { path: "/sessions", component: SessionsView, meta: { needsAuth: true } },
    { path: "/sessions/:sessionId", component: SessionDetailView, meta: { needsAuth: true } },
    { path: "/requests", component: RequestsView, meta: { needsAuth: true } },
    { path: "/audit-log", component: AuditLogView, meta: { needsAuth: true } },
    { path: "/metrics", component: MetricsView, meta: { needsAuth: true } },
  ],
});

router.beforeEach((to) => {
  if (to.meta.needsAuth && !auth.token) return "/login";
});

createApp(App).use(router).mount("#app");
