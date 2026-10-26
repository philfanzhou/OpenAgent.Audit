import { reactive } from "vue";

// Tiny auth store: bearer token + current principal, persisted in
// localStorage so a page refresh keeps the session.
export const auth = reactive({
  token: localStorage.getItem("audit_token") || "",
  username: localStorage.getItem("audit_username") || "",
  role: localStorage.getItem("audit_role") || "",

  setLogin(token, username, role) {
    this.token = token;
    this.username = username;
    this.role = role;
    localStorage.setItem("audit_token", token);
    localStorage.setItem("audit_username", username);
    localStorage.setItem("audit_role", role);
  },

  logout() {
    this.token = "";
    this.username = "";
    this.role = "";
    localStorage.removeItem("audit_token");
    localStorage.removeItem("audit_username");
    localStorage.removeItem("audit_role");
  },

  get isComplianceLead() {
    return this.role === "compliance_lead";
  },
});

export const ROLE_LABELS = {
  auditor: "审计员",
  compliance_lead: "合规主管",
  developer: "开发者",
};
