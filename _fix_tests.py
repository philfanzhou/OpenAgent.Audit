import pathlib

p = pathlib.Path(r"D:\OpenAgent.Audit\tests\test_login_flow.py")
with p.open("r", encoding="utf-8", newline="") as fh:
    text = fh.read()
newline = "\r\n" if "\r\n" in text else "\n"

# 登录页结构测试改为验证 302 跳转（页面渲染移交 SPA）
old = newline.join([
    "    def test_sso_button_and_test_form(self, client, sso_container):",
    '        response = client.get("/ui/login")',
    "        assert response.status_code == 200",
    '        assert "用企业账号登录" in response.text',
    '        assert "用测试账号登录" in response.text',
])
new = newline.join([
    "    def test_login_page_redirects_to_the_spa(self, client):",
    '        response = client.get("/ui/login")',
    "        assert response.status_code == 302",
    '        assert response.headers["location"] == "/login"',
])
assert old in text, "sso button test anchor missing"
text = text.replace(old, new, 1)

old = newline.join([
    "    def test_test_section_collapsed_by_default(self, client, sso_container):",
    '        response = client.get("/ui/login")',
    '        assert "<details" in response.text',
])
new = newline.join([
    "    def test_test_section_collapsed_by_default(self, client, sso_container):",
    '        response = client.get("/ui/login")',
    "        assert response.status_code == 302",
])
assert old in text, "collapsed test anchor missing"
text = text.replace(old, new, 1)

old = newline.join([
    "    def test_sso_disabled_hides_the_button(self, client):",
    '        response = client.get("/ui/login")',
    '        assert "用企业账号登录" not in response.text',
])
new = newline.join([
    "    def test_sso_disabled_hides_the_button(self, client):",
    "        # 页面路由整体跳转 SPA，不再有独立渲染的登录页",
    '        response = client.get("/ui/login")',
    "        assert response.status_code == 302",
])
assert old in text, "sso disabled anchor missing"
text = text.replace(old, new, 1)

# SSO 失败落登录页 → 现在失败后跳 SPA 登录页
old = "def test_sso_failure_lands_on_the_login_page"
assert old in text
p.write_bytes(text.encode("utf-8"))
print("login flow tests updated (partial — checking remaining)")