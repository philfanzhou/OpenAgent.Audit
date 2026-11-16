import pathlib

p = pathlib.Path(r"D:\OpenAgent.Audit\tests\test_sso_login.py")
with p.open("r", encoding="utf-8", newline="") as fh:
    text = fh.read()
newline = "\r\n" if "\r\n" in text else "\n"

anchor = "    async def test_no_usable_claim_fails(self):"
assert anchor in text, "anchor missing"

added = newline.join([
    "    async def test_id_token_name_used_when_userinfo_only_has_sub(self):",
    "        \"\"\"MPS SSO's live id_token answers {sub: uuid, name: sinzoli} while",
    "        userinfo may answer with the bare sub. The id_token's name claim",
    "        must win over the raw subject - the production login displayed a",
    "        UUID until this was in place.\"\"\"",
    "        mock = MockSso(",
    "            userinfo={\"sub\": \"3848856a-e825\"},",
    "            id_token_claims={\"sub\": \"3848856a-e825\", \"name\": \"sinzoli\",",
    "                             \"email\": \"sinzoli@corp.com\"},",
    "        )",
    "        client = _client(mock)",
    "",
    "        identity = await client.exchange_and_identify(BASE, \"code\", \"verifier\")",
    "",
    "        assert identity.username == \"sinzoli\"",
    "        assert identity.display_name == \"sinzoli\"",
    "",
    "    async def test_no_usable_claim_fails(self):",
])

text = text.replace(anchor, added, 1)
p.write_bytes(text.encode("utf-8"))
print("test added")