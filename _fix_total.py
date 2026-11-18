import pathlib

def patch(path, old, new, label):
    p = pathlib.Path(path)
    with p.open("r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    newline = "\r\n" if "\r\n" in text else "\n"
    o = old.replace("\n", newline)
    n = new.replace("\n", newline)
    assert o in text, f"{label}: anchor missing"
    text = text.replace(o, n, 1)
    p.write_bytes(text.encode("utf-8"))
    print(f"OK: {label}")

V = r"D:\OpenAgent.Audit\frontend\src\views"

patch(
    V + r"\SessionsView.vue",
    '''      <form class="jump-form" @submit.prevent="jump">
        <span class="jump-label">跳至第</span>
        <el-input v-model="jumpTo" class="jump-input" placeholder="页码" @keyup.enter="jump" />
        <span class="jump-label">页</span>
        <el-button type="primary" plain size="small" native-type="submit">跳转</el-button>
      </form>''',
    '''      <form class="jump-form" @submit.prevent="jump">
        <span class="jump-label">跳至第</span>
        <el-input v-model="jumpTo" class="jump-input" placeholder="页码" @keyup.enter="jump" />
        <span class="jump-label">页</span>
        <el-button type="primary" plain size="small" native-type="submit">跳转</el-button>
        <span class="jump-label">共 {{ totalPages }} 页</span>
      </form>''',
    "sessions jump shows total",
)

patch(
    V + r"\AuditLogView.vue",
    '''      <form class="jump-form" @submit.prevent="jump">
        <span class="jump-label">跳至第</span>
        <el-input v-model="jumpTo" class="jump-input" placeholder="页码" @keyup.enter="jump" />
        <span class="jump-label">页</span>
        <el-button type="primary" plain size="small" native-type="submit">跳转</el-button>
      </form>''',
    '''      <form class="jump-form" @submit.prevent="jump">
        <span class="jump-label">跳至第</span>
        <el-input v-model="jumpTo" class="jump-input" placeholder="页码" @keyup.enter="jump" />
        <span class="jump-label">页</span>
        <el-button type="primary" plain size="small" native-type="submit">跳转</el-button>
        <span class="jump-label">共 {{ total }} 页</span>
      </form>''',
    "audit log jump shows total",
)

print("both views show total pages")