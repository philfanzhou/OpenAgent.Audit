// 脱敏标记解析：⟦TYPE#编号|掩码⟧ → 可点击的脱敏芯片。
// 管理员点击后调用 /v1/reveal 换取原文；普通用户点击给出提示。

export const ENT_RE = /⟦([^⟧]*?)#([0-9a-fA-F]{8,})\|([^⟧]*)⟧/g

/** 把含脱敏标记的文本拆成片段：[{ type: 'text'|'ent', ... }] */
export function parseEntSegments(text) {
  const segments = []
  let last = 0
  for (const match of String(text ?? '').matchAll(ENT_RE)) {
    const start = match.index
    if (start > last) segments.push({ type: 'text', text: String(text).slice(last, start) })
    segments.push({
      type: 'ent',
      entityType: match[1],
      entityId: match[2],
      mask: match[3]
    })
    last = start + match[0].length
  }
  if (last < String(text ?? '').length) {
    segments.push({ type: 'text', text: String(text).slice(last) })
  }
  return segments
}

export function escapeHtml(text) {
  return String(text ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}
