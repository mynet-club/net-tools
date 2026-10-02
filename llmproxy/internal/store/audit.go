package store

// auditSchema 是 var：scope 两列的定义与老库 ALTER 共用 scope_schema.go 那一份。
//
// 按范围导审计（§2.7 规则 2：组织/项目管理员只看得到自己范围内的那些动作）的索引
// idx_audit_scope **不在这里建**：老库的 audit_log 这时还没有 scope_kind 列，在这里建会撞
// 「列不存在」而让 Open 失败。它由 migrateScopeSchema 在补完列之后按 scopeIndexDDL30 建 ——
// 新库与老库共用那一条语句，幂等。
var auditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
` + scopeColsFragment(auditScopeCols30) + `,
  actor      TEXT    NOT NULL DEFAULT '',
  action     TEXT    NOT NULL,
  target     TEXT    NOT NULL DEFAULT '',
  detail     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
`

// AuditEntry 与无范围的 Audit / AuditRecent 已经随 §2.7 规则 8 删除：审计表从 2.x 起
// 就有 scope_kind + scope_id 两列，一个不带范围的读写接口只是把它们假装丢掉。
//
// 写侧唯一入口是 AuditScope（scope 由调用方给出「这条动作关于哪个范围」），
// 读侧是 AuditRecentAll / AuditRecentByScope / AuditRecentForScopes，
// 三者都返回 ScopedAuditEntry —— Detail 沿用旧口径：不许写密钥明文。

// AuditRecentAll 返回最近 n 条审计（新的在前），不分范围。
//
// 这是网关管理员的全局面板用的那一条；组织/项目管理员的视图走 AuditRecentForScopes。
// 返回条目带 scope，所以「全量列一下」也不会把归属信息读丢。
func (s *Store) AuditRecentAll(n int) ([]ScopedAuditEntry, error) {
	return s.queryScopedAudit(`SELECT `+auditScopedCols+` FROM audit_log ORDER BY id DESC LIMIT ?`,
		auditLimit(n))
}
