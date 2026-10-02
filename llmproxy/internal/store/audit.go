package store

import (
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

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

// AuditEntry 是一条管理操作审计。detail **不许**写密钥明文。
type AuditEntry struct {
	Ts     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
}

// Audit 记一条管理操作（2.x 的无范围接口）。
//
// 2.x 的 audit_log 只记管理员的全局操作，那些操作**本来就**属于 (system,'global')，
// 所以这里固定落到系统范围是事实陈述，不是给缺省值猜一个桶。组织/项目内的操作
// 必须改走 AuditScope，把真正的范围传进来。
//
// §2.7 规则 8：主线接线完成后删除，调用方改用 AuditScope。
func (s *Store) Audit(actor, action, target, detail string) error {
	return s.AuditScope(policy.SystemScope, actor, action, target, detail)
}

// AuditRecent 返回最近 n 条审计（新的在前）。
func (s *Store) AuditRecent(n int) ([]AuditEntry, error) {
	if n <= 0 {
		n = 100
	}
	rows, err := s.query(`SELECT ts, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&ts, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.Ts = time.UnixMilli(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
