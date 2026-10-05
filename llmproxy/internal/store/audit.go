package store

import (
	"fmt"
	"strings"
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

// AuditVolume 是审计表的规模读数。
//
// 2026-10-05 裁决（决策包 §0.1 第 15′ 行）认 audit_log **永久保留、不新增清理器**，
// 并要求「代价必须写成承诺而不是默认」—— 承诺要可数，所以这两位数得上观测面。
type AuditVolume struct {
	// Rows 是 audit_log 的行数。
	Rows int64
	// Bytes 是各行文本列的字节总数（不是磁盘占用：行开销、索引与页填充率各家引擎自己定）。
	Bytes int64
}

// auditVolumeCols 是算进体积的列。
//
// 全是建表时就 NOT NULL 的列，所以表达式里不需要逐列 COALESCE；不含 id/ts 两个整数列
// —— 这一位量的是「内容长多少」，用来盯 detail（审计表里唯一的自由文本位）的增长，
// 把行开销算进来只会让跨引擎对比更难读。
var auditVolumeCols = []string{"scope_kind", "scope_id", "actor", "action", "target", "detail"}

// AuditVolume 汇总审计表的行数与文本字节数。
//
// 这是一次**全表聚合**，而 audit_log 恰好是那张设计上只增不减的表：调用方必须是低频面
// （server 侧按 TTL 缓存后才往外报，见 internal/server/audit30.go 的 auditVolumeSnapshot），
// 不能挂在请求路径或管理口的每次读取上 —— 否则「盯着承诺有没有失控」这件事本身变成负载。
func (s *Store) AuditVolume() (AuditVolume, error) {
	exprs := make([]string, 0, len(auditVolumeCols))
	for _, c := range auditVolumeCols {
		exprs = append(exprs, s.dialect.TextBytes(c))
	}
	// SUM 在零行表上返回 NULL 而不是 0：不套 COALESCE 的话 Scan 直接报错，
	// 于是「一张干净的库」会被读成「指标读不出来」—— 恰好把要报的两种状态弄反。
	q := fmt.Sprintf(`SELECT COUNT(*), COALESCE(SUM(%s), 0) FROM audit_log`,
		strings.Join(exprs, " + "))
	var out AuditVolume
	if err := s.queryRow(q).Scan(&out.Rows, &out.Bytes); err != nil {
		return AuditVolume{}, fmt.Errorf("审计表规模统计失败: %w", err)
	}
	return out, nil
}
