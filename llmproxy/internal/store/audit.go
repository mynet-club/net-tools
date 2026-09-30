package store

import "time"

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
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

// Audit 记一条管理操作。
func (s *Store) Audit(actor, action, target, detail string) error {
	if action == "" {
		return nil
	}
	_, err := s.exec(`INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?,?,?,?,?)`,
		time.Now().UnixMilli(), actor, action, target, detail)
	return err
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
