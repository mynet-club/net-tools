#!/usr/bin/env python3
"""
SQLite -> MariaDB 数据迁移脚本
在服务器上运行: python3 migrate_sqlite_to_mysql.py [sqlite_db_path]
默认路径: /root/.config/subserver/data/subserver.db
"""

import json
import sqlite3
import subprocess
import sys

SQLITE_PATH = sys.argv[1] if len(
    sys.argv) > 1 else '/root/.config/subserver/data/subserver.db'
MYSQL_USER = 'root'
MYSQL_PASS = 'Lyt@2017'
MYSQL_DB = 'subserver'

SCHEMA_SQL = """
CREATE DATABASE IF NOT EXISTS subserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE subserver;

CREATE TABLE IF NOT EXISTS users (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  token          VARCHAR(64) NOT NULL UNIQUE,
  name           VARCHAR(100) NOT NULL,
  note           TEXT,
  enabled        TINYINT(1) DEFAULT 1,
  username       VARCHAR(50) DEFAULT NULL,
  password_hash  VARCHAR(255) DEFAULT NULL,
  role           VARCHAR(10) DEFAULT 'user',
  email          VARCHAR(255) DEFAULT NULL,
  email_verified TINYINT(1) DEFAULT 0,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY idx_users_username (username),
  UNIQUE KEY idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nodes (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(100) NOT NULL UNIQUE,
  display_name    VARCHAR(100) NOT NULL DEFAULT '',
  type            VARCHAR(20) NOT NULL,
  server          VARCHAR(255) NOT NULL,
  port            INT NOT NULL,
  pubkey          VARCHAR(255) DEFAULT NULL,
  shortid         VARCHAR(64) DEFAULT NULL,
  sni             VARCHAR(255) DEFAULT NULL,
  flow            VARCHAR(50) DEFAULT 'xtls-rprx-vision',
  fingerprint     VARCHAR(20) DEFAULT 'chrome',
  alter_id        INT DEFAULT 0,
  cipher          VARCHAR(20) DEFAULT 'auto',
  network         VARCHAR(10) DEFAULT 'tcp',
  ws_path         VARCHAR(255) DEFAULT '',
  ws_host         VARCHAR(255) DEFAULT '',
  tls             TINYINT(1) DEFAULT 0,
  tls_sni         VARCHAR(255) DEFAULT '',
  skip_cert       TINYINT(1) DEFAULT 0,
  enabled         TINYINT(1) DEFAULT 1,
  sort_order      INT DEFAULT 0,
  api_host        VARCHAR(255) DEFAULT NULL,
  api_port        INT DEFAULT 2088,
  api_token       VARCHAR(255) DEFAULT NULL,
  has_upstream_api TINYINT(1) DEFAULT 0,
  INDEX idx_nodes_sort (sort_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_node_uuids (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  user_id  INT NOT NULL,
  node_id  INT NOT NULL,
  uuid     VARCHAR(64) NOT NULL,
  enabled  TINYINT(1) NOT NULL DEFAULT 1,
  UNIQUE KEY uk_user_node (user_id, node_id),
  INDEX idx_user_node_uuids_user (user_id),
  INDEX idx_user_node_uuids_node (node_id),
  CONSTRAINT fk_mapping_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_mapping_node FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS templates (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  content     MEDIUMTEXT NOT NULL,
  enabled     TINYINT(1) DEFAULT 1,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS invite_codes (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  code       VARCHAR(16) NOT NULL UNIQUE,
  created_by INT DEFAULT 0,
  used_by    INT DEFAULT NULL,
  used_at    TIMESTAMP NULL DEFAULT NULL,
  enabled    TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_invite_codes_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS email_tokens (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  user_id    INT NOT NULL,
  token      VARCHAR(64) NOT NULL UNIQUE,
  type       VARCHAR(10) NOT NULL,
  expires    DATETIME NOT NULL,
  used       TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email_tokens_token (token),
  INDEX idx_email_tokens_user (user_id),
  CONSTRAINT fk_email_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def escape_val(v):
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(v)
    s = str(v)
    s = s.replace('\\', '\\\\').replace("'", "\\'").replace(
        '\n', '\\n').replace('\r', '\\r')
    return "'" + s + "'"


def migrate_table(conn, table):
    cursor = conn.execute("SELECT * FROM " + table)
    cols = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    if not rows:
        print("  %s: 0 rows (skip)" % table)
        return []
    statements = []
    for row in rows:
        vals = [escape_val(row[i]) for i in range(len(cols))]
        col_names = ', '.join(cols)
        val_str = ', '.join(vals)
        statements.append(
            "INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s=%s;"
            % (table, col_names, val_str, cols[0], cols[0])
        )
    print("  %s: %d rows" % (table, len(rows)))
    return statements


def run_mysql(sql):
    proc = subprocess.run(
        ['mysql', '-u' + MYSQL_USER, '-p' + MYSQL_PASS,
            '--default-character-set=utf8mb4'],
        input=sql, capture_output=True, text=True
    )
    if proc.returncode != 0:
        err = '\n'.join(l for l in proc.stderr.splitlines()
                        if 'Using a password' not in l)
        if err.strip():
            print("  MySQL ERROR: " + err, file=sys.stderr)
            return False
    return True


def main():
    print("=== SQLite -> MariaDB ===")
    print("  src: " + SQLITE_PATH)
    print("  dst: MariaDB/" + MYSQL_DB)
    print()

    try:
        conn = sqlite3.connect(SQLITE_PATH)
    except Exception as e:
        print("Cannot open SQLite: " + str(e), file=sys.stderr)
        sys.exit(1)

    print("[1/3] Creating schema...")
    if not run_mysql(SCHEMA_SQL):
        print("Schema creation failed", file=sys.stderr)
        sys.exit(1)
    print("  ok")

    print("[2/3] Migrating data...")
    all_sql = ["USE " + MYSQL_DB + ";", "SET FOREIGN_KEY_CHECKS=0;"]
    for table in ['users', 'nodes', 'user_node_uuids', 'templates', 'invite_codes', 'email_tokens']:
        stmts = migrate_table(conn, table)
        all_sql.extend(stmts)
    all_sql.append("SET FOREIGN_KEY_CHECKS=1;")
    conn.close()

    print("[3/3] Writing to MariaDB...")
    if run_mysql('\n'.join(all_sql)):
        print("  ok")
    else:
        print("Data write failed", file=sys.stderr)
        sys.exit(1)

    verify_sql = (
        "USE " + MYSQL_DB + "; "
        "SELECT 'users' as t, COUNT(*) as c FROM users "
        "UNION ALL SELECT 'nodes', COUNT(*) FROM nodes "
        "UNION ALL SELECT 'user_node_uuids', COUNT(*) FROM user_node_uuids "
        "UNION ALL SELECT 'templates', COUNT(*) FROM templates "
        "UNION ALL SELECT 'invite_codes', COUNT(*) FROM invite_codes;"
    )
    proc = subprocess.run(
        ['mysql', '-u' + MYSQL_USER, '-p' + MYSQL_PASS, '-t'],
        input=verify_sql, capture_output=True, text=True
    )
    print("\n=== Verify ===")
    print(proc.stdout)
    print("Done!")


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
SQLite → MariaDB 数据迁移脚本
在服务器上运行: python3 migrate_sqlite_to_mysql.py [sqlite_db_path]
默认路径: /root/.config/subserver/data/subserver.db
"""


SQLITE_PATH = sys.argv[1] if len(
    sys.argv) > 1 else '/root/.config/subserver/data/subserver.db'
MYSQL_USER = 'root'
MYSQL_PASS = 'Lyt@2017'
MYSQL_DB = 'subserver'

# ── MariaDB Schema (与 db.js initDb 完全一致) ──────────────────────
SCHEMA_SQL = """
CREATE DATABASE IF NOT EXISTS subserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE subserver;

CREATE TABLE IF NOT EXISTS users (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  token          VARCHAR(64) NOT NULL UNIQUE,
  name           VARCHAR(100) NOT NULL,
  note           TEXT,
  enabled        TINYINT(1) DEFAULT 1,
  username       VARCHAR(50) DEFAULT NULL,
  password_hash  VARCHAR(255) DEFAULT NULL,
  role           VARCHAR(10) DEFAULT 'user',
  email          VARCHAR(255) DEFAULT NULL,
  email_verified TINYINT(1) DEFAULT 0,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY idx_users_username (username),
  UNIQUE KEY idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nodes (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(100) NOT NULL UNIQUE,
  display_name    VARCHAR(100) NOT NULL DEFAULT '',
  type            VARCHAR(20) NOT NULL,
  server          VARCHAR(255) NOT NULL,
  port            INT NOT NULL,
  pubkey          VARCHAR(255) DEFAULT NULL,
  shortid         VARCHAR(64) DEFAULT NULL,
  sni             VARCHAR(255) DEFAULT NULL,
  flow            VARCHAR(50) DEFAULT 'xtls-rprx-vision',
  fingerprint     VARCHAR(20) DEFAULT 'chrome',
  alter_id        INT DEFAULT 0,
  cipher          VARCHAR(20) DEFAULT 'auto',
  network         VARCHAR(10) DEFAULT 'tcp',
  ws_path         VARCHAR(255) DEFAULT '',
  ws_host         VARCHAR(255) DEFAULT '',
  tls             TINYINT(1) DEFAULT 0,
  tls_sni         VARCHAR(255) DEFAULT '',
  skip_cert       TINYINT(1) DEFAULT 0,
  enabled         TINYINT(1) DEFAULT 1,
  sort_order      INT DEFAULT 0,
  api_host        VARCHAR(255) DEFAULT NULL,
  api_port        INT DEFAULT 2088,
  api_token       VARCHAR(255) DEFAULT NULL,
  has_upstream_api TINYINT(1) DEFAULT 0,
  INDEX idx_nodes_sort (sort_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_node_uuids (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  user_id  INT NOT NULL,
  node_id  INT NOT NULL,
  uuid     VARCHAR(64) NOT NULL,
  enabled  TINYINT(1) NOT NULL DEFAULT 1,
  UNIQUE KEY uk_user_node (user_id, node_id),
  INDEX idx_user_node_uuids_user (user_id),
  INDEX idx_user_node_uuids_node (node_id),
  CONSTRAINT fk_mapping_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_mapping_node FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS templates (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  content     MEDIUMTEXT NOT NULL,
  enabled     TINYINT(1) DEFAULT 1,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS invite_codes (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  code       VARCHAR(16) NOT NULL UNIQUE,
  created_by INT DEFAULT 0,
  used_by    INT DEFAULT NULL,
  used_at    TIMESTAMP NULL DEFAULT NULL,
  enabled    TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_invite_codes_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS email_tokens (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  user_id    INT NOT NULL,
  token      VARCHAR(64) NOT NULL UNIQUE,
  type       VARCHAR(10) NOT NULL,
  expires    DATETIME NOT NULL,
  used       TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email_tokens_token (token),
  INDEX idx_email_tokens_user (user_id),
  CONSTRAINT fk_email_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def escape_val(v):
    """转义 SQL 值"""
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(v)
    s = str(v)
    s = s.replace('\\', '\\\\').replace("'", "\\'").replace(
        '\n', '\\n').replace('\r', '\\r')
    return f"'{s}'"


def migrate_table(conn, table):
    """读取 SQLite 表数据，生成 INSERT 语句"""
    cursor = conn.execute(f"SELECT * FROM {table}")
    cols = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    if not rows:
        print(f"  {table}: 0 rows (skip)")
        return []

    statements = []
    for row in rows:
        vals = [escape_val(row[i]) for i in range(len(cols))]
        col_names = ', '.join(cols)
        val_str = ', '.join(vals)
        # ON DUPLICATE KEY UPDATE 用第一列做 no-op
        statements.append(
            f"INSERT INTO {table} ({col_names}) VALUES ({val_str}) "
            f"ON DUPLICATE KEY UPDATE {cols[0]}={cols[0]};"
        )

    print(f"  {table}: {len(rows)} rows")
    return statements


def run_mysql(sql):
    """通过 mysql CLI 执行 SQL"""
    proc = subprocess.run(
        ['mysql', f'-u{MYSQL_USER}', f'-p{MYSQL_PASS}',
            '--default-character-set=utf8mb4'],
        input=sql, capture_output=True, text=True
    )
    if proc.returncode != 0:
        err = '\n'.join(l for l in proc.stderr.splitlines()
                        if 'Using a password' not in l)
        if err.strip():
            print(f"  MySQL ERROR: {err}", file=sys.stderr)
            return False
    return True


def main():
    print(f"=== SQLite → MariaDB 迁移 ===")
    print(f"  源: {SQLITE_PATH}")
    print(f"  目标: MariaDB/{MYSQL_DB}")
    print()

    # 1. 连接 SQLite
    try:
        conn = sqlite3.connect(SQLITE_PATH)
    except Exception as e:
        print(f"✗ 无法打开 SQLite: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. 创建 schema
    print("[1/3] 创建 MariaDB schema...")
    if not run_mysql(SCHEMA_SQL):
        print("✗ Schema 创建失败", file=sys.stderr)
        sys.exit(1)
    print("  ✓ schema ready")

    # 3. 迁移数据（按外键顺序）
    print("[2/3] 迁移数据...")
    all_sql = [f"USE {MYSQL_DB};", "SET FOREIGN_KEY_CHECKS=0;"]

    for table in ['users', 'nodes', 'user_node_uuids', 'templates', 'invite_codes', 'email_tokens']:
        stmts = migrate_table(conn, table)
        all_sql.extend(stmts)

    all_sql.append("SET FOREIGN_KEY_CHECKS=1;")
    conn.close()

    # 4. 执行插入
    print("[3/3] 写入 MariaDB...")
    batch_sql = '\n'.join(all_sql)
    if run_mysql(batch_sql):
        print("  ✓ 数据迁移完成")
    else:
        print("✗ 数据写入失败", file=sys.stderr)
        sys.exit(1)

    # 5. 验证
    verify_sql = (
        f"USE {MYSQL_DB}; "
        "SELECT 'users' as t, COUNT(*) as c FROM users "
        "UNION ALL SELECT 'nodes', COUNT(*) FROM nodes "
        "UNION ALL SELECT 'user_node_uuids', COUNT(*) FROM user_node_uuids "
        "UNION ALL SELECT 'templates', COUNT(*) FROM templates "
        "UNION ALL SELECT 'invite_codes', COUNT(*) FROM invite_codes;"
    )
    proc = subprocess.run(
        ['mysql', f'-u{MYSQL_USER}', f'-p{MYSQL_PASS}', '-t'],
        input=verify_sql, capture_output=True, text=True
    )
    print(f"\n=== 验证 ===\n{proc.stdout}")
    print("✓ 迁移完成！")


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
SQLite → MariaDB 数据迁移脚本
在服务器上运行: python3 migrate_sqlite_to_mysql.py [sqlite_db_path]
默认路径: /root/.config/subserver/data/subserver.db
"""


SQLITE_PATH = sys.argv[1] if len(
    sys.argv) > 1 else '/root/.config/subserver/data/subserver.db'
MYSQL_USER = 'root'
MYSQL_PASS = 'Lyt@2017'
MYSQL_DB = 'subserver'

# ── MariaDB Schema (与 db.js initDb 保持一致) ──────────────────────
SCHEMA_SQL = """
CREATE DATABASE IF NOT EXISTS subserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE subserver;

CREATE TABLE IF NOT EXISTS users (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  token          VARCHAR(64) NOT NULL UNIQUE,
  name           VARCHAR(100) NOT NULL,
  note           TEXT,
  enabled        TINYINT(1) DEFAULT 1,
  username       VARCHAR(50) DEFAULT NULL,
  password_hash  VARCHAR(255) DEFAULT NULL,
  role           VARCHAR(10) DEFAULT 'user',
  email          VARCHAR(255) DEFAULT NULL,
  email_verified TINYINT(1) DEFAULT 0,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY idx_users_username (username),
  UNIQUE KEY idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nodes (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(100) NOT NULL UNIQUE,
  display_name    VARCHAR(100) NOT NULL DEFAULT '',
  type            VARCHAR(20) NOT NULL,
  server          VARCHAR(255) NOT NULL,
  port            INT NOT NULL,
  pubkey          VARCHAR(255) DEFAULT NULL,
  shortid         VARCHAR(64) DEFAULT NULL,
  sni             VARCHAR(255) DEFAULT NULL,
  flow            VARCHAR(50) DEFAULT 'xtls-rprx-vision',
  fingerprint     VARCHAR(20) DEFAULT 'chrome',
  alter_id        INT DEFAULT 0,
  cipher          VARCHAR(20) DEFAULT 'auto',
  network         VARCHAR(10) DEFAULT 'tcp',
  ws_path         VARCHAR(255) DEFAULT '',
  ws_host         VARCHAR(255) DEFAULT '',
  tls             TINYINT(1) DEFAULT 0,
  tls_sni         VARCHAR(255) DEFAULT '',
  skip_cert       TINYINT(1) DEFAULT 0,
  enabled         TINYINT(1) DEFAULT 1,
  sort_order      INT DEFAULT 0,
  api_host        VARCHAR(255) DEFAULT NULL,
  api_port        INT DEFAULT 2088,
  api_token       VARCHAR(255) DEFAULT NULL,
  has_upstream_api TINYINT(1) DEFAULT 0,
  INDEX idx_nodes_sort (sort_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_node_uuids (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  user_id  INT NOT NULL,
  node_id  INT NOT NULL,
  uuid     VARCHAR(64) NOT NULL,
  enabled  TINYINT(1) NOT NULL DEFAULT 1,
  UNIQUE KEY uk_user_node (user_id, node_id),
  INDEX idx_user_node_uuids_user (user_id),
  INDEX idx_user_node_uuids_node (node_id),
  CONSTRAINT fk_mapping_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_mapping_node FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS templates (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  content     MEDIUMTEXT NOT NULL,
  enabled     TINYINT(1) DEFAULT 1,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS invite_codes (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  code        VARCHAR(16) NOT NULL UNIQUE,
  created_by  INT DEFAULT 0,
  used_by     INT DEFAULT NULL,
  used_at     TIMESTAMP NULL DEFAULT NULL,
  enabled     TINYINT(1) DEFAULT 1,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_invite_codes_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS email_tokens (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  token       VARCHAR(64) NOT NULL UNIQUE,
  type        VARCHAR(10) NOT NULL,
  expires     DATETIME NOT NULL,
  used        TINYINT(1) DEFAULT 0,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email_tokens_token (token),
  INDEX idx_email_tokens_user (user_id),
  CONSTRAINT fk_email_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def escape_val(v):
    """转义 SQL 值"""
    if v is None:
        return 'NULL'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(v)
    s = str(v)
    s = s.replace('\\', '\\\\').replace("'", "\\'").replace(
        '\n', '\\n').replace('\r', '\\r')
    return f"'{s}'"


# 列映射: SQLite 有但 MariaDB 没有的列 (跳过)
SKIP_COLUMNS = {
    # (user_node_uuids 的 id 列在 MariaDB 中也存在，无需跳过)
}


def migrate_table(conn, table, columns_map=None):
    """读取 SQLite 表数据，生成 INSERT 语句"""
    cursor = conn.execute(f"SELECT * FROM {table}")
    cols = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    # 过滤掉 MariaDB 不存在的列
    skip = SKIP_COLUMNS.get(table, [])
    keep_idx = [i for i, c in enumerate(cols) if c not in skip]
    cols = [cols[i] for i in keep_idx]

    if not rows:
        print(f"  {table}: 0 rows (skip)")
        return []

    statements = []
    for row in rows:
        vals = []
        for i in keep_idx:
            v = row[i]
            vals.append(escape_val(v))
        col_names = ', '.join(cols)
        val_str = ', '.join(vals)
        statements.append(
            f"INSERT INTO {table} ({col_names}) VALUES ({val_str}) ON DUPLICATE KEY UPDATE {cols[0]}={cols[0]};"
        )

    print(f"  {table}: {len(rows)} rows")
    return statements


def run_mysql(sql):
    """通过 mysql CLI 执行 SQL"""
    proc = subprocess.run(
        ['mysql', f'-u{MYSQL_USER}', f'-p{MYSQL_PASS}',
            '--default-character-set=utf8mb4'],
        input=sql, capture_output=True, text=True
    )
    if proc.returncode != 0:
        # 忽略 password warning
        err = '\n'.join(l for l in proc.stderr.splitlines()
                        if 'Using a password' not in l)
        if err.strip():
            print(f"  MySQL ERROR: {err}", file=sys.stderr)
            return False
    return True


def main():
    print(f"=== SQLite → MariaDB 迁移 ===")
    print(f"  源: {SQLITE_PATH}")
    print(f"  目标: MariaDB/{MYSQL_DB}")
    print()

    # 1. 连接 SQLite
    try:
        conn = sqlite3.connect(SQLITE_PATH)
    except Exception as e:
        print(f"✗ 无法打开 SQLite: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. 创建 schema
    print("[1/3] 创建 MariaDB schema...")
    if not run_mysql(SCHEMA_SQL):
        print("✗ Schema 创建失败", file=sys.stderr)
        sys.exit(1)
    print("  ✓ schema ready")

    # 3. 迁移数据（按外键顺序）
    print("[2/3] 迁移数据...")
    all_sql = [f"USE {MYSQL_DB};", "SET FOREIGN_KEY_CHECKS=0;"]

    for table in ['users', 'nodes', 'user_node_uuids', 'templates', 'invite_codes', 'email_tokens']:
        stmts = migrate_table(conn, table)
        all_sql.extend(stmts)

    all_sql.append("SET FOREIGN_KEY_CHECKS=1;")
    conn.close()

    # 4. 执行插入
    print("[3/3] 写入 MariaDB...")
    batch_sql = '\n'.join(all_sql)
    if run_mysql(batch_sql):
        print("  ✓ 数据迁移完成")
    else:
        print("✗ 数据写入失败", file=sys.stderr)
        sys.exit(1)

    # 5. 验证
    verify_sql = f"USE {MYSQL_DB}; SELECT 'users' as t, COUNT(*) as c FROM users UNION ALL SELECT 'nodes', COUNT(*) FROM nodes UNION ALL SELECT 'user_node_uuids', COUNT(*) FROM user_node_uuids UNION ALL SELECT 'templates', COUNT(*) FROM templates UNION ALL SELECT 'invite_codes', COUNT(*) FROM invite_codes;"
    proc = subprocess.run(
        ['mysql', f'-u{MYSQL_USER}', f'-p{MYSQL_PASS}', '-t'],
        input=verify_sql, capture_output=True, text=True
    )
    out = '\n'.join(l for l in proc.stdout.splitlines())
    print(f"\n=== 验证 ===\n{out}")
    print("\n✓ 迁移完成！")


if __name__ == '__main__':
    main()
