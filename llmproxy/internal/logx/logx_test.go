package logx

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestLogger 造一个写到 buffer + 临时文件的 logger。
// maxBytes 直接设小值而不走 New 的 maxMb 参数 —— 后者单位是 MB，
// 为了触发一次轮转要写满 1MB 日志，测试没必要那么慢。
func newTestLogger(t *testing.T, level Level, maxBytes int64, keep int) (*Logger, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "llmproxy.log")
	lg := New(level, path, 1, keep)
	lg.maxBytes = maxBytes
	buf := &bytes.Buffer{}
	lg.stdout = buf
	t.Cleanup(func() { _ = lg.Close() })
	return lg, buf, path
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug": LevelDebug, "info": LevelInfo, "warn": LevelWarn, "error": LevelError,
		// 认不出来的一律退回 info：日志级别配错不该让服务起不来，
		// 也不该静默变成 debug（那会把上游错误体之类的东西全刷出来）
		"": LevelInfo, "DEBUG": LevelInfo, "verbose": LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLevelString(t *testing.T) {
	for lv, want := range map[Level]string{
		LevelDebug: "DEBUG", LevelInfo: "INFO", LevelWarn: "WARN", LevelError: "ERROR",
	} {
		if got := lv.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", lv, got, want)
		}
	}
	if got := Level(99).String(); got != "?" {
		t.Errorf("未知级别应当是 ?，实际 %q", got)
	}
}

// 级别过滤：低于当前级别的不该被写出去（既不进 stdout 也不进文件）。
func TestLevelFiltering(t *testing.T) {
	lg, buf, path := newTestLogger(t, LevelWarn, 0, 3)
	lg.Debugf("debug 消息")
	lg.Infof("info 消息")
	lg.Warnf("warn 消息")
	lg.Errorf("error 消息")

	out := buf.String()
	if strings.Contains(out, "debug 消息") || strings.Contains(out, "info 消息") {
		t.Errorf("warn 级别下不该出现 debug/info：%s", out)
	}
	if !strings.Contains(out, "warn 消息") || !strings.Contains(out, "error 消息") {
		t.Errorf("warn/error 应当被写出：%s", out)
	}
	if !strings.Contains(out, "[WARN]") || !strings.Contains(out, "[ERROR]") {
		t.Errorf("行里应当带级别标签：%s", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != out {
		t.Errorf("文件内容应当与 stdout 一致\n文件: %q\nstdout: %q", data, out)
	}
}

// SetLevel 要立刻生效（热重载改 log.level 走的就是它）。
func TestSetLevelTakesEffect(t *testing.T) {
	lg, buf, _ := newTestLogger(t, LevelError, 0, 3)
	lg.Infof("看不见")
	if buf.Len() != 0 {
		t.Fatalf("error 级别下 info 不该被写出：%s", buf)
	}
	lg.SetLevel(LevelDebug)
	lg.Debugf("看得见")
	if !strings.Contains(buf.String(), "看得见") {
		t.Errorf("SetLevel(Debug) 之后 debug 应当被写出：%s", buf)
	}
}

// 日志文件必须 0600、目录 0700：里面会有上游错误体片段与客户端 IP，
// 不该让同机器的其他用户读到。
func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "llmproxy.log") // 目录不存在，New 要自己建
	lg := New(LevelInfo, path, 1, 3)
	defer lg.Close()
	lg.Infof("x")

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("日志文件权限 = %o, want 600", perm)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("日志目录权限 = %o, want 700", perm)
	}
}

// 超过 maxBytes 就轮转：当前文件改名成 .1，然后开一个新的。
func TestRotationCreatesBackup(t *testing.T) {
	lg, _, path := newTestLogger(t, LevelInfo, 200, 3)
	for i := 0; i < 20; i++ {
		lg.Infof("第 %d 行日志，用来把文件撑过 maxBytes", i)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("轮转后应当有 %s.1: %v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 400 {
		t.Errorf("轮转后当前文件应当重新变小，实际 %d 字节", fi.Size())
	}
	// 轮转出来的备份也必须是 0600（它同样是日志）
	bi, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if perm := bi.Mode().Perm(); perm != 0o600 {
		t.Errorf("备份文件权限 = %o, want 600", perm)
	}
}

// keep 决定保留几份备份：超出的最旧那份要被挤掉。
func TestRotationRespectsKeep(t *testing.T) {
	const keep = 2
	lg, _, path := newTestLogger(t, LevelInfo, 120, keep)
	for i := 0; i < 200; i++ {
		lg.Infof("第 %d 行日志，用来反复触发轮转", i)
	}
	for i := 1; i <= keep; i++ {
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), "llmproxy.log."+string(rune('0'+i)))); err != nil {
			t.Errorf("应当保留 .%d: %v", i, err)
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("keep=2 时不该留下 .3")
	}
}

// maxBytes <= 0 表示不轮转（New 在 maxMb=0 时就是这个状态）。
func TestNoRotationWhenMaxBytesZero(t *testing.T) {
	lg, _, path := newTestLogger(t, LevelInfo, 0, 3)
	for i := 0; i < 50; i++ {
		lg.Infof("第 %d 行", i)
	}
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Error("maxBytes=0 时不该轮转")
	}
}

// 没给文件路径时只写 stdout，不该炸。
func TestStdoutOnly(t *testing.T) {
	lg := New(LevelInfo, "", 0, 0)
	defer lg.Close()
	buf := &bytes.Buffer{}
	lg.stdout = buf
	lg.Infof("只到 stdout")
	if !strings.Contains(buf.String(), "只到 stdout") {
		t.Errorf("应当写进 stdout：%s", buf)
	}
	if lg.file != nil {
		t.Error("没给路径时不该打开文件")
	}
}

// Close 之后再写不该 panic（关停顺序里 housekeeping 可能还在跑）。
func TestWriteAfterCloseIsSafe(t *testing.T) {
	lg, buf, _ := newTestLogger(t, LevelInfo, 0, 3)
	if err := lg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lg.Infof("关闭之后的一条") // 不该 panic
	if !strings.Contains(buf.String(), "关闭之后的一条") {
		t.Errorf("关闭后仍应当写 stdout：%s", buf)
	}
	if lg.file != nil {
		t.Error("Close 之后 file 应当被置空")
	}
	// 重复 Close 也不该炸
	if err := lg.Close(); err != nil {
		t.Errorf("重复 Close 不该报错: %v", err)
	}
}
