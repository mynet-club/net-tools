package replay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// SchemaVersion 是记录文件的结构版本。
//
// 它和 config_schema_version（配置文件结构版本）不是一回事，也和 policy bundle 的
// id@version（策略内容版本，进决策与回放）无关：§3.0 要求这三种版本各管各的层，
// 混用会让「改了记录字段」被误读成「改了策略」。
const SchemaVersion = 1

// forbiddenFieldWords 是记录里绝不允许出现的字段名片段。
//
// 覆盖 §2.8 / §2.9 禁止入库的东西：正文及其摘要、prompt/messages、密钥与凭证类。
// 这里连 `raw` 都禁掉，是因为「raw_body」这类命名会诱导实现方往记录里塞正文或片段；
// A 包的 leak_test.go 用同一套词表，两个包口径必须一致。
var forbiddenFieldWords = []string{
	"body", "payload", "content", "prompt", "messages", "message",
	"apikey", "api_key", "secret", "token", "password", "credential",
	"baseurl", "base_url", "cookie", "authorization", "raw",
	"email", "phone", "idcard", "id_card",
}

// ForbiddenFieldWords 暴露词表，供主线在别处（审计表列名、UI 字段）复用同一口径。
func ForbiddenFieldWords() []string { return append([]string(nil), forbiddenFieldWords...) }

// forbiddenWordHit 返回字段名命中的第一个被禁词；大小写不敏感。
func forbiddenWordHit(name string) string {
	lower := strings.ToLower(name)
	for _, word := range forbiddenFieldWords {
		if strings.Contains(lower, word) {
			return word
		}
	}
	return ""
}

// File 是一份可回放的记录集合。
//
// 刻意没有 generated_at：文件级时间戳会让同一批记录两次导出产生不同字节，
// 而 §2.8 要的是「同一输入同一输出」。每条记录自带 recorded_at，足够定位时刻。
type File struct {
	SchemaVersion int              `json:"schema_version"`
	Decisions     []DecisionRecord `json:"decisions,omitempty"`
	Routings      []RoutingRecord  `json:"routing,omitempty"`
}

// NewFile 构造记录文件：只收已自校验过的记录（调用方负责先 Validate），
// 文件级校验交给 Validate，避免构造期把顺序问题悄悄修掉。
func NewFile(decisions []DecisionRecord, routings []RoutingRecord) File {
	return File{
		SchemaVersion: SchemaVersion,
		Decisions:     append([]DecisionRecord(nil), decisions...),
		Routings:      append([]RoutingRecord(nil), routings...),
	}
}

// Validate 校验文件结构版本与其中每条记录。now 是回放时钟，供计划 TTL 判定。
func (f File) Validate(now time.Time) error {
	if f.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: 文件声明 %d，本实现支持 %d", ErrSchemaVersion, f.SchemaVersion, SchemaVersion)
	}
	for _, rec := range f.Decisions {
		if err := rec.Validate(); err != nil {
			return err
		}
	}
	for _, rec := range f.Routings {
		if err := rec.Validate(now); err != nil {
			return err
		}
	}
	return nil
}

// Encode 输出缩进 JSON（键序由 encoding/json 按字段名稳定输出，因此产物可 diff）。
func Encode(f File) ([]byte, error) {
	f.SchemaVersion = SchemaVersion
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("replay: 记录序列化失败: %w", err)
	}
	if hit := scanForbiddenKeys(data); hit != "" {
		return nil, fmt.Errorf("%w: %s", ErrForbiddenField, hit)
	}
	return append(data, '\n'), nil
}

// MustEncode 只用于测试与导出手册样例。
func MustEncode(f File) string {
	data, err := Encode(f)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// Decode 解析记录文件，fail_closed：
//   - 未知字段直接报错（多出来的字段意味着有人在往里塞没被契约承认的东西，
//     最典型的就是正文或摘要）；
//   - 任何 JSON 键命中被禁词直接报错；
//   - schema 版本必须是本实现支持的版本，未来版本要靠显式的迁移代码承认。
func Decode(data []byte) (File, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return File{}, fmt.Errorf("%w: 记录文件为空", ErrRecordInvalid)
	}
	if hit := scanForbiddenKeys(data); hit != "" {
		return File{}, fmt.Errorf("%w: %s", ErrForbiddenField, hit)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return File{}, fmt.Errorf("replay: 记录文件解析失败: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return File{}, fmt.Errorf("replay: 记录文件末尾有多余内容: %v", err)
	}
	if f.SchemaVersion != SchemaVersion {
		return File{}, fmt.Errorf("%w: 文件声明 %d，本实现支持 %d", ErrSchemaVersion, f.SchemaVersion, SchemaVersion)
	}
	return f, nil
}

// ReadFrom 从流读记录（不碰文件系统：路径语义归调用方，便于审计侧自己管大小与超时）。
func ReadFrom(r io.Reader) (File, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return File{}, fmt.Errorf("replay: 读取记录失败: %w", err)
	}
	return Decode(data)
}

// WriteTo 把记录写进流。
func WriteTo(w io.Writer, f File) error {
	data, err := Encode(f)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// scanForbiddenKeys 递归扫描 JSON 对象的所有键，返回第一个命中被禁词的键路径。
//
// 反射测试只能管住本包结构体；文件里出现的键可能来自更早/更晚的版本或手写改动，
// 所以加载/导出两侧都按同一词表再扫一遍。数组与字符串值不扫（值可能是
// 组织自定的资源名，例如 model:raw-audio —— 禁的是字段名，不是业务命名）。
func scanForbiddenKeys(data []byte) string {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return ""
	}
	return walkKeys(root, "")
}

func walkKeys(node any, path string) string {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			hit := forbiddenWordHit(k)
			if hit != "" {
				return path + k + "（命中被禁词 " + hit + "）"
			}
			if sub := walkKeys(v[k], path+k+"."); sub != "" {
				return sub
			}
		}
	case []any:
		for _, item := range v {
			if sub := walkKeys(item, path); sub != "" {
				return sub
			}
		}
	}
	return ""
}
