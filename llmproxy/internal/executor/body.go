package executor

import (
	"encoding/json"
	"fmt"
)

// 本文件是现网 internal/server/forwarder.go 两个正文工具函数的抽取件：
// rewriteModelBody（:800-820）与 withIncludeUsage（:822-841）。
// 之所以搬而不是留在 server 包里等接线方 import：正文改写属于「发出去之前
// 的最后一步」，是执行器分内的事；而 F 包禁止 import internal/server。
// 口径保持一致是硬要求 —— 这两处直接决定上游收到什么、usage 回不回得来。
//
// 两者的实现纪律相同：用 map[string]json.RawMessage 做**外科手术式**字段改写，
// 其余字段原样保留（现网注释的原话：避免数值精度被 json 往返破坏）。
// 改写只在调用方显式要求时发生（Attempt.UpstreamModel / Attempt.WantUsage），
// 执行器不自作主张动正文（doc.go 正文访问契约）。

// rewriteModelInBody 只替换 model 字段为上游真名。
func rewriteModelInBody(body []byte, upstreamModel string) ([]byte, error) {
	fields, err := unmarshalObject(body)
	if err != nil {
		return nil, err
	}
	quoted, err := json.Marshal(upstreamModel)
	if err != nil {
		return nil, fmt.Errorf("上游模型名无法序列化: %v", err)
	}
	fields["model"] = quoted
	return json.Marshal(fields)
}

// injectIncludeUsage 强制打开 stream_options.include_usage，保留客户端的其他子字段。
//
// 不能只在键缺失时才注入（现网 :822-827 的原始理由，逐字成立）：客户端自带
// stream_options（哪怕写的是 include_usage:false，或只是认不出的方言字段）
// 就会把注入整个跳过 —— 上游于是不回报 usage，这条请求的 token 与金额全部
// 记 0、配额一分不扣，而上游照样向我们收钱。计量是网关自己的需求，
// 不该由下游客户端决定，所以这里一律覆盖 include_usage。
func injectIncludeUsage(body []byte) ([]byte, error) {
	fields, err := unmarshalObject(body)
	if err != nil {
		return nil, err
	}
	fields["stream_options"] = forcedIncludeUsage(fields["stream_options"])
	return json.Marshal(fields)
}

// unmarshalObject 是共用的入口校验：请求体必须是 JSON 对象。
// 报错文本只说形态，不回显正文（ExecutionError.Detail 的自律纪律从这里开始）。
func unmarshalObject(body []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("请求体不是 JSON 对象")
	}
	if m == nil {
		return nil, fmt.Errorf("请求体是 JSON null 而非对象")
	}
	return m, nil
}

// forcedIncludeUsage 的语义与键值形状同 forwarder.go withIncludeUsage :828-841。
func forcedIncludeUsage(raw json.RawMessage) json.RawMessage {
	only := json.RawMessage(`{"include_usage":true}`)
	var opts map[string]json.RawMessage
	// raw 缺失（nil）、是 null、不是对象、或解析不了时，整个换成我们要的形状
	if err := json.Unmarshal(raw, &opts); err != nil || opts == nil {
		return only
	}
	opts["include_usage"] = json.RawMessage(`true`)
	out, err := json.Marshal(opts)
	if err != nil {
		return only
	}
	return out
}
