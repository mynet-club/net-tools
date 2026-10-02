package executor

import (
	"encoding/json"
	"fmt"
	"strings"
)

// 本文件把「本地后端」的差异收敛进 HTTPExecutor 的两个窄面：
// 请求形态适配器（发送前）与扫描方言（响应旁路）。**传输层一行都不复制**：
// 本地与远程的差别从来不在「怎么发 HTTP」，而在「讲哪种协议形态」。
//
// 两者的真实差异表（写下来就是为了不让你去 git blame Ollama 源码）：
//
//	              远程 OpenAI 兼容 / vLLM          Ollama 原生
//	入口          /v1/chat/completions             /api/chat
//	请求体        OpenAI chat 全字段                model + messages + stream + options(扁平推理参数)
//	流式响应      SSE（data: 行 + [DONE]）          NDJSON（每行一个对象，done:true 收尾）
//	非流式响应    单个 JSON 对象                    单个 JSON 对象（等同只有一行的 NDJSON）
//	用量          usage 对象（SSE 末帧）            收尾行平铺 prompt_eval_count / eval_count
//	认证          Bearer 密钥                       默认无
//
// vLLM 的选择：vLLM 服务的是 OpenAI 兼容 /v1/*，协议上与远程没有形态差，
// 所以它**不是**一个新执行器，只是 NewHTTPExecutor 的一组默认参数。
// 若在这里造一个 "vllm" 专用类型，就会出现第二个「OpenAI 兼容」实现。
// （Ollama 其实也有 /v1/chat/completions 兼容端点，理论上可全程走 OpenAI 形态；
// 原生 /api/chat 的价值是 options 全量参数与不依赖兼容层的行为漂移，
// 这正是 F 要求「本地形态差异要写清并收敛」指的那个差异。）

// NewVLLM 构造 vLLM 执行器：OpenAI 兼容协议 + 本地默认无认证。
//
// 与远程 OpenAI 上游共用 HTTPExecutor 与同一扫描方言；唯一的刻意默认是
// APIKey 留空由 Attempt 决定（vLLM 默认不校验 Authorization，但有些部署
// 前面挂了鉴权反代 —— 不替调用方假定「本地=无鉴权」）。
func NewVLLM(base Options) (*HTTPExecutor, error) {
	if base.Name == "" {
		base.Name = "vllm"
	}
	if base.Protocol == "" {
		base.Protocol = ProtocolOpenAIChat
	}
	return NewHTTPExecutor(base)
}

// ollamaNativePath 是 Ollama 原生 chat 入口。
const ollamaNativePath = "/api/chat"

// NewOllama 构造 Ollama 原生协议执行器。
//
// 它与 HTTPExecutor 的关系是「配置 + 一个 shape 适配器」，不是子类也不是新类型：
//   - 请求侧：适配器把已定稿的 OpenAI 形态正文翻译成 /api/chat 的 native 形态；
//   - 响应侧：Protocol=ProtocolOllamaNative 让旁路扫描走 NDJSON 方言
//     （scan.go noteOllamaChunk：done:true 收尾 + eval 计数折算成 Usage）。
//
// 透传纪律不变：**响应字节一个不改**。native 响应形状与 OpenAI 不同，
// 把它转回 OpenAI 形状喂给下游客户端是接线层（server/processor）的职责 ——
// 执行器只回报「上游实际吐了什么」+「从中原样扫出的用量」。
// 在传输层偷偷重写响应字节，会让审计里记录的透传与实发内容对不上，
// 那正是 2.x「forwarder 顺手改包」被诟病的模式。
func NewOllama(base Options) (*HTTPExecutor, error) {
	if base.Name == "" {
		base.Name = "ollama"
	}
	base.Protocol = ProtocolOllamaNative
	if base.AdaptRequest == nil {
		base.AdaptRequest = adaptOllamaNative
	}
	return NewHTTPExecutor(base)
}

// ollamaOptionKeys 是 OpenAI 顶层推理参数 → Ollama native options 的映射表。
//
// 只映射**名字确定**的键，其余字段原样留在顶层（Ollama 会忽略认不出的字段，
// 不会因一个生僻参数把整个请求打回）。刻意不做的事：把 max_tokens 映射成
// num_ctx —— 那是上下文窗口不是生成长度，语义对应的是 num_predict，
// 这种名字相近的坑宁可留原键让运维在 Ollama 日志里看到，也不静默改语义。
var ollamaOptionKeys = map[string]string{
	"temperature":       "temperature",
	"top_p":             "top_p",
	"presence_penalty":  "presence_penalty",
	"frequency_penalty": "frequency_penalty",
	"stop":              "stop",
	"seed":              "seed",
	"max_tokens":        "num_predict",
}

// adaptOllamaNative 把 OpenAI chat 请求体翻译成 Ollama 原生 /api/chat 形态。
//
// 输入是 prepareRequest 已定稿的 OpenAI 形态正文（model 已改写、
// stream_options 已处理完毕）。翻译规则：
//   - model / messages / stream 原键搬运（Ollama 的 messages 与 OpenAI 的
//     role/content 形状兼容；多模态 images 字段的方言差异超出本包职责，
//     原样搬运、由 Ollama 自己裁决）；
//   - ollamaOptionKeys 表内的推理参数收进 options 对象；
//   - stream_options 是 OpenAI 方言，原生协议不认，剥离；
//   - 其余键不动。
func adaptOllamaNative(a *Attempt, openaiBody []byte) (string, []byte, error) {
	fields, err := unmarshalObject(openaiBody)
	if err != nil {
		return "", nil, err
	}
	if _, ok := fields["messages"]; !ok {
		// 没有 messages 就不是 chat 请求，native /api/chat 无从翻译。
		// 报错而不是硬发：让接线层知道该走 completions 形态的执行器。
		return "", nil, fmt.Errorf("Ollama 原生适配器只接受 chat 形态请求体（缺 messages）")
	}
	native := make(map[string]json.RawMessage, len(fields))
	options := make(map[string]json.RawMessage)
	for k, v := range fields {
		switch k {
		case "stream_options":
			// OpenAI 方言专用，Ollama 原生协议里没有这个概念（用量总在收尾行）。
		case "max_completion_tokens":
			// 新 OpenAI 方言键，语义同 num_predict。
			options["num_predict"] = v
		default:
			if optName, isOption := ollamaOptionKeys[k]; isOption {
				options[optName] = v
				continue
			}
			native[k] = v
		}
	}
	if len(options) > 0 {
		// 表是 map、但序列化交给 json.Marshal（map 按键排序）——
		// 同一输入永远译出同一份请求体（§2.8 对「转换环节引入抖动」的通用防线）。
		encoded, err := json.Marshal(options)
		if err != nil {
			return "", nil, fmt.Errorf("options 序列化失败")
		}
		native["options"] = encoded
	}
	body, err := json.Marshal(native)
	if err != nil {
		return "", nil, fmt.Errorf("原生请求体序列化失败")
	}
	return ollamaNativePath, body, nil
}

// ollamaUsageLine 是 Ollama 收尾行里平铺的用量字段形状（scan.go 之外也供
// fake 的观测自检复用 —— 见 fake.go 对 Protocol 的处理）。
type ollamaUsageLine struct {
	Done            bool  `json:"done"`
	PromptEvalCount int64 `json:"prompt_eval_count"`
	EvalCount       int64 `json:"eval_count"`
}

// usageFromOllamaLine 把收尾行折算成统一的 Usage。
// Ollama 不报缓存拆分（本地部署的 KV-cache 不向上暴露命中数），
// HasCache 恒 false 是事实回报而不是「不支持」的猜测。
func usageFromOllamaLine(line ollamaUsageLine) Usage {
	p := line.PromptEvalCount
	c := line.EvalCount
	t := p + c
	return Usage{PromptTokens: &p, CompletionTokens: &c, TotalTokens: &t}
}

// isLocalhostBase 判断 base URL 是否回环地址（供接线层决定「本地=不出网」的
// 审计口径；本包用它只做日志性判断，不做权限 —— 见 doc.go 边界第 2 条）。
func isLocalhostBase(baseURL string) bool {
	i := strings.Index(baseURL, "://")
	if i < 0 {
		return false
	}
	rest := baseURL[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	host := rest
	if k := strings.LastIndexByte(rest, ':'); k > strings.LastIndexByte(rest, ']') {
		host = rest[:k]
	}
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return false
}
