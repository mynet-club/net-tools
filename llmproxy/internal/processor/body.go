package processor

import (
	"bytes"
	"io"
)

// Body 是正文的受控句柄（§2.9）。
//
// 为什么要有这个类型而不是直接把 []byte 传给处理器：正文访问是三档的，
// 而 Go 的类型系统不会阻止一个处理器函数去读它拿到的任何切片。把来源收进
// 未导出的字段、只通过 Input 上带档位检查的方法暴露，档位才成为**强制**而不是约定。
//
// 两种形态：
//   - buffered：调用方已经有完整字节（现网 forwarder 对请求体就是 io.ReadAll 的形态）；
//   - streaming：只有读者。未授权时 Pipeline 一次都不会调用它，
//     所以「metadata-only 下不缓存整个请求」是可以被测试证明的事实（规则 7）。
type Body struct {
	reader    io.Reader
	data      []byte
	owned     bool // data 是否由本句柄（或处理器）分配 —— 只有自己分配的才能在释放时清零
	declared  int64
	buffered  bool
	discarded bool
	readBytes int64
}

// NewBufferedBody 用调用方已有的字节构造句柄。
//
// owned=false：这份内存是调用方的（例如 forwarder 读进来的原始请求体），
// 我们**没有权利**在它作废时清零 —— 那会静默毁掉调用方还在用的数据。
// §2.9 规则 2 要求的「原始正文处理完立即释放」在这里落实为丢弃本包引用。
func NewBufferedBody(data []byte) *Body {
	return &Body{data: data, buffered: true, declared: int64(len(data)), owned: false}
}

// NewOwnedBody 是本包内部使用的形态：字节由处理器产出（脱敏后的新正文等），
// 链条作废它时可以把内容清零。导出 NewBufferedBody 而不导出这个，
// 是为了让外部调用方永远不会把「自己的 buffer」误标成我们可以擦除。
func NewOwnedBody(data []byte) *Body {
	return &Body{data: data, buffered: true, declared: int64(len(data)), owned: true}
}

// NewBodyReader 用流构造句柄。declared 是调用方声明的大小（Content-Length 之类），
// 它在 metadata-only 档也可见 —— 大小属于元数据，不是内容。
func NewBodyReader(r io.Reader, declared int64) *Body {
	return &Body{reader: r, declared: declared}
}

// DeclaredBytes 返回声明大小，不需要读取正文，因此三档都可用。
func (b *Body) DeclaredBytes() int64 {
	if b == nil {
		return 0
	}
	return b.declared
}

// buffer 把正文取成字节，带硬上限。limit<=0 时按绝对上限夹住 —— 绝不出现「不限」。
func (b *Body) buffer(limit int64) ([]byte, error) {
	if b == nil {
		return nil, ErrNoBody
	}
	if b.discarded {
		// 原文已经按规则 2 释放。此时还想读，说明链条上有处理器越权回看原文 ——
		// 宁可报错，也不要悄悄给一份缓存副本。
		return nil, Errorf(ErrBodyAccessDenied, "原始正文已释放，禁止再次读取")
	}
	if limit <= 0 || limit > AbsoluteMaxInputBytes {
		limit = AbsoluteMaxInputBytes
	}
	if b.buffered {
		if int64(len(b.data)) > limit {
			return nil, Errorf(ErrInputTooLarge, "正文 %d 字节，上限 %d", len(b.data), limit)
		}
		b.readBytes = int64(len(b.data))
		return b.data, nil
	}
	if b.reader == nil {
		return nil, ErrNoBody
	}
	// 多读 1 字节来区分「正好等于上限」和「可能还有更多」：后者必须拒绝，
	// 否则一个刚好卡在上限的恶意请求可以让下一个处理器拿到被截断的正文。
	all, err := io.ReadAll(io.LimitReader(b.reader, limit+1))
	if err != nil {
		return nil, Errorf(ErrProcessFailed, "读取正文失败: %v", err)
	}
	if int64(len(all)) > limit {
		return nil, Errorf(ErrInputTooLarge, "正文超过上限 %d 字节", limit)
	}
	b.data = all
	b.owned = true // 这份拷贝是本句柄分配的，作废时可以清零
	b.buffered = true
	b.readBytes = int64(len(all))
	return b.data, nil
}

// stream 返回底层读者（不缓冲），供流式处理器使用。
// 已经缓冲过则返回字节读者，保证同一次调用看到的是同一份内容。
func (b *Body) stream() (io.Reader, error) {
	if b == nil {
		return nil, ErrNoBody
	}
	if b.discarded {
		return nil, Errorf(ErrBodyAccessDenied, "原始正文已释放，禁止再次读取")
	}
	if b.buffered {
		return bytes.NewReader(b.data), nil
	}
	if b.reader == nil {
		return nil, ErrNoBody
	}
	return b.reader, nil
}

// readBytesOf 返回本句柄累计真的交出去过多少字节，供审计的 input_bytes 用。
// 用 DeclaredBytes 报数会把「声明 1MB 但只看首字节」也算成读了 1MB，
// 审计里就分不清 metadata-only 的快速路径和全量缓冲。
func (b *Body) readBytesOf() int64 {
	if b == nil {
		return 0
	}
	return b.readBytes
}

// bufferedData 返回已缓冲的字节（没缓冲过就返回 nil）。
// 只给 Pipeline 算内容指纹用 —— 指纹是规则 6 允许的内容标识，字节本身不外传。
func (b *Body) bufferedData() []byte {
	if b == nil || !b.buffered {
		return nil
	}
	return b.data
}

// discard 丢弃本包对正文的引用（§2.9 规则 2）。
// 只清零自己分配的拷贝；调用方传进来的 buffer 只丢引用不清零，理由见 NewBufferedBody。
func (b *Body) discard() {
	if b == nil || b.discarded {
		return
	}
	if b.owned {
		for i := range b.data {
			b.data[i] = 0
		}
	}
	b.data = nil
	b.reader = nil
	b.discarded = true
}
