// e2eidp 是端到端验证用的**假 IdP**：它一次运行里生成一把一次性 RSA 密钥，
// 把对应的 JWKS 落到本机文件，再为上给的每个画像签一枚真 token 打到 stdout。
//
// 为什么要单独一个可执行文件，而不是在 e2e 脚本里手搓 JWT：
// 网关验的是**真实签名**（iss/aud/kid/RS256 一个都不放松），手搓的 token 要么绕过
// 验签（那这一节就没验到东西），要么得在 shell/python 里重建 RSA 签名与 JWKS 编码
// （可靠性与可读性都差）。这里复用 internal/identity 里那套与生产逐字相同的签发路径，
// 于是「e2e 里签得出来、网关验得过」本身就是身份的键来源与算法面在真进程上的证据。
//
// 一次运行一把密钥，不做密钥持久化：JWKS 与 token 出自同一个进程，天然一致；
// 需要多枚 token（不同画像）时在**同一次**调用里用 -profiles 列出，不能分两次签。
package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
)

// 带 e2e 前缀的固定签发参数：写进被演练实例的配置，脚本里两处引用同一个常量。
const (
	e2eIssuer    = "https://idp.e2e.local"
	e2eAudience  = "llmproxy-e2e"
	defaultProbe = "teacher-2001"
)

func main() {
	jwksPath := flag.String("jwks", "", "写出的 JWKS 文件路径（必填）")
	issuer := flag.String("issuer", e2eIssuer, "iss，必须与被演练实例的 identity.issuer 一致")
	audience := flag.String("audience", e2eAudience, "aud，必须与被演练实例的 identity.audience 一致")
	profiles := flag.String("profiles", defaultProbe, "画像名，逗号分隔；每枚 token 打一行")
	flag.Parse()

	if strings.TrimSpace(*jwksPath) == "" {
		fmt.Fprintln(os.Stderr, "必须给 -jwks：JWKS 要落到本机文件，网关只从文件读公钥")
		os.Exit(2)
	}

	auth, err := identity.NewFakeAuthority()
	if err != nil {
		fail(err)
	}
	auth.WithIdentity(*issuer, *audience)

	pub, err := rsaPublic(auth)
	if err != nil {
		fail(err)
	}
	if err := writeJWKS(*jwksPath, auth.RSAKeyID(), pub); err != nil {
		fail(err)
	}

	at := time.Now()
	names := splitNonEmpty(*profiles)
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "-profiles 至少要有一个画像名")
		os.Exit(2)
	}
	for _, name := range names {
		prof, ok := sampleProfile(name)
		if !ok {
			fmt.Fprintf(os.Stderr, "画像 %q 不在 identity.UniversitySampleProfiles 里\n", name)
			os.Exit(2)
		}
		token, err := auth.SignUniversityToken(prof, at)
		if err != nil {
			fail(err)
		}
		fmt.Println(token)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "e2eidp:", err)
	os.Exit(1)
}

func splitNonEmpty(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func sampleProfile(name string) (identity.UniversityProfile, bool) {
	for _, p := range identity.UniversitySampleProfiles() {
		if p.FixtureName() == name {
			return p, true
		}
	}
	return identity.UniversityProfile{}, false
}

func rsaPublic(auth *identity.FakeAuthority) (*rsa.PublicKey, error) {
	keys, err := auth.Keys(context.Background())
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.Algorithm == identity.AlgRS256 {
			pub, ok := k.Public.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("RS256 公钥类型不符: %T", k.Public)
			}
			return pub, nil
		}
	}
	return nil, fmt.Errorf("FakeAuthority 没有 RS256 公钥")
}

// writeJWKS 手拼一份标准 JWKS：internal/identity 只解析、不序列化，
// 所以这里按 RFC 7517 的 RSA 键字段（n/e 用无填充 base64url）自己拼。
func writeJWKS(path, kid string, pub *rsa.PublicKey) error {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, kid, n, e)
	return os.WriteFile(path, []byte(doc), 0o600)
}
