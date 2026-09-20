// Package ui 把用户控制台的静态资源编进二进制。
//
// 放在这里而不是运行时目录：llmproxy 是零依赖的单二进制，
// 网页界面跟着二进制走，部署时不用额外分发文件。
// 源文件就在本目录下，改完重新编译即可。
package ui

import "embed"

//go:embed index.html app.css app.js
var FS embed.FS
