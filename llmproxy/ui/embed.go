// Package ui 把控制台的静态资源编进二进制：用户台（user.*）与管理台（admin.*）两套页面，
// 共用 common.js 与 app.css。
//
// 放在这里而不是运行时目录：llmproxy 是零依赖的单二进制，
// 网页界面跟着二进制走，部署时不用额外分发文件。
// 源文件就在本目录下，改完重新编译即可。
package ui

import "embed"

//go:embed user.html user.js admin.html admin.js common.js app.css
var FS embed.FS
