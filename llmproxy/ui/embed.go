// Package ui 把控制台的静态资源编进二进制。
//
// 目录分工：
//   - spa/user、spa/admin：两个独立 SPA 的构建产物（web/ 下 Vue3+Vite 工程产出）；
//   - user.* / admin.* / common.js / app.css：旧版原生页（迁移期保留，SPA 功能对等后删除）；
//   - openapi.yaml：接口描述。
//
// SPA 的构建产物不入库（见 .gitignore）；从源码运行时先跑 `cd web && npm run build`。
// 运行时还可以用 <RuntimeDir>/ui/{user,admin} 覆盖嵌入版本（机构定制界面）。
package ui

import "embed"

//go:embed all:spa user.html user.js admin.html admin.js common.js app.css openapi.yaml
var FS embed.FS

