# 可选的 OpenTimestamps 时间锚定

证据包中的 `public/timestamp-target.json` 只承诺设备已签名的最终证据链头，
不含研究正文、文件路径、截图、密钥或敏感层内容。桌面端生成它时不会联网。

如研究者希望增加一个独立的“最迟存在时间”见证，可在导出后自行安装并运行
OpenTimestamps 客户端：

```sh
unzip research-process.evidence.zip public/timestamp-target.json
ots stamp public/timestamp-target.json
ots upgrade public/timestamp-target.json.ots
ots verify public/timestamp-target.json.ots
```

`stamp` 会向公共日历服务器发送文件摘要并产生初始 receipt；确认可能需要数小时，
之后用 `upgrade` 补全 Bitcoin 证明。`.ots` 文件应与原 ZIP 一同提交，但不得替换或
修改 ZIP 内文件。上述命令是明确的可选联网操作，本项目不会自动执行。

验证结果只能支持“该摘要在某外部时间界限前已经存在”。Bitcoin 区块时间并非精确
的研究活动时间，它不能证明作者身份、原创性、记录完整性或研究结论正确。
