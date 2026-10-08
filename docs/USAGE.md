# 使用说明

## 自动防护

正常打开 Max 后，启动入口加载防护脚本。打开 `.max` 前检查已支持的 CRP；发现后可以确认清理或暂不处理。清理成功才替换源文件，并保留清理前备份。

合并或导入后，检查当前场景中的已知 CRP 回调和持久变量，先移除这些已知记录，再询问后续处理。该步骤不会删除模型、材质、灯光或贴图；请按正常方式保存当前场景。它无法追回病毒在检查前已经造成的场景改动。

保存、渲染和视口变化时会补充检查当前场景中的已知 CRP。防护回调只注册在当前 Max 会话中，不作为持久回调写入分享给他人的场景。

## 设置与手动检查

在 Max 中运行 `OpenSettings.ms`，打开设置面板：

- **自动清理已确认的 CRP**：默认关闭。开启后无需再次确认，仍会备份原件。
- **清理完成后不通知**：默认开启。清理成功时静默；失败、不能检查或其他恶意标记仍提示。
- **检查当前场景**：检查当前场景及其已保存的源文件。
- **检查一个文件**：检查指定 `.max` 或 `.ms`，发现已支持的 CRP 时询问或自动清理。
- **查看备份 / 查看日志**：打开本机保存位置。

无已知异常时不自动弹窗。设置修改会即时写入本地 `settings.ini`，下次启动继续生效。

## 手动安装

1. 正常关闭 Max。
2. 建立 `%LOCALAPPDATA%\3danxSafety` 文件夹。
3. 将 `package/3danxSafety.ms` 和 `package/3danx.Security.dll` 复制到该文件夹。
4. 将 `package/000_3danx_safety.ms` 复制到需要保护的 Max 安装目录下的 `scripts\Startup`。
5. 可将该启动入口设为只读，以减少本次 CRP 对启动文件直接追加代码的机会。
6. 重新打开 Max，并通过 `OpenSettings.ms` 查看设置。

## 备份与失败处理

备份位于 `%LOCALAPPDATA%\3danxSafety\Backups`。每次文件清理建立独立目录，保存原件及原始路径说明。

文件只读、被占用、结构不支持、备份失败、模型完整性不一致，或清理期间源文件改变时，工具不会替换原文件。不要把检查错误当作已清理完成。

`.infected-backup` 备份可能包含原始病毒脚本。不要改名为 `.max` 后直接加载，也不要将含私人路径的日志或备份上传到公共仓库。

## 官方接口参考

- [Autodesk：一般事件回调](https://help.autodesk.com/cloudhelp/2020/ENU/3DSMax-MAXScript/files/GUID-C1F6495F-5831-4FC8-A00C-667C5F2EAE36.htm)
- [Autodesk：文件事件及通知参数](https://help.autodesk.com/cloudhelp/2024/ENU/MAXScript-Help/files/MAXScript-Tools-and-Interaction/Change-Handlers-and-Callbacks/General-Event-Callback-Mechanism/GUID-2D8606DF-EF5D-4F5B-A00C-B10D29A14947.html)
