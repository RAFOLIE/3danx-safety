# 3danx 安全卫士

面向 **Windows 上的 3ds Max 2014 / 2015** 的 CRP 专项防护工具。打开场景前检查可识别的 CRP 嵌入脚本，合并或导入后检查当前场景，并提供清理确认、自动清理和成功静默设置。

## 功能

- 随 Max 自动启动，无已知异常时不弹窗。
- 打开 `.max` 文件前检查已支持的 CRP 持久回调及变量。
- 合并、导入后检查当前场景；保存、渲染及视口变化时补充检查。
- 默认询问是否清理；可勾选“自动清理”，设置会保存。
- 默认“清理完成后不通知”；失败、无法检查或其他已知恶意标记仍会提示。
- 清理文件前建立完整备份；校验所有模型相关数据流，校验失败时不替换原文件。
- 不联网，不上传场景、日志或备份。

## 下载与安装

在 [Releases](https://github.com/RAFOLIE/3danx-safety/releases) 下载完整安装包并解压。先正常关闭所有 Max 窗口。

使用管理员 PowerShell，在解压目录执行：

```powershell
.\Install.ps1
```

安装程序默认寻找 `%ProgramFiles%\Autodesk\3ds Max 2014` 和 `%ProgramFiles%\Autodesk\3ds Max 2015`。安装在其他位置时，可以指定目录：

```powershell
.\Install.ps1 -MaxDirectories @('<Max 2014 安装目录>', '<Max 2015 安装目录>')
```

安装后重新打开 Max，防护会自动启动。若当前环境不允许运行 PowerShell 脚本，可按 [使用说明中的手动安装步骤](docs/USAGE.md#手动安装) 安装。

## 打开设置

在 Max 中选择 **MAXScript → 运行脚本**，运行 `OpenSettings.ms`。也可从“自定义用户界面”的 **3danx 安全卫士** 分类添加设置按钮。

发现 CRP 的弹窗和设置面板都提供：

| 选项 | 默认值 | 行为 |
| --- | --- | --- |
| 自动清理已确认的 CRP | 关闭 | 开启后不再询问清理，仍先备份 |
| 清理完成后不通知 | 开启 | 成功时静默，失败及未知情况仍提示 |

## 数据保存位置

本地备份、设置与日志位于 `%LOCALAPPDATA%\3danxSafety`。备份使用 `.infected-backup` 后缀，可能含原始病毒代码，请勿改名后直接用 Max 打开。

详细操作见 [使用说明](docs/USAGE.md)，检测与验证范围见 [验证说明](docs/VALIDATION.md)，本地数据处理见 [隐私说明](docs/PRIVACY.md)。

## 检测边界

本工具只自动清理已经验证的 CRP 结构。ADSL 等少量其他已知标记只提示；加密脚本、未知变种和其他文件格式不视为已全面检查。

Max 2014/2015 的合并与导入事件不提供可靠的源文件路径。因此这些操作后清理的是 **当前场景**，请正常保存；不会覆盖未知源文件。合并外来 `.max` 前，可以在设置面板使用“检查一个文件”提前检查源文件。

载入后检查不能保证所有嵌入脚本都尚未执行。如果在打开前选择暂不处理，源文件仍含病毒。检测结果不能作为电脑不存在其他病毒的证明。

## 取消自启动

关闭 Max 后，在管理员 PowerShell 中执行：

```powershell
.\Uninstall.ps1
```

安装时指定了自定义 Max 目录的，应向卸载脚本传入同样的 `-MaxDirectories`。卸载仅移除本工具的启动入口，保留模型、备份、日志和设置。

## 文件结构与构建

```text
package/3danxSafety.ms      Max 防护逻辑与界面
package/3danx.Security.dll  .NET 4 文件清理核心
package/000_3danx_safety.ms 自动启动入口
src/SecurityCore.cs        清理核心源码
OpenSettings.ms            设置入口
Install.ps1                安装脚本
Uninstall.ps1              取消自启动
Build.ps1                  使用 Windows .NET Framework 编译器重新构建
```

重新构建核心：

```powershell
.\Build.ps1
```

使用 Windows COM 结构化存储接口定点修改场景脚本数据。发布内容仅包含工具文件和通用说明，不包含用户模型、感染样本、运行日志、原始检查记录或本机路径。
