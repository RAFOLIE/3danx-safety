param([string[]]$MaxDirectories)
$ErrorActionPreference = 'Stop'
if (Get-Process -Name 3dsmax -ErrorAction SilentlyContinue) { throw '请先正常关闭 3ds Max。' }
if (-not $MaxDirectories) {
    $MaxDirectories = @(
        (Join-Path $env:ProgramFiles 'Autodesk\3ds Max 2014'),
        (Join-Path $env:ProgramFiles 'Autodesk\3ds Max 2015')
    )
}
foreach ($maxDir in $MaxDirectories) {
    $startup = [IO.Path]::GetFullPath((Join-Path $maxDir 'scripts\Startup'))
    $target = [IO.Path]::GetFullPath((Join-Path $startup '000_3danx_safety.ms'))
    if (-not $target.StartsWith($startup + '\',[StringComparison]::OrdinalIgnoreCase)) { throw '路径校验失败。' }
    if (Test-Path -LiteralPath $target) {
        if (-not [IO.File]::ReadAllText($target).Contains('3danx 安全卫士自动启动入口')) {
            throw ('文件不属于本工具，未删除：' + $target)
        }
        (Get-Item -LiteralPath $target).IsReadOnly = $false
        Remove-Item -LiteralPath $target
    }
}
Write-Output '已取消自启动。模型、备份、日志和设置均已保留。'
