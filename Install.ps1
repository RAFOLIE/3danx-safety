param([string[]]$MaxDirectories)
$ErrorActionPreference = 'Stop'
function Get-DanxFileDigest([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
    finally { $sha.Dispose(); $stream.Dispose() }
}
if (-not $MaxDirectories) {
    $MaxDirectories = @(
        (Join-Path $env:ProgramFiles 'Autodesk\3ds Max 2014'),
        (Join-Path $env:ProgramFiles 'Autodesk\3ds Max 2015')
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $_ '3dsmax.exe') }
}
if (-not $MaxDirectories) { throw '没有找到 Max 2014 或 2015。可通过 -MaxDirectories 指定安装目录。' }
if (Get-Process -Name 3dsmax -ErrorAction SilentlyContinue) { throw '请先正常关闭 3ds Max，避免覆盖正在使用的防护文件。' }
$installRoot = Join-Path $env:LOCALAPPDATA '3danxSafety'
$packageRoot = Join-Path $PSScriptRoot 'package'
$startupTargets = @()
foreach ($maxDir in $MaxDirectories) {
    if (-not (Test-Path -LiteralPath (Join-Path $maxDir '3dsmax.exe'))) { throw ('无效的 Max 安装目录：' + $maxDir) }
    $startup = [IO.Path]::GetFullPath((Join-Path $maxDir 'scripts\Startup'))
    if (-not (Test-Path -LiteralPath $startup -PathType Container)) { throw ('缺少启动目录：' + $startup) }
    $target = Join-Path $startup '000_3danx_safety.ms'
    if ((Test-Path -LiteralPath $target) -and (-not [IO.File]::ReadAllText($target).Contains('3danx 安全卫士自动启动入口'))) {
        throw ('同名文件不属于本工具，未覆盖：' + $target)
    }
    $startupTargets += $target
}
foreach ($name in @('3danxSafety.ms','3danx.Security.dll','000_3danx_safety.ms')) {
    if (-not (Test-Path -LiteralPath (Join-Path $packageRoot $name))) { throw ('安装包缺少文件：' + $name) }
}
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $installRoot 'Backups') | Out-Null
$changed = @()
foreach ($name in @('3danxSafety.ms','3danx.Security.dll')) {
    $source = Join-Path $packageRoot $name
    $target = Join-Path $installRoot $name
    if (Test-Path -LiteralPath $target) {
        $existing = Get-Item -LiteralPath $target
        if ($existing.IsReadOnly) { $existing.IsReadOnly = $false }
        Copy-Item -LiteralPath $target -Destination ($target + '.previous') -Force
    }
    Copy-Item -LiteralPath $source -Destination $target -Force
    if ((Get-DanxFileDigest $source) -ne (Get-DanxFileDigest $target)) { throw ('安装校验失败：' + $name) }
    $changed += $target
}
foreach ($target in $startupTargets) {
    if (Test-Path -LiteralPath $target) { (Get-Item -LiteralPath $target).IsReadOnly = $false }
    $source = Join-Path $packageRoot '000_3danx_safety.ms'
    Copy-Item -LiteralPath $source -Destination $target -Force
    if ((Get-DanxFileDigest $source) -ne (Get-DanxFileDigest $target)) { throw '启动入口校验失败。' }
    (Get-Item -LiteralPath $target).IsReadOnly = $true
    $changed += $target
}
$changed | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installRoot 'installation.json') -Encoding UTF8
Write-Output '安装完成。下次打开 Max 会自动启动。默认询问是否清理，清理成功后不弹通知。'
