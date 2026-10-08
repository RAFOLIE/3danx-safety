$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path -LiteralPath $compiler)) { throw '没有找到 .NET Framework 4 编译器。' }
$source = Join-Path $PSScriptRoot 'src\SecurityCore.cs'
$target = Join-Path $PSScriptRoot 'package\3danx.Security.dll'
& $compiler /nologo /target:library /optimize+ ('/out:' + $target) $source
if ($LASTEXITCODE -ne 0) { throw '清理核心编译失败。' }
Write-Output '已生成 package/3danx.Security.dll。未生成调试符号或本机路径记录。'
