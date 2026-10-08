/* 3danx 安全卫士自动启动入口 */
(
    try
    (
        local path = (dotNetClass "System.Environment").GetEnvironmentVariable "LOCALAPPDATA"
        path += "\\3danxSafety\\3danxSafety.ms"
        if doesFileExist path do fileIn path
    )
    catch
    (
        messageBox ("3danx 安全卫士未能启动：\n" + (getCurrentException())) title:"3danx 安全卫士" beep:false
    )
)
