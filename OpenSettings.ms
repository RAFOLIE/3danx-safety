(
    global DanxSafety
    global DanxSafetyShowSettings
    local root = (dotNetClass "System.Environment").GetEnvironmentVariable "LOCALAPPDATA"
    root += "\\3danxSafety\\3danxSafety.ms"
    if DanxSafety == undefined do fileIn root
    DanxSafetyShowSettings()
)
