/* 3danx 安全卫士 1.0.0 — CRP 专项防护，Max 2014 / 2015。
   本脚本只按已确认的 CRP 特征清理，不执行被检查文件中的脚本。
   开源核心及使用说明随安装包提供。 */
global DanxSafety
global DanxSafetyController
global DanxSafetySettings
global DanxSafetyPrompt
global DanxSafetyDecision = false
global DanxSafetyPromptText = ""

struct DanxSafetyController
(
    root, iniPath, backupRoot, core,
    autoClean = false, silentSuccess = true, busy = false,
    declinedPath = "", warned = #(), lastStatus = "防护已就绪",
    crpIDs = #(#ID_CRP_viewportChangeP, #ID_CRP_filePostOpenP, #ID_CRP_preRenderP,
        #ID_CRP_filePostOpen, #ID_CRP_filePostMerge, #ID_CRP_postImport),
    crpGlobals = #(#CRP_AScript, #CRP_BScript, #CRP_Authorization),

    fn writeLog text = (try(core.Log root text)catch()),
    fn saveSettings =
    (
        setINISetting iniPath "Protection" "AutoClean" (autoClean as string)
        setINISetting iniPath "Protection" "SilentSuccess" (silentSuccess as string)
    ),
    fn readSettings =
    (
        autoClean = ((getINISetting iniPath "Protection" "AutoClean") == "true")
        local value = getINISetting iniPath "Protection" "SilentSuccess"
        silentSuccess = (value != "false")
    ),
    fn notifySuccess text =
    (
        lastStatus = text
        if not silentSuccess do messageBox text title:"3danx 安全卫士" beep:false
    ),
    fn notifyProblem text =
    (
        lastStatus = text
        writeLog ("需要处理：" + text)
        messageBox text title:"3danx 安全卫士 — 需要处理" beep:false
    ),
    fn askToClean text =
    (
        if autoClean then true
        else
        (
            DanxSafetyPromptText = text
            DanxSafetyDecision = false
            try(destroyDialog DanxSafetyPrompt)catch()
            createDialog DanxSafetyPrompt 540 320 modal:true
            DanxSafetyDecision
        )
    ),
    fn inspectFile path manual:false =
    (
        local result = core.Probe path
        case result of
        (
            0: (if manual do notifySuccess "检查完成：未发现本版本识别的恶意脚本特征。"; true)
            1:
            (
                writeLog ("发现 CRP：" + path)
                local approved = askToClean ("发现 CRP 病毒：\n" + path + "\n\n清理前会备份原件，仅移除已确认的病毒脚本，并校验模型数据。\n选择暂不清理后，源文件仍含病毒；旧版 Max 的载入后检查不能保证病毒代码完全没有运行。")
                if approved then
                (
                    if core.CleanFile path backupRoot then
                    (
                        declinedPath = ""
                        writeLog ("文件清理成功：" + path + "；备份：" + core.LastBackup)
                        notifySuccess "CRP 已清理，模型数据已保留。"
                        true
                    )
                    else (notifyProblem ("未能清理，原文件未被替换：\n" + path + "\n\n" + core.LastMessage); false)
                )
                else
                (
                    declinedPath = path
                    lastStatus = "用户暂不清理源文件"
                    writeLog ("用户暂不清理：" + path)
                    false
                )
            )
            default:
            (
                local key = path + "|" + core.LastMessage
                if manual or (findItem warned key == 0) do
                (
                    append warned key
                    notifyProblem ("文件检查需要人工处理：\n" + path + "\n\n" + core.LastMessage + "\n\n此文件未被自动修改。")
                )
                false
            )
        )
    ),
    fn hasRuntimeCRP =
    (
        local found = false
        for ident in #(#CRP_AScript, #CRP_BScript) do
        (
            if globalVars.isGlobal ident do try
            (
                local value = globalVars.get ident
                if classOf value == String and value.count > 0 do found = true
            )catch()
        )
        found
    ),
    fn removeRuntimeCRP =
    (
        local found = hasRuntimeCRP()
        for ident in crpIDs do try(callbacks.removeScripts id:ident)catch()
        if found do
        (
            for ident in crpGlobals do
            (
                try(persistents.remove ident)catch()
                try(globalVars.remove ident)catch()
            )
            setSaveRequired true
            writeLog "已从当前场景移除 CRP 全局变量及已知回调；未修改物体、材质、灯光。"
        )
        found
    ),
    fn beforeOpen =
    (
        if not busy do
        (
            busy = true
            declinedPath = ""
            try
            (
                local info = callbacks.notificationParam()
                if (classOf info == Array) and info.count >= 2 do
                (
                    local path = info[2]
                    if (classOf path == String) and doesFileExist path do inspectFile path
                )
            )
            catch (writeLog ("载入前检查异常：" + (getCurrentException())))
            busy = false
        )
    ),
    fn afterEvent reason =
    (
        if not busy do
        (
            busy = true
            try
            (
                local found = removeRuntimeCRP()
                if found do
                (
                    local path = maxFilePath + maxFileName
                    if reason == #open and maxFileName != "" and doesFileExist path then
                    (
                        if (toLower path) != (toLower declinedPath) do inspectFile path
                    )
                    else
                    (
                        local approved = askToClean "合并或导入后发现 CRP。\n\n已移除当前场景中的已知 CRP 回调和持久变量。物体、材质、灯光保持原样。\n\n确认清理后，请按正常方式保存当前场景。Max 2014/2015 不提供可靠的合并/导入源文件路径，因此不会覆盖未知源文件。"
                        writeLog ("合并/导入场景清理；用户确认：" + (approved as string))
                        if approved do notifySuccess "当前场景中的 CRP 已清理，请正常保存场景。"
                    )
                )
                local other = #(#ADSL_BScript, #AutodeskLicSerStuckCleanBeta, #AutodeskLicSerStuckBeta, #PhysXPluginMfx, #PhysXPluginStl, #MSCPROP)
                for ident in other where globalVars.isGlobal ident do
                (
                    local key = ident as string
                    if findItem warned key == 0 do
                    (
                        append warned key
                        notifyProblem ("发现其他已知恶意标记：" + key + "。\n本版本只自动清理 CRP，请先停止保存或传播此场景并进行专项检查。")
                    )
                )
            )
            catch (writeLog ("载入后检查异常：" + (getCurrentException())))
            busy = false
        )
    ),
    fn quickGuard =
    (
        if not busy and hasRuntimeCRP() do afterEvent #runtime
    ),
    fn scanStartup =
    (
        local folders = #()
        try(append folders (getDir #startupScripts))catch()
        try
        (
            local folder = getDir #userStartupScripts
            if findItem folders folder == 0 do append folders folder
        )catch()
        for folder in folders do
        (
            for path in getFiles (folder + "\\*.ms") do
            (
                local result = core.Probe path
                if result != 0 do inspectFile path
            )
        )
    ),
    fn installCallbacks =
    (
        callbacks.removeScripts id:#DanxSafetyGuard
        callbacks.addScript #filePreOpenProcess "if DanxSafety != undefined do DanxSafety.beforeOpen()" id:#DanxSafetyGuard persistent:false
        callbacks.addScript #filePostOpen "if DanxSafety != undefined do DanxSafety.afterEvent #open" id:#DanxSafetyGuard persistent:false
        callbacks.addScript #filePostMerge "if DanxSafety != undefined do DanxSafety.afterEvent #merge" id:#DanxSafetyGuard persistent:false
        callbacks.addScript #postImport "if DanxSafety != undefined do DanxSafety.afterEvent #import" id:#DanxSafetyGuard persistent:false
        callbacks.addScript #filePreSave "if DanxSafety != undefined do DanxSafety.quickGuard()" id:#DanxSafetyGuard persistent:false
        callbacks.addScript #preRender "if DanxSafety != undefined do DanxSafety.quickGuard()" id:#DanxSafetyGuard persistent:false
        callbacks.addScript #viewportChange "if DanxSafety != undefined do DanxSafety.quickGuard()" id:#DanxSafetyGuard persistent:false
        writeLog "防护启动：已注册打开、合并、导入、保存、渲染及视口检查。"
    )
)

rollout DanxSafetyPrompt "3danx 安全卫士 — 发现 CRP"
(
    editText details "" pos:[16,12] width:505 height:184 readOnly:true
    checkbox cbAuto "以后自动清理已确认的 CRP（仍会备份）" pos:[18,205] checked:false
    checkbox cbSilent "清理完成后不通知（失败和未知情况仍会提示）" pos:[18,233] checked:true
    button btnClean "清理 CRP" pos:[18,273] width:235 height:30
    button btnLater "暂不处理" pos:[282,273] width:235 height:30
    on DanxSafetyPrompt open do
    (
        details.text = DanxSafetyPromptText
        cbAuto.checked = DanxSafety.autoClean
        cbSilent.checked = DanxSafety.silentSuccess
    )
    on cbAuto changed state do (DanxSafety.autoClean = state; DanxSafety.saveSettings())
    on cbSilent changed state do (DanxSafety.silentSuccess = state; DanxSafety.saveSettings())
    on btnClean pressed do (DanxSafetyDecision = true; destroyDialog DanxSafetyPrompt)
    on btnLater pressed do (DanxSafetyDecision = false; destroyDialog DanxSafetyPrompt)
)

rollout DanxSafetySettings "3danx 安全卫士 — 设置"
(
    label titleText "CRP 专项防护 · Max 2014 / 2015" pos:[18,15] width:450 height:22
    label scopeText "启动后自动检查打开、合并和导入的场景。" pos:[18,45] width:450
    checkbox cbAuto "自动清理已确认的 CRP（不再询问，仍会备份）" pos:[18,79] checked:false
    checkbox cbSilent "清理完成后不通知" pos:[18,111] checked:true
    label failureText "失败、无法检查及其他恶意标记仍会提示。" pos:[38,140] width:445
    label saveText "合并/导入后清理当前场景，请正常保存。" pos:[18,170] width:460
    label statusText "" pos:[18,202] width:460 height:30
    button btnScene "检查当前场景" pos:[18,245] width:220 height:30
    button btnFile "检查一个文件…" pos:[258,245] width:220 height:30
    button btnBackups "查看备份" pos:[18,291] width:140 height:28
    button btnLog "查看日志" pos:[178,291] width:140 height:28
    button btnClose "关闭" pos:[338,291] width:140 height:28
    on DanxSafetySettings open do
    (
        cbAuto.checked = DanxSafety.autoClean
        cbSilent.checked = DanxSafety.silentSuccess
        statusText.text = DanxSafety.lastStatus
    )
    on cbAuto changed state do (DanxSafety.autoClean = state; DanxSafety.saveSettings())
    on cbSilent changed state do (DanxSafety.silentSuccess = state; DanxSafety.saveSettings())
    on btnScene pressed do
    (
        if DanxSafety.hasRuntimeCRP() then DanxSafety.afterEvent #manual
        else
        (
            local path = maxFilePath + maxFileName
            if maxFileName != "" and doesFileExist path then DanxSafety.inspectFile path manual:true
            else DanxSafety.notifySuccess "当前场景未发现本版本识别的 CRP 变量；场景尚未保存。"
        )
        statusText.text = DanxSafety.lastStatus
    )
    on btnFile pressed do
    (
        local path = getOpenFileName caption:"选择文件进行检查" types:"3ds Max 场景 (*.max)|*.max|MAXScript (*.ms)|*.ms|"
        if path != undefined do DanxSafety.inspectFile path manual:true
        statusText.text = DanxSafety.lastStatus
    )
    on btnBackups pressed do ShellLaunch DanxSafety.backupRoot ""
    on btnLog pressed do ShellLaunch (DanxSafety.root + "\\3danxSafety.log") ""
    on btnClose pressed do destroyDialog DanxSafetySettings
)

fn DanxSafetyShowSettings =
(
    if DanxSafety != undefined do
    (
        try(destroyDialog DanxSafetySettings)catch()
        createDialog DanxSafetySettings 500 340
    )
)

(
    local sourceDir = getFilenamePath (getSourceFileName())
    local dataDir = (dotNetClass "System.Environment").GetEnvironmentVariable "LOCALAPPDATA"
    dataDir += "\\3danxSafety"
    makeDir dataDir all:true
    dotNet.loadAssembly (sourceDir + "3danx.Security.dll")
    DanxSafety = DanxSafetyController root:dataDir iniPath:(dataDir + "\\settings.ini") backupRoot:(dataDir + "\\Backups") core:(dotNetClass "DanxSafety.SecurityCore")
    makeDir DanxSafety.backupRoot all:true
    DanxSafety.readSettings()
    DanxSafety.installCallbacks()
    DanxSafety.scanStartup()
    DanxSafety.afterEvent #startup
)

macroScript DanxSafetyOpenSettings category:"3danx 安全卫士" tooltip:"3danx 安全卫士设置" buttonText:"3danx 安全卫士"
(
    on execute do DanxSafetyShowSettings()
)
