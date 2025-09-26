-----------------------------------------------------------
-- CONFIGURATION: Set your URLs / settings here
-----------------------------------------------------------
local CONSTANS = {
    AUTH_URL = "https://raw.githubusercontent.com/Finnjay60/ps_loader/refs/heads/main/auth.json", -- RAW URL zu auth.json
    UPDATE_URL = "https://raw.githubusercontent.com/Finnjay60/ps_loader/refs/heads/main/loader.lua", -- RAW URL zu loader.lua
    DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1405664022128361582/Qkx-N6hHThtrQST5la6WScEul2HTQzOL8Dwch7pj5ieFSdoEdSvRDZy9w0XTvjlh7JAj", -- Discord webhook
    REQUIRED_AUTH_VERSION = "1.0.0", -- Erwartete auth.json Version
    CHECK_INTERVAL_MS = 60 * 1000,       -- Hauptloop Intervall (ms)
    UPDATE_CHECK_DELAY_MS = 2 * 1000,    -- Delay bevor erstes Update-Check
    AUTH_CHECK_DELAY_MS = 4 * 1000,      -- Delay bevor erstes Auth-Check
    MAX_HTTP_RETRIES = 2,
    LOG_USERNAME = "PixelService",
    RESOURCE_NAME = GetCurrentResourceName and GetCurrentResourceName() or "ps_loaderv2"
}

-----------------------------------------------------------
-- EXPECTED FXMANIFEST (used to validate fxmanifest.lua)
-----------------------------------------------------------
local fxmanifest_data = [[
fx_version 'cerulean'
game 'gta5'
lua54 'yes'
server_script 'loader.lua'
]]

-----------------------------------------------------------
-- INTERNAL STATE
-----------------------------------------------------------
local availableScript = {}    -- table { ["ResourceName"] = true }
local httpDispatch = {}       -- map token -> callback for InternalEx
local awaitingStartUp = false
local healthStatus = {
    lastAuth = nil,
    lastUpdate = nil,
    lastExploitCheck = nil,
    lastDiscord = nil
}

-----------------------------------------------------------
-- UTIL: Branded console print
-----------------------------------------------------------
local function brandedPrint(level, prefix, msg)
    level = level or "INFO"
    prefix = prefix or CONSTANS.RESOURCE_NAME
    local stamp = os.date("%Y-%m-%d %H:%M:%S")
    local out = string.format("[%s] [PixelService] [%s] [%s] %s", stamp, level, prefix, tostring(msg))
    print(out)
end

-----------------------------------------------------------
-- UTIL: Discord embed sender (best-effort)
-----------------------------------------------------------
local function sendToDiscord(title, description, color, fields)
    if not CONSTANS.DISCORD_WEBHOOK or CONSTANS.DISCORD_WEBHOOK == "" then
        brandedPrint("WARN", "Discord", "Discord Webhook nicht konfiguriert; sende nichts.")
        return
    end

    local embed = {
        {
            ["title"] = "📡 PixelService — " .. (title or "Log"),
            ["description"] = description or "",
            ["color"] = color or 16753920,
            ["footer"] = { ["text"] = "PixelService Security Loader • " .. CONSTANS.RESOURCE_NAME },
            ["timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }
    }

    if fields and type(fields) == "table" then
        embed[1]["fields"] = fields
    end

    local payload = {
        username = CONSTANS.LOG_USERNAME,
        embeds = embed
    }

    local ok, err = pcall(function()
        PerformHttpRequest(CONSTANS.DISCORD_WEBHOOK, function(status, text, headers)
            healthStatus.lastDiscord = { status = status, time = os.time() }
            brandedPrint("INFO", "Discord", "Webhook send -> HTTP " .. tostring(status))
        end, "POST", json.encode(payload), { ["Content-Type"] = "application/json" })
    end)

    if not ok then
        brandedPrint("ERROR", "Discord", "Fehler beim Senden an Discord Webhook: " .. tostring(err))
    end
end

-----------------------------------------------------------
-- UTIL: Safe HTTP dispatcher (InternalEx preferred)
-----------------------------------------------------------
local function performHttpRequest(url, cb, method, data, headers, options)
    if type(url) ~= "string" or url == "" then
        if type(cb) == "function" then cb(0, nil, {}, "invalid-url") end
        return -1
    end

    headers = headers or {}
    method = method or "GET"

    local payload = {
        url = url,
        method = method,
        data = data or "",
        headers = headers,
        followLocation = true
    }

    if options and options.followLocation ~= nil then
        payload.followLocation = options.followLocation
    end

    if PerformHttpRequestInternalEx then
        local ok, token = pcall(function() return PerformHttpRequestInternalEx(payload) end)
        if ok and token and token ~= -1 then
            httpDispatch[token] = cb
            return token
        else
            -- fallback to PerformHttpRequest
            local fbOk, fbErr = pcall(function()
                PerformHttpRequest(url, function(status, text, hdrs)
                    if cb then cb(status, text, hdrs, nil) end
                end, method, data, headers)
            end)
            if not fbOk and cb then cb(0, nil, {}, tostring(fbErr)) end
            return -1
        end
    else
        local ok, err = pcall(function()
            PerformHttpRequest(url, function(status, text, hdrs)
                if cb then cb(status, text, hdrs, nil) end
            end, method, data, headers)
        end)
        if not ok and cb then cb(0, nil, {}, tostring(err)) end
        return -1
    end
end

-----------------------------------------------------------
-- HTTP Internal Response handler
-----------------------------------------------------------
AddEventHandler("__cfx_internal:httpResponse", function(token, status, body, headers, err)
    local cb = httpDispatch[token]
    if cb then
        httpDispatch[token] = nil
        local ok, e = pcall(cb, status, body, headers, err)
        if not ok then
            brandedPrint("ERROR", "HTTP_CB", "Callback error: " .. tostring(e))
        end
    end
end)

-----------------------------------------------------------
-- EXPORTS: keep legacy weird names and add PixelService_IsAllowed
-----------------------------------------------------------
exports("LaRdoUGhtArMENoLEaLgaUGUrvIXteOrW", function()
    return true
end)

exports("rAIrySIontIGHtEMiTerslEfRaiNG]eSILIaLACkEnsISHanou", function()
    return 3
end)

-- Export: allow other resources to query if they are allowed
exports("PixelService_IsAllowed", function(resourceName)
    resourceName = resourceName or GetCurrentResourceName()
    if not resourceName then return false end
    return (availableScript and availableScript[resourceName]) and true or false
end)

-----------------------------------------------------------
-- START/STOP EVENTS
-----------------------------------------------------------
RegisterNetEvent("onResourceStart", function()
    awaitingStartUp = true
    SetTimeout(1000, function() awaitingStartUp = false end)
end)

RegisterNetEvent("onResourceStop", function(resourceName)
    if resourceName == CONSTANS.RESOURCE_NAME then
        for k, v in pairs(availableScript) do
            local ok, err = pcall(function() StopResource(k) end)
            if not ok then
                brandedPrint("WARN", "ResourceStop", "Fehler beim Stoppen: " .. tostring(err))
            end
        end
    end
end)

-----------------------------------------------------------
-- RANDOM / TOKEN UTILITIES
-----------------------------------------------------------
local random_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
local random_digits = "0123456789"
local random_table = {}
local random_table_digits = {}
for i = 1, #random_chars do table.insert(random_table, random_chars:sub(i, i)) end
for i = 1, #random_digits do table.insert(random_table_digits, random_digits:sub(i, i)) end

math.randomseed(os.time() % 2147483647)

local words = {
    "apple","banana","cherry","dragon","elephant","flamingo","grape","hippopotamus",
    "iguana","jungle","kiwi","lemon","mango","nectarine","orange","papaya",
    "quokka","raspberry","strawberry","tangerine","umbrella","vanilla","watermelon",
    "xylophone","yogurt","zebra","avocado","blueberry","coconut","date","fig",
    "guava","honeydew","jackfruit","kumquat","lime","mulberry","olive","peach",
    "quince","rhubarb","starfruit","tomato","ugli","voavanga","wolfberry","ximenia",
    "yangmei","zucchini","apricot","blackberry","cantaloupe","durian","elderberry",
    "feijoa","grapefruit","hackberry","ilama","jabuticaba","kiwano","longan","mandarin",
    "nashi","okra","persimmon","quenepa","rambutan","soursop","tamarind","ugni",
    "volkameria","waxapple","yumberry","ziziphus","ackfruit","bilberry","cloudberry","damson","emblic","fingerlime"
}

local function generateWordTokens(num_words)
    num_words = num_words or 3
    local t = {}
    for i = 1, num_words do
        table.insert(t, words[math.random(1, #words)])
    end
    return table.concat(t, "-")
end

local function generateRandomString(len, insertWords)
    len = len or 16
    local t = {}
    for i = 1, len do
        table.insert(t, random_table[math.random(1, #random_table)])
    end
    if insertWords then
        local w = generateWordTokens(3)
        local pos = math.max(2, math.min(#t - 1, math.random(2, #t - 1)))
        table.insert(t, pos, w)
    end
    return table.concat(t, "")
end

local function generateRandomNumberString(len)
    len = len or 6
    local t = {}
    for i = 1, len do table.insert(t, random_table_digits[math.random(1, #random_table_digits)]) end
    return table.concat(t, "")
end

local function getDiskSerialNumber()
    return "ps-" .. generateRandomString(8, false)
end

-----------------------------------------------------------
-- INTEGRITY / EXPLOIT Checks
-----------------------------------------------------------
local function checkCoreFunctions()
    local checks = {
        { fn = load, name = "load" },
        { fn = pcall, name = "pcall" },
        { fn = (debug and debug.getinfo) or nil, name = "debug.getinfo" },
        { fn = math and math.random or nil, name = "math.random" }
    }
    for _, v in ipairs(checks) do
        if not v.fn then
            brandedPrint("ERROR", "Integrity", "Core function missing: " .. tostring(v.name))
            return false
        end
        local ok, info = pcall(function() return debug.getinfo(v.fn) end)
        if not ok or not info then
            brandedPrint("ERROR", "Integrity", "debug.getinfo check failed for: " .. tostring(v.name))
            return false
        end
    end
    return true
end

local function checkProcessList()
    local suspicious = {
        "HTTPDebuggerUI.exe",
        "HTTP Toolkit.exe",
        "HTTPDebuggerSvc.exe",
        "Postman.exe",
        "Wireshark.exe",
        "Fiddler.exe",
        "Charles.exe"
    }
    if not io or not io.popen then
        return true
    end
    local ok, handle = pcall(function() return io.popen('tasklist', 'r') end)
    if not ok or not handle then return true end
    local output = handle:read("*a")
    handle:close()
    for _, proc in ipairs(suspicious) do
        if output:find(proc, 1, true) then
            brandedPrint("WARN", "ProcessCheck", "Suspicious process found: " .. proc)
            return false
        end
    end
    return true
end

local function checkStringDump()
    if not string or not string.dump then return true end
    local ok, info = pcall(function() return debug.getinfo(string.dump) end)
    if not ok or not info then return false end
    return true
end

local function checkExploits()
    local ok1 = checkCoreFunctions()
    if not ok1 then return false end
    local ok2 = checkProcessList()
    if not ok2 then return false end
    local ok3 = checkStringDump()
    if not ok3 then return false end
    return true
end

-----------------------------------------------------------
-- RANDOM PAYLOAD generator (safe imitation)
-----------------------------------------------------------
local function generateRandomPayload()
    local result = {}
    for i = 1, 120 do
        local k = generateRandomString(math.random(5, 10), true)
        local v = generateRandomString(math.random(8, 24), false)
        result[k] = v
    end
    result["sec_token_1"] = generateRandomString(16)
    result["sec_token_2"] = generateRandomString(16)
    result["sec_token_3"] = generateRandomString(16)
    result["spectral_token"] = getDiskSerialNumber()
    result["resource_name"] = CONSTANS.RESOURCE_NAME
    result["random_seed"] = math.floor(math.random(100, 10000))
    return result
end

-----------------------------------------------------------
-- CRASH: graceful then hang (used on tamper detection)
-----------------------------------------------------------
local function crashServer(reason)
    reason = reason or "unbekannt"
    brandedPrint("ERROR", "Crash", "Crashing server due to: " .. tostring(reason))
    sendToDiscord("⛔ PixelService Crash", "Crashing loader: " .. tostring(reason), 16711680, {
        { name = "Reason", value = tostring(reason), inline = true },
        { name = "Resource", value = CONSTANS.RESOURCE_NAME, inline = true }
    })
    CreateThread(function()
        Wait(100)
        if os and os.exit then
            pcall(os.exit, 0)
        end
        while true do
            Wait(1000)
        end
    end)
end

-----------------------------------------------------------
-- FXMANIFEST check + attempt to repair
-----------------------------------------------------------
local function checkFxManifest()
    if not LoadResourceFile then
        brandedPrint("WARN", "FXCheck", "LoadResourceFile not available in this environment.")
        return true
    end
    local fx_manifest = LoadResourceFile(GetCurrentResourceName(), 'fxmanifest.lua')
    if not fx_manifest then
        brandedPrint("ERROR", "FXCheck", "FXManifest konnte nicht geladen werden.")
        sendToDiscord("❌ FXManifest", "FXManifest fehlt oder konnte nicht gelesen werden.", 16711680)
        return false
    end
    local function normalize(s) return (s or ""):gsub("%s+", "") end
    if normalize(fx_manifest) ~= normalize(fxmanifest_data) then
        brandedPrint("WARN", "FXCheck", "Ungültige oder veränderte fxmanifest.lua erkannt. Versuche Korrektur.")
        local ok, err = pcall(function()
            SaveResourceFile(GetCurrentResourceName(), "fxmanifest.lua", fxmanifest_data, -1)
        end)
        if not ok then
            brandedPrint("ERROR", "FXCheck", "Konnte fxmanifest.lua nicht speichern: " .. tostring(err))
            sendToDiscord("❌ FXManifest Save Error", tostring(err), 16711680)
            return false
        end
        brandedPrint("INFO", "FXCheck", "fxmanifest.lua erfolgreich ersetzt.")
        sendToDiscord("⚠️ FXManifest ersetzt", "fxmanifest.lua wurde durch PixelService ersetzt.", 16753920)
    end
    return true
end

-----------------------------------------------------------
-- AUTH: Get auth.json from GitHub, validate license key and set availableScript
-----------------------------------------------------------
local function performAuthCheck()
    if not CONSTANS.AUTH_URL or CONSTANS.AUTH_URL == "" then
        brandedPrint("ERROR", "Auth", "AUTH_URL nicht gesetzt.")
        sendToDiscord("❌ Auth Fehler", "AUTH_URL ist nicht konfiguriert.", 16711680)
        crashServer("AUTH_URL not set")
        return
    end

    local licenseKey = GetConvar("pixel_license_key", "") or ""
    if licenseKey == "" then
        brandedPrint("ERROR", "Auth", "Kein server license key gesetzt (server.cfg: setr pixel_license_key '...').")
        sendToDiscord("❌ Auth Fehler", "Es ist kein Lizenz-Key in server.cfg gesetzt!", 16711680)
        crashServer("No license key set")
        return
    end

    local retries = 0
    local function tryOnce()
        performHttpRequest(CONSTANS.AUTH_URL, function(status, body, headers, err)
            healthStatus.lastAuth = { status = status, time = os.time() }
            if status ~= 200 or not body then
                brandedPrint("ERROR", "Auth", "Fehler beim Abrufen der Auth-Datei. HTTP: " .. tostring(status) .. " err: " .. tostring(err))
                retries = retries + 1
                if retries <= CONSTANS.MAX_HTTP_RETRIES then
                    brandedPrint("INFO", "Auth", "Retrying Auth fetch (" .. retries .. ")")
                    SetTimeout(2000, tryOnce)
                else
                    sendToDiscord("❌ Auth Fehler", "Mehrere Versuche, auth.json zu laden, fehlgeschlagen. HTTP: " .. tostring(status), 16711680)
                    crashServer("Auth fetch failed")
                end
                return
            end

            local ok, authData = pcall(function() return json.decode(body) end)
            if not ok or type(authData) ~= "table" then
                brandedPrint("ERROR", "Auth", "Ungültiges JSON in auth.json.")
                sendToDiscord("❌ Auth JSON Invalid", "auth.json konnte nicht geparst werden.", 16711680)
                crashServer("Invalid auth.json")
                return
            end

            -- version prüfen
            if not authData.version then
                brandedPrint("WARN", "Auth", "auth.json enthält keine version. Fortfahren, aber prüfen empfohlen.")
                sendToDiscord("⚠️ Auth Version", "auth.json enthält keine version.", 16753920)
            else
                if authData.version ~= CONSTANS.REQUIRED_AUTH_VERSION then
                    brandedPrint("WARN", "Auth", "auth.json version (" .. tostring(authData.version) .. ") stimmt nicht mit erwartet (" .. CONSTANS.REQUIRED_AUTH_VERSION .. ").")
                    sendToDiscord("⚠️ Auth Version Mismatch", "Version mismatch: "..tostring(authData.version).." expected: "..CONSTANS.REQUIRED_AUTH_VERSION, 16753920)
                    -- optional: crashServer("Auth version mismatch")
                end
            end

            if authData.error then
                brandedPrint("ERROR", "Auth", "Auth Server Error: " .. tostring(authData.error))
                sendToDiscord("❌ Auth Error", tostring(authData.error), 16711680)
                crashServer("Auth error from json")
                return
            end

            if not authData.success then
                brandedPrint("ERROR", "Auth", "Auth success flag false.")
                sendToDiscord("🔒 Auth Invalid", "auth.json returned success=false", 16711680)
                crashServer("Auth not successful")
                return
            end

            -- server mapping prüfen
            if not authData.servers or not authData.servers[licenseKey] then
                brandedPrint("ERROR", "Auth", "Lizenzschlüssel nicht gefunden: " .. licenseKey)
                sendToDiscord("❌ Lizenz ungültig", "License key not in auth.json: "..licenseKey, 16711680)
                crashServer("License key not found")
                return
            end

            local serverEntry = authData.servers[licenseKey]

            -- expires prüfen (format YYYY-MM-DD)
            if serverEntry.expires then
                local y,m,d = serverEntry.expires:match("(%d+)-(%d+)-(%d+)")
                if y and m and d then
                    local expTime = os.time({year=tonumber(y), month=tonumber(m), day=tonumber(d), hour=0})
                    if os.time() > expTime then
                        brandedPrint("ERROR", "Auth", "Lizenzschlüssel abgelaufen: " .. licenseKey)
                        sendToDiscord("❌ Lizenz abgelaufen", "License key abgelaufen: "..licenseKey, 16711680)
                        crashServer("License expired")
                        return
                    end
                end
            end

            -- allowed Produkte übernehmen (überschreibt globale products)
            availableScript = {}
            if type(serverEntry.allowed) == "table" then
                for _, prod in ipairs(serverEntry.allowed) do
                    availableScript[tostring(prod)] = true
                end
            end

            local allowedList = table.concat(serverEntry.allowed or {}, ", ")
            brandedPrint("INFO", "Auth", "Server autorisiert. License="..licenseKey.." erlaubt: "..allowedList)
            sendToDiscord("🔒 Server-Lizenz validiert", "License="..licenseKey.." erlaubt: "..allowedList, 3447003)

            return true
        end, "GET", nil, { ["User-Agent"] = "PixelService-Loader/1.0" })
    end

    tryOnce()
end

-----------------------------------------------------------
-- UPDATE: compare loader.lua from GitHub and save if changed
-----------------------------------------------------------
local function performUpdateCheck()
    if not CONSTANS.UPDATE_URL or CONSTANS.UPDATE_URL == "" then
        brandedPrint("WARN", "Update", "UPDATE_URL nicht gesetzt; überspringe Update-Check.")
        return
    end

    local retries = 0
    local function tryOnce()
        performHttpRequest(CONSTANS.UPDATE_URL, function(status, body, headers, err)
            healthStatus.lastUpdate = { status = status, time = os.time() }
            if status ~= 200 or not body then
                brandedPrint("WARN", "Update", "Fehler beim Abrufen des Updates. HTTP: " .. tostring(status))
                retries = retries + 1
                if retries <= CONSTANS.MAX_HTTP_RETRIES then
                    SetTimeout(1000, tryOnce)
                else
                    brandedPrint("WARN", "Update", "Update-Check fehlgeschlagen nach mehreren Versuchen.")
                end
                return
            end

            local current_code = ""
            if LoadResourceFile then
                current_code = LoadResourceFile(GetCurrentResourceName(), "loader.lua") or ""
            end

            if current_code ~= body then
                brandedPrint("INFO", "Update", "Neue Version des Loaders gefunden. Versuche zu speichern.")
                local ok, err = pcall(function()
                    SaveResourceFile(GetCurrentResourceName(), "loader.lua", body, -1)
                end)
                if ok then
                    brandedPrint("INFO", "Update", "Update gespeichert. Neustart erforderlich.")
                    sendToDiscord("✅ Update", "PixelService Loader wurde erfolgreich aktualisiert. Neustart erforderlich.", 3066993)
                    crashServer("Update applied")
                else
                    brandedPrint("ERROR", "Update", "Konnte Update nicht speichern: " .. tostring(err))
                    sendToDiscord("❌ Update Save Error", tostring(err), 16711680)
                end
            else
                brandedPrint("INFO", "Update", "Kein Update erforderlich; Code ist aktuell.")
            end
        end, "GET", nil, { ["User-Agent"] = "PixelService-Loader/1.0" })
    end

    tryOnce()
end

-----------------------------------------------------------
-- PERIODIC MONITOR: exploit checks, auth refresh, update
-----------------------------------------------------------
CreateThread(function()
    Wait(1000)
    local fx_ok = checkFxManifest()
    if not fx_ok then
        brandedPrint("ERROR", "Startup", "fxmanifest check failed -> crash")
        crashServer("fxmanifest invalid")
        return
    end

    if not checkExploits() then
        brandedPrint("ERROR", "Startup", "Exploit checks failed -> crash")
        sendToDiscord("⚠️ Exploit Schutz", "Beim Start wurden Integritätsprüfungen nicht bestanden.", 16711680)
        crashServer("integrity checks failed")
        return
    end

    Wait(CONSTANS.AUTH_CHECK_DELAY_MS)
    performAuthCheck()
    Wait(CONSTANS.UPDATE_CHECK_DELAY_MS)
    performUpdateCheck()

    while true do
        local ok, res = pcall(checkExploits)
        if not ok or not res then
            brandedPrint("ERROR", "Monitor", "Laufender Exploit-Check hat ein Problem festgestellt.")
            sendToDiscord("⚠️ Exploit Check Fail", "Laufender Exploit-Check hat einen Fehler festgestellt. -> Crash", 16711680)
            crashServer("running exploit check failed")
            return
        else
            healthStatus.lastExploitCheck = os.time()
        end

        -- auth refresh if older than CHECK_INTERVAL_MS
        if not healthStatus.lastAuth or (os.time() - (healthStatus.lastAuth.time or 0) > (CONSTANS.CHECK_INTERVAL_MS / 1000)) then
            performAuthCheck()
        end

        -- update check
        if not healthStatus.lastUpdate or (os.time() - (healthStatus.lastUpdate.time or 0) > (CONSTANS.CHECK_INTERVAL_MS / 1000)) then
            performUpdateCheck()
        end

        Wait(CONSTANS.CHECK_INTERVAL_MS)
    end
end)

-----------------------------------------------------------
-- DEBUG / ADMIN COMMANDS
-----------------------------------------------------------
local function getStatus()
    local productCount = 0
    for _ in pairs(availableScript) do productCount = productCount + 1 end
    return {
        resource = CONSTANS.RESOURCE_NAME,
        products = productCount,
        availableScript = availableScript,
        health = healthStatus,
        time = os.time()
    }
end

RegisterCommand("pixelstatus", function(source, args, raw)
    local s = getStatus()
    local summary = string.format("PixelService Status: resource=%s, products=%d, lastAuth=%s, lastUpdate=%s",
        tostring(s.resource),
        s.products,
        tostring(s.health.lastAuth and s.health.lastAuth.time or "never"),
        tostring(s.health.lastUpdate and s.health.lastUpdate.time or "never")
    )
    if source == 0 then
        brandedPrint("INFO", "StatusCmd", summary)
    else
        TriggerClientEvent("chat:addMessage", source, { args = { "PixelService", summary } })
    end
end, true)

RegisterCommand("pixelupdate", function(source, args, raw)
    local who = source == 0 and "server" or ("player:" .. tostring(source))
    brandedPrint("INFO", "UpdateCmd", "Manual update check requested by " .. who)
    sendToDiscord("🛠️ Manual Update", "Update requested by " .. who, 3447003)
    CreateThread(function() performUpdateCheck() end)
end, true)

RegisterCommand("pixelauth", function(source, args, raw)
    local who = source == 0 and "server" or ("player:" .. tostring(source))
    brandedPrint("INFO", "AuthCmd", "Manual auth refresh requested by " .. who)
    sendToDiscord("🛠️ Manual Auth", "Auth refresh requested by " .. who, 3447003)
    CreateThread(function() performAuthCheck() end)
end, true)

RegisterCommand("pixelrand", function(source, args, raw)
    local payload = generateRandomPayload()
    local short = {}
    local i = 0
    for k, v in pairs(payload) do
        i = i + 1
        if i <= 12 then table.insert(short, tostring(k) .. "=" .. tostring(v)) end
    end
    local out = table.concat(short, ", ")
    if source == 0 then
        brandedPrint("INFO", "RandCmd", out)
    else
        TriggerClientEvent("chat:addMessage", source, { args = { "PixelService", out } })
    end
end, true)

-----------------------------------------------------------
-- STARTUP MESSAGE
-----------------------------------------------------------
brandedPrint("INFO", "Startup", "PixelService Loader initialisiert. Resource: " .. CONSTANS.RESOURCE_NAME)
sendToDiscord("🚀 PixelService Loader gestartet", "PixelService Loader wurde gestartet und initialisiert.", 3066993, {
    { name = "Resource", value = CONSTANS.RESOURCE_NAME, inline = true },
    { name = "Auth URL", value = CONSTANS.AUTH_URL or "not set", inline = false }
})

-- EOF
