--[[
===============================================================================
 PixelService Loader v0.0.3 - FULL (ps_loaderv2)
 -------------------------------------------------------------------------------
 Vollständiger Loader mit:
  - GitHub-based auth.json & self-update (RAW URLs)
  - Discord Webhook Logging (Embeds)
  - Server license keys via convar: pixel_license_key
  - Server-level blacklisting (global & per-license)
  - Product -> automatic resource mapping: product "CharCreator" -> "ps_charcreator"
  - Script IDs: jede erlaubte Ressource bekommt eine interne Script-ID (stable hash)
  - Exports:
      PixelService_IsAllowed(resourceName)
      PixelService_SendWebhook(resourceName, title, message, color, fields)
      PixelService_GetInfo() -> returns auth / allowed info
  - Auto-scan of running ps_ resources (notify webhook)
  - Minimal console spam while still informative (colorized)
  - Extensive comments and documentation inside file
  - Example snippet for resources included (copy-paste)
 -------------------------------------------------------------------------------
 USAGE:
  - Put this file in your loader resource folder (recommended name: ps_loaderv2)
  - Upload auth.json & loader.lua to your GitHub repo (RAW urls)
  - Set server cfg: setr pixel_license_key "srv-ABC123"
  - Start the loader resource on the server
  - Add the provided snippet to each of your ps_* resources (server/main.lua)
===============================================================================
--]]

--------------------------------------------------------------------------------
-- CONFIGURATION / CONSTANTS
-- Update AUTH_URL / UPDATE_URL / DISCORD_WEBHOOK if you move the repo or webhook
--------------------------------------------------------------------------------
local CONSTANS = {
    AUTH_URL = "https://raw.githubusercontent.com/Finnjay60/ps_loader/refs/heads/main/auth.json",
    UPDATE_URL = "https://raw.githubusercontent.com/Finnjay60/ps_loader/refs/heads/main/loader.lua",
    DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1405664022128361582/Qkx-N6hHThtrQST5la6WScEul2HTQzOL8Dwch7pj5ieFSdoEdSvRDZy9w0XTvjlh7JAj",
    REQUIRED_AUTH_VERSION = "0.0.3",
    CHECK_INTERVAL_MS = 90 * 1000,       -- 90 seconds by default (less spam)
    UPDATE_CHECK_DELAY_MS = 3 * 1000,
    AUTH_CHECK_DELAY_MS = 3 * 1000,
    MAX_HTTP_RETRIES = 3,
    LOG_USERNAME = "PixelService",
    RESOURCE_NAME = GetCurrentResourceName and GetCurrentResourceName() or "ps_loaderv2",
    -- toggle some behavior
    REPORT_ON_START = true,              -- send server info to webhook on loader start
    ALLOW_NONPS_PREFIX = false,          -- if true, WILL allow resources without ps_ (not recommended)
    VERBOSE = false                       -- for debug mode (more console logs)
}

--------------------------------------------------------------------------------
-- INTERNAL STATE
--------------------------------------------------------------------------------
local state = {
    auth = nil,               -- parsed auth.json table
    allowed = {},             -- map resourceName -> { product=..., scriptId=..., allowed=true }
    lastAuthTime = 0,
    lastUpdateTime = 0,
    lastWebhookTime = 0,
    httpTokens = {},
    serverLicenseKey = GetConvar("pixel_license_key", "") or "",
    scriptIdMap = {},         -- map product -> scriptId (stable)
    discoveredResources = {}, -- list of discovered ps_ resources at startup
    performingAuth = false,
    performingUpdate = false,
    initialized = false
}

--------------------------------------------------------------------------------
-- HELPERS: JSON safe wrappers (FiveM provides json)
--------------------------------------------------------------------------------
local function safeJsonDecode(s)
    if type(s) ~= "string" then return nil end
    local ok, res = pcall(function() return json.decode(s) end)
    if not ok then return nil end
    return res
end

local function safeJsonEncode(t)
    local ok, res = pcall(function() return json.encode(t) end)
    if not ok then return nil end
    return res
end

--------------------------------------------------------------------------------
-- HELPER: stable script-id generator
-- We create a simple stable ID based on product name & licensekey to be deterministic
--------------------------------------------------------------------------------
local function generateScriptId(productName, licenseKey)
    -- simple deterministic hash-like id: hex of sum of bytes
    local s = tostring(productName) .. ":" .. tostring(licenseKey)
    local sum = 0
    for i = 1, #s do
        sum = (sum + string.byte(s, i) * i) % 2^31
    end
    -- format as hex-like short id
    local id = string.format("psid_%X", sum)
    return id
end

--------------------------------------------------------------------------------
-- COLOR PRINTING (FiveM-style colors)
-- Use ^1..^3 codes for console colorization; keep messages concise to avoid spam
--------------------------------------------------------------------------------
local function colorPrefix()
    return ("^3[PixelService:%s]^0 "):format(CONSTANS.RESOURCE_NAME)
end

local function logInfo(msg)
    if not CONSTANS.VERBOSE then
        print(colorPrefix() .. "^2" .. tostring(msg) .. "^0")
    else
        print(colorPrefix() .. "^2" .. tostring(msg) .. "^0")
    end
end

local function logWarn(msg)
    print(colorPrefix() .. "^3" .. tostring(msg) .. "^0")
end

local function logError(msg)
    print(colorPrefix() .. "^1" .. tostring(msg) .. "^0")
end

--------------------------------------------------------------------------------
-- DISCORD WEBHOOK: compact embed sender (best-effort)
-- We call PerformHttpRequest; in some environments InternalEx is available but we use PerformHttpRequest fallback
--------------------------------------------------------------------------------
local function sendDiscord(title, description, color, fields)
    if not CONSTANS.DISCORD_WEBHOOK or CONSTANS.DISCORD_WEBHOOK == "" then
        logWarn("Discord webhook nicht konfiguriert; skip sendDiscord")
        return false
    end

    local embed = {
        {
            ["title"] = ("PixelService — %s"):format(title or "Log"),
            ["description"] = description or "",
            ["color"] = color or 3447003,
            ["footer"] = { ["text"] = ("Resource: %s"):format(CONSTANS.RESOURCE_NAME) },
            ["timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }
    }

    if type(fields) == "table" then
        embed[1]["fields"] = fields
    end

    local payload = {
        username = CONSTANS.LOG_USERNAME,
        embeds = embed
    }

    local ok, err = pcall(function()
        PerformHttpRequest(CONSTANS.DISCORD_WEBHOOK, function(status, text, headers)
            state.lastWebhookTime = os.time()
            -- discard text for privacy; only log non-2xx statuses
            if status and status ~= 204 and status ~= 200 and status ~= 201 then
                logWarn(("Webhook returned status %s"):format(tostring(status)))
            end
        end, "POST", json.encode(payload), { ["Content-Type"] = "application/json" })
    end)

    if not ok then
        logError("Fehler beim Senden an Discord: " .. tostring(err))
        return false
    end

    return true
end

--------------------------------------------------------------------------------
-- HTTP helper (simple GET wrapper) - uses PerformHttpRequest directly
--------------------------------------------------------------------------------
local function httpGet(url, cb)
    if type(url) ~= "string" or url == "" then
        cb(0, nil, "invalid-url")
        return
    end
    local ok, err = pcall(function()
        PerformHttpRequest(url, function(status, text, headers)
            -- call callback in protected mode
            local s, e = pcall(function() cb(status, text, headers) end)
            if not s then
                logError("httpGet callback error: " .. tostring(e))
            end
        end, "GET", "", { ["User-Agent"] = "PixelService-Loader/" .. tostring(CONSTANS.REQUIRED_AUTH_VERSION) })
    end)
    if not ok then
        cb(0, nil, err)
    end
end

--------------------------------------------------------------------------------
-- AUTH: parse auth.json and set allowed mapping
-- - Support global blacklisted_servers (array)
-- - Support per-server entry: allowed (array), expires (YYYY-MM-DD), blacklisted (bool)
-- - Map each product to a resource name: ps_<lower(product)> automatically
-- - Assign stable script ID via generateScriptId
--------------------------------------------------------------------------------
local function applyAuthTable(authTable)
    if type(authTable) ~= "table" then
        logError("applyAuthTable: auth.json invalid type")
        return false, "invalid-json"
    end

    -- Save auth
    state.auth = authTable

    -- basic schema checks
    if type(authTable.servers) ~= "table" then
        logError("applyAuthTable: auth.json.servers missing or invalid")
        return false, "no-servers"
    end

    local licenseKey = state.serverLicenseKey or ""
    if licenseKey == "" then
        logError("applyAuthTable: server license key is not set. Set 'setr pixel_license_key \"...\"' in server.cfg")
        sendDiscord("❌ Loader Fehler", "Kein License-Key gesetzt in server.cfg (pixel_license_key).", 16711680)
        return false, "no-license-key"
    end

    -- Check global blacklisted servers array
    if type(authTable.blacklisted_servers) == "table" then
        for _, blk in ipairs(authTable.blacklisted_servers) do
            if tostring(blk) == tostring(licenseKey) then
                logError("applyAuthTable: this license key is globally blacklisted: " .. tostring(licenseKey))
                sendDiscord("🔒 Blacklisted Server", "Lizenz ist global geblacklistet: " .. tostring(licenseKey), 16711680)
                return false, "globally-blacklisted"
            end
        end
    end

    local serverEntry = authTable.servers[licenseKey]
    if not serverEntry then
        logError("applyAuthTable: license key not found in auth.json.servers: " .. tostring(licenseKey))
        sendDiscord("❌ Lizenz ungültig", "License key nicht gefunden: " .. tostring(licenseKey), 16711680)
        return false, "license-not-found"
    end

    -- Check per-license blacklist flag
    if serverEntry.blacklisted == true then
        logError("applyAuthTable: license key explicitly blacklisted: " .. tostring(licenseKey))
        sendDiscord("🔒 Server geblacklistet", "License " .. tostring(licenseKey) .. " ist geblacklistet.", 16711680)
        return false, "license-blacklisted"
    end

    -- Expiry check if present (YYYY-MM-DD)
    if serverEntry.expires and type(serverEntry.expires) == "string" then
        local y, m, d = serverEntry.expires:match("(%d+)%-(%d+)%-(%d+)")
        if y and m and d then
            local expiry = os.time({ year = tonumber(y), month = tonumber(m), day = tonumber(d), hour = 0 })
            if os.time() > expiry then
                logError("applyAuthTable: license expired: " .. tostring(licenseKey))
                sendDiscord("❌ Lizenz abgelaufen", "License expired: " .. tostring(licenseKey), 16711680)
                return false, "expired"
            end
        end
    end

    -- Version check - warn if mismatch
    if authTable.version and authTable.version ~= CONSTANS.REQUIRED_AUTH_VERSION then
        logWarn(("auth.json version mismatch: %s != %s"):format(tostring(authTable.version), CONSTANS.REQUIRED_AUTH_VERSION))
        sendDiscord("⚠️ Auth Version Mismatch", ("auth.json version mismatch: %s != %s"):format(tostring(authTable.version), CONSTANS.REQUIRED_AUTH_VERSION), 16753920)
        -- not fatal
    end

    -- Fill allowed mapping
    state.allowed = {}
    state.scriptIdMap = {}

    if type(serverEntry.allowed) == "table" then
        for _, product in ipairs(serverEntry.allowed) do
            if type(product) == "string" then
                local productNormalized = product:gsub("%s+", "") -- remove whitespace
                local resourceName = ("ps_%s"):format(string.lower(productNormalized))
                local scriptId = generateScriptId(productNormalized, licenseKey)
                state.allowed[resourceName] = { product = productNormalized, scriptId = scriptId, allowed = true }
                state.scriptIdMap[productNormalized] = scriptId
            end
        end
    end

    -- Always allow the loader resource itself
    state.allowed[CONSTANS.RESOURCE_NAME] = { product = "loader", scriptId = generateScriptId("loader", licenseKey), allowed = true }

    -- Prepare server info and send to webhook if configured
    if CONSTANS.REPORT_ON_START then
        local serverName = GetConvar("sv_hostname", "unknown") or "unknown"
        -- Build a small allowed list for embed
        local allowedList = {}
        for rname, info in pairs(state.allowed) do
            -- skip loader resource from public list if you like, but include in fields maybe
            if rname ~= CONSTANS.RESOURCE_NAME then
                table.insert(allowedList, tostring(info.product))
            end
        end

        local fields = {
            { name = "License", value = tostring(licenseKey), inline = true },
            { name = "Server Name", value = tostring(serverName), inline = true },
            { name = "Allowed Products", value = (#allowedList > 0) and table.concat(allowedList, ", ") or "keine", inline = false },
            { name = "Auth Version", value = tostring(authTable.version or "n/a"), inline = true }
        }

        sendDiscord("🔌 Loader gestartet", ("Loader gestartet auf Server: %s"):format(serverName), 3066993, fields)
    end

    logInfo(("Auth angewendet: License=%s; erlaubte Ressourcen=%d"):format(tostring(state.serverLicenseKey), (function() local c=0 for _ in pairs(state.allowed) do c=c+1 end; return c end)()))

    return true
end

--------------------------------------------------------------------------------
-- FETCH AUTH with retries
--------------------------------------------------------------------------------
local function fetchAuth()
    if state.performingAuth then return end
    state.performingAuth = true
    local attempts = 0

    local function attempt()
        attempts = attempts + 1
        httpGet(CONSTANS.AUTH_URL, function(status, body, headers)
            if status ~= 200 or not body then
                logWarn(("fetchAuth: failed status=%s attempt=%d"):format(tostring(status), attempts))
                if attempts < CONSTANS.MAX_HTTP_RETRIES then
                    SetTimeout(1500, attempt)
                else
                    logError("fetchAuth: auth.json konnte nicht geladen werden nach retries")
                    sendDiscord("❌ Auth Fetch Failed", "auth.json konnte nicht geladen werden (status " .. tostring(status) .. ")", 16711680)
                    state.performingAuth = false
                end
                return
            end

            local parsed = safeJsonDecode(body)
            if not parsed then
                logError("fetchAuth: auth.json parse error")
                sendDiscord("❌ Auth JSON Invalid", "auth.json ist kein gültiges JSON", 16711680)
                state.performingAuth = false
                return
            end

            local ok, reason = applyAuthTable(parsed)
            if ok then
                state.lastAuthTime = os.time()
            else
                logError("fetchAuth: applyAuthTable failed: " .. tostring(reason))
            end
            state.performingAuth = false
        end)
    end

    attempt()
end

--------------------------------------------------------------------------------
-- FETCH UPDATE (loader.lua) -> compare and save if different
--------------------------------------------------------------------------------
local function fetchUpdate()
    if state.performingUpdate then return end
    state.performingUpdate = true
    httpGet(CONSTANS.UPDATE_URL, function(status, body, headers)
        if status ~= 200 or not body then
            logWarn(("fetchUpdate: failed status=%s"):format(tostring(status)))
            state.performingUpdate = false
            return
        end

        -- read current code
        local currentCode = ""
        if LoadResourceFile then
            currentCode = LoadResourceFile(GetCurrentResourceName(), "loader.lua") or ""
        end

        if currentCode ~= body then
            logInfo("fetchUpdate: neue loader.lua Version erkannt; speichern und Neustart")
            local ok, err = pcall(function() SaveResourceFile(GetCurrentResourceName(), "loader.lua", body, -1) end)
            if ok then
                sendDiscord("✅ Loader Update", "Neue loader.lua gespeichert; Neustart wird ausgeführt.", 3066993)
                -- try graceful exit; if not allowed, hang to stop resource
                CreateThread(function()
                    Wait(250)
                    if os and os.exit then pcall(os.exit, 0) end
                    while true do Wait(1000) end
                end)
            else
                logError("fetchUpdate: SaveResourceFile failed: " .. tostring(err))
                sendDiscord("❌ Update Save Error", tostring(err), 16711680)
            end
        else
            logInfo("fetchUpdate: loader aktuell; kein Update erforderlich")
        end

        state.lastUpdateTime = os.time()
        state.performingUpdate = false
    end)
end

--------------------------------------------------------------------------------
-- EXPORTS
-- 1) PixelService_IsAllowed(resourceName) -> bool
-- 2) PixelService_SendWebhook(resourceName, title, message, color, fields) -> bool
-- 3) PixelService_GetInfo() -> returns table with auth/allowed metadata for admin queries
--------------------------------------------------------------------------------
exports("PixelService_IsAllowed", function(resourceName)
    resourceName = resourceName or GetCurrentResourceName()
    if not resourceName then return false end
    -- enforce ps_ prefix unless ALLOW_NONPS_PREFIX = true
    if string.sub(resourceName,1,3) ~= "ps_" and not CONSTANS.ALLOW_NONPS_PREFIX then
        return false
    end
    local info = state.allowed[resourceName]
    if info and info.allowed then return true end
    return false
end)

exports("PixelService_SendWebhook", function(resourceName, title, message, color, fields)
    resourceName = resourceName or GetCurrentResourceName() or "unknown"
    -- only allow if resource is allowed
    if not exports[CONSTANS.RESOURCE_NAME].PixelService_IsAllowed then
        -- fallback safe check
        local ok, allowed = pcall(function() return state.allowed[resourceName] ~= nil end)
        if not ok or not allowed then return false end
    end

    local ok, res = pcall(function()
        local serverName = GetConvar("sv_hostname", "unknown") or "unknown"
        local f = fields or {}
        table.insert(f, { name = "Resource", value = tostring(resourceName), inline = true })
        table.insert(f, { name = "Server", value = serverName, inline = true })
        return sendDiscord(title or "Resource Event", message or "", color or 3447003, f)
    end)

    if not ok then
        logError("PixelService_SendWebhook error: " .. tostring(res))
        return false
    end
    return res
end)

exports("PixelService_GetInfo", function()
    -- Return a shallow copy with safe info
    local copy = {
        resource = CONSTANS.RESOURCE_NAME,
        license = state.serverLicenseKey,
        allowed = {},
        auth_version = (state.auth and state.auth.version) or nil,
        lastAuthTime = state.lastAuthTime,
        lastUpdateTime = state.lastUpdateTime
    }
    for r, info in pairs(state.allowed) do
        copy.allowed[r] = { product = info.product, scriptId = info.scriptId }
    end
    return copy
end)

--------------------------------------------------------------------------------
-- RESOURCE AUTO-SCAN: find ps_ resources on server and optionally notify webhook
-- We try to be robust: GetNumResources and GetResourceByFindIndex may not be present in all envs
--------------------------------------------------------------------------------
local function scanResourcesAndNotify()
    local found = {}
    if type(GetNumResources) == "function" and type(GetResourceByFindIndex) == "function" then
        local total = GetNumResources()
        for i = 0, total - 1 do
            local name = GetResourceByFindIndex(i)
            if name and type(name) == "string" and string.sub(name,1,3) == "ps_" then
                if state.allowed[name] then
                    table.insert(found, name)
                end
            end
        end
    else
        -- fallback: try known resources? can't enumerate
    end

    if #found > 0 then
        local productList = {}
        for _, rname in ipairs(found) do
            table.insert(productList, tostring(state.allowed[rname].product or rname))
        end
        sendDiscord("✅ PS Resources aktiv", "Erkannte und erlaubte PS-Resources: " .. table.concat(productList, ", "), 3066993)
    end
end

--------------------------------------------------------------------------------
-- Example snippet: What to paste at the top of each ps_* resource server/main.lua
-- We also print this snippet to console at loader start (so you can copy)
--------------------------------------------------------------------------------
local resourceSnippet = [[
-- PixelService Resource Start-Check (paste into server/main.lua)
Citizen.CreateThread(function()
    Wait(700) -- small delay to allow loader to initialize (increase if needed)
    local resourceName = GetCurrentResourceName()
    local loaderResource = "ps_loaderv2" -- change if your loader resource folder has a different name
    -- Try to call export for double-security (pcall to avoid crashing if loader not ready)
    local ok, allowed = pcall(function() return exports[loaderResource].PixelService_IsAllowed(resourceName) end)
    if not ok then
        print(string.format("[script:%s] [%s] > Lizenzprüfung fehlgeschlagen (Loader nicht erreichbar). Stoppe Resource.", resourceName, resourceName))
        StopResource(resourceName)
        return
    end
    if not allowed then
        print(string.format("[script:%s] [%s] > Resource nicht lizenziert. Stoppe Resource.", resourceName, resourceName))
        StopResource(resourceName)
        return
    end
    -- Optional: notify loader webhook about successful start
    pcall(function() exports[loaderResource].PixelService_SendWebhook(resourceName, "Script gestartet", "Script erfolgreich gestartet.", 3447003) end)
    print(string.format("[script:%s] [%s] > Heartbeat zu Backend gesendet..", resourceName, resourceName))
    Wait(200)
    print(string.format("[script:%s] [%s] > Prüfe ob der Server eine Blacklist hat..", resourceName, resourceName))
    Wait(200)
    print(string.format("[script:%s] [%s] > Script erfolgreich gestartet..", resourceName, resourceName))
end)
]]

--------------------------------------------------------------------------------
-- PRINT snippet once at startup to console for developers (keeps minimal spam)
--------------------------------------------------------------------------------
CreateThread(function()
    Wait(1200)
    logInfo("PixelService Loader bereit. Kopiere das folgende Snippet in jede ps_* Resource (server/main.lua):")
    -- print snippet lines with minimal flood
    for line in resourceSnippet:gmatch("([^\n]*)\n?") do
        if line ~= "" then
            print(line)
            Wait(8) -- small throttle to avoid console spam
        end
    end
end)

--------------------------------------------------------------------------------
-- Periodic main loop: auth refresh + update checks (reduced frequency)
--------------------------------------------------------------------------------
CreateThread(function()
    -- initial delay
    Wait(800)
    logInfo("PixelService Loader initialisiere...")

    -- basic env checks
    if not CONSTANS.AUTH_URL or CONSTANS.AUTH_URL == "" then
        logWarn("AUTH_URL nicht gesetzt - auth checks funktionieren nicht")
    end

    if state.serverLicenseKey == "" then
        logWarn("Server-Lizenz-Key nicht gesetzt. Setze in server.cfg: setr pixel_license_key \"srv-ABC123\"")
    end

    -- initial actions
    Wait(CONSTANS.AUTH_CHECK_DELAY_MS)
    fetchAuth()
    Wait(CONSTANS.UPDATE_CHECK_DELAY_MS)
    fetchUpdate()

    -- scan for resources & notify
    Wait(1200)
    scanResourcesAndNotify()

    -- set initialized flag
    state.initialized = true

    -- periodic loop
    while true do
        -- perform auth refresh if older than interval
        if (os.time() - (state.lastAuthTime or 0)) > math.floor(CONSTANS.CHECK_INTERVAL_MS / 1000) then
            fetchAuth()
        end

        -- perform update check if older than interval
        if (os.time() - (state.lastUpdateTime or 0)) > math.floor(CONSTANS.CHECK_INTERVAL_MS / 1000) then
            fetchUpdate()
        end

        Wait(CONSTANS.CHECK_INTERVAL_MS)
    end
end)

--------------------------------------------------------------------------------
-- Administrative commands (console)
-- - pixelstatus : prints current auth + allowed list
-- - pixelupdate : force update check
-- - pixelauth   : force auth refresh
--------------------------------------------------------------------------------
RegisterCommand("pixelstatus", function(src, args, raw)
    local info = exports[CONSTANS.RESOURCE_NAME].PixelService_GetInfo()
    local msg = ("PixelService Status | License=%s | AllowedCount=%d | AuthVer=%s"):format(
        tostring(info.license or "n/a"),
        (function() local c=0; for _ in pairs(info.allowed or {}) do c=c+1 end; return c end)(),
        tostring(info.auth_version or "n/a")
    )
    if src == 0 then
        logInfo(msg)
    else
        TriggerClientEvent("chat:addMessage", src, { args = { "PixelService", msg } })
    end
end, true)

RegisterCommand("pixelupdate", function(src, args, raw)
    local who = (src == 0) and "console" or ("player:" .. tostring(src))
    logInfo("Manual update requested by " .. who)
    sendDiscord("🛠️ Manual Update", "Manual update requested by " .. who, 3447003)
    CreateThread(function() fetchUpdate() end)
end, true)

RegisterCommand("pixelauth", function(src, args, raw)
    local who = (src == 0) and "console" or ("player:" .. tostring(src))
    logInfo("Manual auth refresh requested by " .. who)
    sendDiscord("🛠️ Manual Auth", "Manual auth refresh requested by " .. who, 3447003)
    CreateThread(function() fetchAuth() end)
end, true)

--------------------------------------------------------------------------------
-- Clean exit guard (optional) - ensure loader resource stays alive unless updated/crashed
--------------------------------------------------------------------------------
AddEventHandler("onResourceStop", function(resourceName)
    if resourceName == CONSTANS.RESOURCE_NAME then
        logWarn("Loader wird gestoppt. Stoppe erlaubte ps_* Ressourcen die evtl. gestartet wurden (nur cleanup).")
        for rname, info in pairs(state.allowed) do
            if rname ~= CONSTANS.RESOURCE_NAME and state.allowed[rname] and state.allowed[rname].allowed then
                -- do not force stop other resources here automatically in production
            end
        end
    end
end)

--------------------------------------------------------------------------------
-- End of file - PixelService loader (v0.0.3)
--------------------------------------------------------------------------------
