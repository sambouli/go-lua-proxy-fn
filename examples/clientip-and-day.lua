-- Client IP + day-of-week demo rule.
-- Run the proxy with: LUA_SCRIPTS=./examples/clientip-and-day.lua

local ip = proxy.clientIP()
proxy.setResponseHeader("X-Client-IP", ip)
proxy.setResponseHeader("X-Day-Of-Week", os.date("!%A"))
proxy.setRequestHeader("X-From-Lua", "lua-rule-ran")
proxy.log("serving " .. proxy.request.path .. " for " .. ip)
