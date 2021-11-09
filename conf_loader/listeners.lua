local pl_stringx = require "pl.stringx"
local utils = require "kong.tools.utils"
local log = require("kong.cmd.utils.log")


local concat = table.concat


local listeners = {}


local subsystem_flags = {
  http = { "ssl", "http2", "proxy_protocol", "deferred", "bind", "reuseport",
           "backlog=%d+" },
  stream = { "udp", "ssl", "proxy_protocol", "bind", "reuseport", "backlog=%d+" },
}

local _nop_tostring_mt = {
  __tostring = function() return "" end,
}

local function parse_option_flags(value, flags)
  assert(type(value) == "string")
  value = " " .. value .. " "

  local sanitized = ""
  local result = {}

  for _, flag in ipairs(flags) do
    local count
    local patt = "%s(" .. flag .. ")%s"

    local found = value:match(patt)
    if found then
      flag = found
    end

    value, count = value:gsub(patt, " ")

    if count > 0 then
      result[flag] = true
      sanitized = sanitized .. " " .. flag

    else
      result[flag] = false
    end
  end

  return pl_stringx.strip(value), result, pl_stringx.strip(sanitized)
end

local function parse_listeners(values, flags)
  assert(type(flags) == "table")
  local list = {}
  local usage = "must be of form: [off] | <ip>:<port> [" ..
                concat(flags, "] [") .. "], [... next entry ...]"

  if #values == 0 then
    return nil, usage
  end

  if pl_stringx.strip(values[1]) == "off" then
    return list
  end

  for _, entry in ipairs(values) do
    local remainder, listener, cleaned_flags = parse_option_flags(entry, flags)

    local ip

    if utils.hostname_type(remainder) == "name" then
      ip = {}
      ip.host, ip.port = remainder:match("(.+):([%d]+)$")
    else
      ip = utils.normalize_ip(remainder)
      if ip and ip.type == "ipv6" then
        ip.host = "[" .. ip.host .. "]"
      end
    end

    if not ip or not ip.port then
      return nil, usage
    end

    listener.ip = ip.host
    listener.port = ip.port
    listener.listener = ip.host .. ":" .. ip.port ..
                        (#cleaned_flags == 0 and "" or " " .. cleaned_flags)
    
    table.insert(list, listener)
  end

  return list
end

function listeners.parse(conf, listener_configs)
  for _, l in ipairs(listener_configs) do
    local plural = l.name .. "ers"
    local flags = l.flags or subsystem_flags[l.subsystem]
    local err
    conf[plural], err = parse_listeners(conf[l.name], flags)
    if err then
      return nil, l.name .. " " .. err
    end
    setmetatable(conf[plural], _nop_tostring_mt)

    if l.ssl_flag then
      conf[l.ssl_flag] = false
      for _, listener in ipairs(conf[plural]) do
        if listener.ssl == true then
          conf[l.ssl_flag] = true
          break
        end
      end
    end
  end

  return true
end

return listeners
