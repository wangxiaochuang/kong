local cjson = require "cjson.safe"
local utils = require "kong.tools.utils"
local knode = (kong and kong.node) and kong.node or
              require "kong.pdk.node".new()



local _buffer = {}
local _buffer_immutable_idx

local report_counter = nil

do
  local meta = require("kong.meta")
  local system_infos = utils.get_system_infos()
  system_infos.hostname = system_infos.hostname or knode.get_hostname()
  _buffer[#_buffer + 1] = "<14>version=" .. meta._VERSION

  for k, v in pairs(system_infos) do
    _buffer[#_buffer + 1] = k .. "=" .. v
  end

  _buffer_immutable_idx = #_buffer
end

local function serialize_report_value(v)
  if type(v) == "function" then
    v = v()
  end

  if type(v) == "table" then
    local json, err = cjson.encode(v)
    if err then
      log(WARN, "could not JSON encode given table entity: ", err)
    end

    v = json
  end

  return v ~= nil and tostring(v) or nil
end

local function add_immutable_value(k, v)
  v = serialize_report_value(v)
  if v ~= nil then
    _buffer_immutable_idx = _buffer_immutable_idx + 1
    _buffer[_buffer_immutable_idx] = k .. "=" .. v
  end
end


return {
  add_immutable_value = add_immutable_value,
}
