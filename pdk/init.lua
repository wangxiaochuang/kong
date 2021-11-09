local log = require("kong.cmd.utils.log")
assert(package.loaded["resty.core"])

local MAJOR_VERSIONS = {
  [1] = {
    version = "1.4.0",
    modules = {
      "table",
      "node",
      "log",
      "ctx",
      "ip",
      "client",
      "service",
      "request",
      "service.request",
      "service.response",
      "response",
      "router",
      "nginx",
      "cluster",
    },
  },

  latest = 1,
}

if ngx.config.subsystem == 'http' then
  table.insert(MAJOR_VERSIONS[1].modules, 'client.tls')
end

local _PDK = {
  major_versions = MAJOR_VERSIONS,
}

function _PDK.new(kong_config, major_version, self)
  if kong_config then
    if type(kong_config) ~= "table" then
      error("kong_config must be a table", 2)
    end
  else
    kong_config = {}
  end

  if major_version then
    if type(major_version) ~= "number" then
      error("major_version must be a number", 2)
    end
  else
    major_version = MAJOR_VERSIONS.latest
  end

  local version_meta = MAJOR_VERSIONS[major_version]

  self = self or {}

  self.pdk_major_version = major_version
  self.pdk_version = version_meta.version

  self.configuration = setmetatable({}, {
    __index = function(_, v)
      return kong_config[v]
    end,

    __newindex = function()
      error("cannot write to configuration", 2)
    end,
  })

  for _, module_name in ipairs(version_meta.modules) do
    local parent = self
    for part in module_name:gmatch("([^.]+)%.") do
      if not parent[part] then
        parent[part] = {}
      end

      parent = parent[part]
    end

    local child = module_name:match("[^.]*$")
    if parent[child] then
      error("PDK module '" .. module_name .. "' conflicts with a key")
    end

    local mod = require("kong.pdk." .. module_name)

    parent[child] = mod.new(self)
  end

  self._log = self.log
  self.log = nil

  return setmetatable(self, {
    __index = function(t, k)
      if k == "core_log" then
        return (rawget(t, "_log"))
      end

      if k == "log" then
        if t.ctx.core and t.ctx.core.log then
          return t.ctx.core.log
        end
      end

      if k == "v" then
        return log.v
      end
    end
  })
end

return _PDK
