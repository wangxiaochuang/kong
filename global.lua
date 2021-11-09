local meta = require "kong.meta"
local PDK = require "kong.pdk"
local phase_checker = require "kong.pdk.private.phases"
--local kong_cache = require "kong.cache"
--local kong_cluster_events = require "kong.cluster_events"
local kong_constants = require "kong.constants"

local type = type
local setmetatable = setmetatable


local KONG_VERSION = tostring(meta._VERSION)
local KONG_VERSION_NUM = tonumber(string.format("%d%.2d%.2d",
                                  meta._VERSION_TABLE.major * 100,
                                  meta._VERSION_TABLE.minor * 10,
                                  meta._VERSION_TABLE.patch))


local LOCK_OPTS = {
  exptime = 10,
  timeout = 5,
}

local _GLOBAL = {
  phases = phase_checker.phases,
}

function _GLOBAL.new()
  return {
    version = KONG_VERSION,
    version_num = KONG_VERSION_NUM,

    pdk_major_version = nil,
    pdk_version = nil,

    configuration = nil,
  }
end

function _GLOBAL.set_named_ctx(self, name, key)
  error("in set_named_ctx")
end

function _GLOBAL.del_named_ctx(self, name)
  error("in del_named_ctx")
end

function _GLOBAL.set_phase(self, phase)
  error("in set_phase")
end

function _GLOBAL.get_phase(self)
  if not self then
    error("arg #1 cannot be nil", 2)
  end

  local kctx = self.ctx
  if not kctx then
    error("ctx SDK module not initialized", 2)
  end

  return kctx.core.phase
end

do
  local log_facilities = setmetatable({}, { __index = "k" })

  function _GLOBAL.set_namespaced_log(self, namespace)
  end

  function _GLOBAL.reset_log(self)
    error("in reset_log")
  end
end

function _GLOBAL.init_pdk(self, kong_config, pdk_major_version)
  if not self then
    error("arg #1 cannot be nil", 2)
  end

  PDK.new(kong_config, pdk_major_version, self)
end

function _GLOBAL.init_worker_events()
  error("in init_worker_events")
end

function _GLOBAL.init_cluster_events(kong_config, db)
  error("in init_cluster_events")
end

function _GLOBAL.init_cache(kong_config, cluster_events, worker_events)
  error("in init_cache")
end

function _GLOBAL.init_core_cache(kong_config, cluster_events, worker_events)
  error("in init_core_cache")
end

return _GLOBAL
