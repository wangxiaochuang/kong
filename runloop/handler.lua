local ck           = require "resty.cookie"
local meta         = require "kong.meta"
local utils        = require "kong.tools.utils"
local Router       = require "kong.router"
local balancer     = require "kong.runloop.balancer"
local reports      = require "kong.reports"
local constants    = require "kong.constants"
local singletons   = require "kong.singletons"
local certificate  = require "kong.runloop.certificate"
local concurrency  = require "kong.concurrency"
local declarative  = require "kong.db.declarative"
local PluginsIterator = require "kong.runloop.plugins_iterator"

local kong         = kong
local type         = type
local ipairs       = ipairs
local tostring     = tostring
local tonumber     = tonumber
local setmetatable = setmetatable
local sub          = string.sub
local byte         = string.byte
local gsub         = string.gsub
local find         = string.find
local lower        = string.lower
local fmt          = string.format
local ngx          = ngx
local var          = ngx.var
local log          = ngx.log
local exit         = ngx.exit
local null         = ngx.null
local header       = ngx.header
local timer_at     = ngx.timer.at
local timer_every  = ngx.timer.every
local subsystem    = ngx.config.subsystem
local clear_header = ngx.req.clear_header
local unpack       = unpack
local escape       = require("kong.tools.uri").escape


local NOOP = function() end


local ERR   = ngx.ERR
local CRIT  = ngx.CRIT
local NOTICE = ngx.NOTICE
local WARN  = ngx.WARN
local DEBUG = ngx.DEBUG
local COMMA = byte(",")
local SPACE = byte(" ")
local ARRAY_MT = require("cjson.safe").array_mt


local HOST_PORTS = {}


local SUBSYSTEMS = constants.PROTOCOLS_WITH_SUBSYSTEM
local EMPTY_T = {}
local TTL_ZERO = { ttl = 0 }


local ROUTER_SYNC_OPTS
local PLUGINS_ITERATOR_SYNC_OPTS
local FLIP_CONFIG_OPTS
local GLOBAL_QUERY_OPTS = { workspace = null, show_ws_id = true }


local get_plugins_iterator, get_updated_plugins_iterator
local build_plugins_iterator, update_plugins_iterator
local rebuild_plugins_iterator

local get_updated_router, build_router, update_router
local server_header = meta._SERVER_TOKENS
local rebuild_router

-- for tests
local _set_update_plugins_iterator
local _set_update_router
local _set_build_router
local _set_router
local _set_router_version
local _register_balancer_events

local update_lua_mem
do
  local pid = ngx.worker.pid
  local kong_shm = ngx.shared.kong

  local LUA_MEM_SAMPLE_RATE = 10 -- seconds
  local last = ngx.time()

  local collectgarbage = collectgarbage

  update_lua_mem = function(force)
    local time = ngx.time()

    if force or time - last >= LUA_MEM_SAMPLE_RATE then
      local count = collectgarbage("count")

      local ok, err = kong_shm:safe_set("kong:mem:" .. pid(), count)
      if not ok then
        log(ERR, "could not record Lua VM allocated memory: ", err)
      end

      last = ngx.time()
    end
  end
end

local function csv_iterator(s, b)
  if b == -1 then
    return
  end

  local e = find(s, ",", b, true)
  local v
  local l
  if e then
    if e == b then
      return csv_iterator(s, b + 1) -- empty string
    end
    v = sub(s, b, e - 1)
    l = e - b
    b = e + 1

  else
    if b > 1 then
      v = sub(s, b)
    else
      v = s
    end

    l = #v
    b = -1 -- end iteration
  end

  if l == 1 and (byte(v) == SPACE or byte(v) == COMMA) then
    return csv_iterator(s, b)
  end

  if byte(v, 1, 1) == SPACE then
    v = gsub(v, "^%s+", "")
  end

  if byte(v, -1) == SPACE then
    v = gsub(v, "%s+$", "")
  end

  if v == "" then
    return csv_iterator(s, b)
  end

  return b, v
end


local function csv(s)
  if type(s) ~= "string" or s == "" then
    return csv_iterator, s, -1
  end

  s = lower(s)
  if s == "close" or s == "upgrade" or s == "keep-alive" then
    return csv_iterator, s, -1
  end

  return csv_iterator, s, 1
end

local function register_balancer_events(core_cache, worker_events, cluster_events)
  error("in register_balancer_events")
end

local function register_events()
  error("in register_events")
end

local function rebuild(name, callback, version, opts)
  error("in rebuild")
end

do
  local plugins_iterator

  build_plugins_iterator = function(version)
    local new_iterator, err = PluginsIterator.new(version)
    if not new_iterator then
      return nil, err
    end
    plugins_iterator = new_iterator
    return true
  end

  update_plugins_iterator = function()
    local version, err = kong.core_cache:get("plugins_iterator:version", TTL_ZERO,
                                             utils.uuid)
    if err then
      return nil, "failed to retrieve plugins iterator version: " .. err
    end

    if plugins_iterator and plugins_iterator.version == version then
      return true
    end

    local ok, err = build_plugins_iterator(version)
    if not ok then
      return nil, --[[ 'err' fully formatted ]] err
    end

    return true
  end

  rebuild_plugins_iterator = function(timeout)
    local plugins_iterator_version = plugins_iterator and plugins_iterator.version
    return rebuild("plugins_iterator", update_plugins_iterator,
                   plugins_iterator_version, timeout)
  end

  get_updated_plugins_iterator = function()
    if kong.db.strategy ~= "off" and kong.configuration.worker_consistency == "strict" then
      error("in get_updated_plugins_iterator")
    end

    return plugins_iterator
  end

  get_plugins_iterator = function()
    return plugins_iterator
  end

  -- for tests only
  _set_update_plugins_iterator = function(f)
    update_plugins_iterator = f
  end
end

do
  local router
  local router_version

  -- Given a protocol, return the subsystem that handles it
  local function should_process_route(route)
    for _, protocol in ipairs(route.protocols) do
      if SUBSYSTEMS[protocol] == subsystem then
        return true
      end
    end

    return false
  end

  local function load_service_from_db(service_pk)
    local service, err = kong.db.services:select(service_pk, GLOBAL_QUERY_OPTS)
    if service == nil then
      -- the third value means "do not cache"
      return nil, err, -1
    end
    return service
  end

  local function build_services_init_cache(db)
    local services_init_cache = {}

    for service, err in db.services:each(nil, GLOBAL_QUERY_OPTS) do
      if err then
        return nil, err
      end

      services_init_cache[service.id] = service
    end

    return services_init_cache
  end

  local function get_service_for_route(db, route, services_init_cache)
    error("in get_service_for_route")
  end

  local function get_router_version()
    return kong.core_cache:get("router:version", TTL_ZERO, utils.uuid)
  end

  build_router = function(version)
    error("in build_router")
  end

  update_router = function()
    error("in update_router")
  end

  rebuild_router = function(opts)
    return rebuild("router", update_router, router_version, opts)
  end

  get_updated_router = function()
    if kong.db.strategy ~= "off" and kong.configuration.worker_consistency == "strict" then
      error("in get_updated_router")
    end
    return router
  end
end

local balancer_prepare
do
  local get_certificate = certificate.get_certificate
  local get_ca_certificate_store = certificate.get_ca_certificate_store
  local subsystem = ngx.config.subsystem

  function balancer_prepare(ctx, scheme, host_type, host, port,
                            service, route)
    error("in balancer_prepare")
  end
end

local function balancer_execute(ctx)
  error("in balancer_execute")
end

local function set_init_versions_in_cache()
  if kong.configuration.role ~= "control_pane" then
    local ok, err = kong.core_cache:safe_set("router:version", "init")
    if not ok then
      return nil, "failed to set router version in cache: " .. tostring(err)
    end
  end

  local ok, err = kong.core_cache:safe_set("plugins_iterator:version", "init")
  if not ok then
    return nil, "failed to set plugins iterator version in cache: " ..
                tostring(err)
  end

  return true
end

return {
  build_router = build_router,

  build_plugins_iterator = build_plugins_iterator,
  update_plugins_iterator = update_plugins_iterator,
  get_plugins_iterator = get_plugins_iterator,
  get_updated_plugins_iterator = get_updated_plugins_iterator,
  set_init_versions_in_cache = set_init_versions_in_cache,

  -- exposed only for tests
  _set_router = _set_router,
  _set_update_router = _set_update_router,
  _set_build_router = _set_build_router,
  _set_router_version = _set_router_version,
  _set_update_plugins_iterator = _set_update_plugins_iterator,
  _get_updated_router = get_updated_router,
  _update_lua_mem = update_lua_mem,
  _register_balancer_events = _register_balancer_events,

  init_worker = {
  },
  certificate = {},
  preread = {},
  rewrite = {},
  access = {},
  response = {
  },
  header_filter = {},
  log = {},
}
