pcall(require, "luarocks.loader")
local log = require("kong.cmd.utils.log")


assert(package.loaded["resty.core"], "lua-resty-core must be loaded; make " ..
                                     "sure 'lua_load_resty_core' is not "..
                                     "disabled.")


local constants = require "kong.constants"
do
  for _, dict in ipairs(constants.DICTS) do
    if not ngx.shared[dict] then
      return error("missing shared dict '" .. dict .. "' in Nginx "          ..
                   "configuration, are you using a custom template? "        ..
                   "Make sure the 'lua_shared_dict " .. dict .. " [SIZE];' " ..
                   "directive is defined.")
    end
  end

  if os.getenv("KONG_NGINX_CONF_CHECK") then
    return {
      init = function() end,
    }
  end
end

require("kong.globalpatches")()

local kong_global = require "kong.global"
local PHASES = kong_global.phases


_G.kong = kong_global.new()

local DB = require "kong.db"
local dns = require "kong.tools.dns"
local meta = require "kong.meta"
local lapis = require "lapis"
--local runloop = require "kong.runloop.handler"
--local stream_api = require "kong.tools.stream_api"
local singletons = require "kong.singletons"
local declarative = require "kong.db.declarative"
local ngx_balancer = require "ngx.balancer"
local kong_resty_ctx = require "kong.resty.ctx"
local certificate = require "kong.runloop.certificate"
--local concurrency = require "kong.concurrency"
--local cache_warmup = require "kong.cache.warmup"
--local balancer_execute = require("kong.runloop.balancer").execute
--local balancer_set_host_header = require("kong.runloop.balancer").set_host_header
--local kong_error_handlers = require "kong.error_handlers"
local migrations_utils = require "kong.cmd.utils.migrations"
--local plugin_servers = require "kong.runloop.plugin_servers"
local clustering

local kong             = kong
local ngx              = ngx
local now              = ngx.now
local update_time      = ngx.update_time
local var              = ngx.var
local arg              = ngx.arg
local header           = ngx.header
local ngx_log          = ngx.log
local ngx_ALERT        = ngx.ALERT
local ngx_CRIT         = ngx.CRIT
local ngx_ERR          = ngx.ERR
local ngx_WARN         = ngx.WARN
local ngx_NOTICE       = ngx.NOTICE
local ngx_INFO         = ngx.INFO
local ngx_DEBUG        = ngx.DEBUG
local subsystem        = ngx.config.subsystem
local start_time       = ngx.req.start_time
local type             = type
local error            = error
local ipairs           = ipairs
local assert           = assert
local tostring         = tostring
local coroutine        = coroutine
local get_last_failure = ngx_balancer.get_last_failure
local set_current_peer = ngx_balancer.set_current_peer
local set_timeouts     = ngx_balancer.set_timeouts
local set_more_tries   = ngx_balancer.set_more_tries
local enable_keepalive = ngx_balancer.enable_keepalive
if not enable_keepalive then
  ngx_log(ngx_WARN, "missing method 'ngx_balancer.enable_keepalive()' ",
                    "(was the dyn_upstream_keepalive patch applied?) ",
                    "set the 'nginx_upstream_keepalive' configuration ",
                    "property instead of 'upstream_keepalive_pool_size'")
end
if subsystem == "http" then
  clustering = require "kong.clustering"
end

local DECLARATIVE_LOAD_KEY = constants.DECLARATIVE_LOAD_KEY
local DECLARATIVE_HASH_KEY = constants.DECLARATIVE_HASH_KEY


local declarative_entities
local declarative_meta
local schema_state


local stash_init_worker_error
local log_init_worker_errors
do
  local init_worker_errors
  local init_worker_errors_str
  local ctx_k = {}

  stash_init_worker_error = function(err)
    if err == nil then
      return
    end

    err = tostring(err)

    if not init_worker_errors then
      init_worker_errors = {}
    end

    table.insert(init_worker_errors, err)
    init_worker_errors_str = table.concat(init_worker_errors, ", ")

    return ngx_log(ngx_CRIT, "worker initialization error: ", err,
                             "; this node must be restarted")
  end

  log_init_worker_errors = function(ctx)
    if not init_worker_errors_str or ctx[ctx_k] then
      return
    end

    ctx[ctx_k] = true

    return ngx_log(ngx_ALERT, "unsafe request processing due to earlier ",
                              "initialization errors; this node must be ",
                              "restarted (", init_worker_errors_str, ")")
  end
end

local reset_kong_shm
do
  local DECLARATIVE_PAGE_KEY = constants.DECLARATIVE_PAGE_KEY
  local preserve_keys = {
    "kong:node_id",
    "events:requests",
    "events:requests:http",
    "events:requests:https",
    "events:requests:h2c",
    "events:requests:h2",
    "events:requests:grpc",
    "events:requests:grpcs",
    "events:requests:ws",
    "events:requests:wss",
    "events:requests:go_plugins",
    "events:streams",
    "events:streams:tcp",
    "events:streams:tls",
  }

  reset_kong_shm = function(config)
    local kong_shm = ngx.shared.kong
    local dbless = config.database == "off"

    if dbless then
      -- prevent POST /config while initializing dbless
      declarative.try_lock()
    end

    local old_page = kong_shm:get(DECLARATIVE_PAGE_KEY)
    if old_page == nil then -- fresh node, just storing the initial page
      kong_shm:set(DECLARATIVE_PAGE_KEY, 1)
      return
    end

    local preserved = {}

    local new_page = old_page
    if dbless then
      if config.declarative_config then
        new_page = old_page == 1 and 2 or 1
      else
        preserved[DECLARATIVE_LOAD_KEY] = kong_shm:get(DECLARATIVE_LOAD_KEY)
        preserved[DECLARATIVE_HASH_KEY] = kong_shm:get(DECLARATIVE_HASH_KEY)
      end
    end

    preserved[DECLARATIVE_PAGE_KEY] = new_page
    for _, key in ipairs(preserve_keys) do
      preserved[key] = kong_shm:get(key) -- ignore errors
    end

    kong_shm:flush_all()
    if dbless then
      -- reinstate the lock to hold POST /config, which was flushed with the previous `flush_all`
      declarative.try_lock()
    end
    for key, value in pairs(preserved) do
      kong_shm:set(key, value)
    end
    kong_shm:flush_expired(0)
  end
end


local function execute_plugins_iterator(plugins_iterator, phase, ctx)
  error("in execute_plugins_iterator")
end

local function execute_cache_warmup(kong_config)
  if kong_config.database == "off" then
    return true
  end
  error("in execute_cache_warmup")
end

local function get_now_ms()
  update_time()
  return now() * 1000
end

local function flush_delayed_response(ctx)
  error("in flush_delayed_response")
end

local function parse_declarative_config(kong_config)
  if kong_config.database ~= "off" then
    return {}, nil, {}
  end

  local dc = declarative.new_config(kong_config)

  -- 解析/etc/kong/kong.yaml
  if not kong_config.declarative_config then
    -- return an empty configuration,
    -- including only the default workspace
    local entities, _, _, meta = dc:parse_table({ _format_version = "2.1" })
    return entities, nil, meta
  end

  local entities, err, _, meta = dc:parse_file(kong_config.declarative_config)
  if not entities then
    return nil, "error parsing declarative config file " ..
                kong_config.declarative_config .. ":\n" .. err
  end

  return entities, nil, meta
end

local function load_declarative_config(kong_config, entities, meta)
  error("in load_declarative_config")
end

local function list_migrations(migtable)
  error("in list_migrations")
end

local Kong = {}

function Kong.init()
  local pl_path = require "pl.path"
  local conf_loader = require "kong.conf_loader"

  -- check if kong global is the correct one
  if not kong.version then
    error("configuration error: make sure your template is not setting a " ..
          "global named 'kong' (please use 'Kong' instead)")
  end

  -- retrieve kong_config
  local conf_path = pl_path.join(ngx.config.prefix(), ".kong_env")
  local config = assert(conf_loader(conf_path, nil, { from_kong_env = true }))

  reset_kong_shm(config)

  math.randomseed()

  kong_global.init_pdk(kong, config, nil)

  local db = assert(DB.new(config))
  assert(db:init_connector())

  schema_state = assert(db:schema_state())
  migrations_utils.check_state(schema_state)

  if schema_state.missing_migrations or schema_state.pending_migrations then
    error("in init")
  end

  assert(db:connect())

  singletons.dns = dns(config)
  singletons.configuration = config
  singletons.db = db

  kong.db = db
  kong.dns = singletons.dns

  if config.proxy_ssl_enabled or config.stream_ssl_enabled then
    certificate.init()
  end

  if subsystem == "http" then
    clustering.init(config)
  end

  assert(db.plugins:load_plugin_schemas(config.loaded_plugins))

  if subsystem == "stream" then
    error()
  end

  if config.database == "off" then
    local err
    declarative_entities, err, declarative_meta = parse_declarative_config(kong.configuration)
    if not declarative_entities then
      error(err)
    end
  else
    error("config.database")
  end

  db:close()
end

function Kong.init_worker()
  kong_global.set_phase(kong, PHASES.init_worker)

  math.randomseed()

  local ok, err = kong.db:init_worker()
  if not ok then
    stash_init_worker_error("failed to instantiate 'kong.db' module: " .. err)
    return
  end

  if ngx.worker.id() == 0 then
    if schema_state.missing_migrations then
      ngx_log(ngx_WARN, "missing migrations: ",
              list_migrations(schema_state.missing_migrations))
    end

    if schema_state.pending_migrations then
      ngx_log(ngx_INFO, "starting with pending migrations: ",
              list_migrations(schema_state.pending_migrations))
    end
  end

  local worker_events, err = kong_global.init_worker_events()
  if not worker_events then
    stash_init_worker_error("failed to instantiate 'kong.worker_events' " ..
                            "module: " .. err)
    return
  end
  kong.worker_events = worker_events

  local cluster_events, err = kong_global.init_cluster_events(kong.configuration, kong.db)
  if not cluster_events then
    stash_init_worker_error("failed to instantiate 'kong.cluster_events' " ..
                            "module: " .. err)
    return
  end
  kong.cluster_events = cluster_events

  local cache, err = kong_global.init_cache(kong.configuration, cluster_events, worker_events)
  if not cache then
    stash_init_worker_error("failed to instantiate 'kong.cache' module: " ..
                            err)
    return
  end
  kong.cache = cache

  local core_cache, err = kong_global.init_core_cache(kong.configuration, cluster_events, worker_events)
  if not core_cache then
    stash_init_worker_error("failed to instantiate 'kong.core_cache' module: " ..
                            err)
    return
  end
  kong.core_cache = core_cache

  ok, err = runloop.set_init_versions_in_cache()
  if not ok then
    stash_init_worker_error(err) -- 'err' fully formatted
    return
  end
end

function Kong.ssl_certificate()
error("in Kong.ssl_certificate")
end

function Kong.preread()
error("in Kong.preread")
end

function Kong.rewrite()
error("in Kong.rewrite")
end

function Kong.access()
error("in Kong.access")
end

function Kong.balancer()
error("in Kong.balancer")
end

do
  local HTTP_METHODS = {
    GET       = ngx.HTTP_GET,
    HEAD      = ngx.HTTP_HEAD,
    PUT       = ngx.HTTP_PUT,
    POST      = ngx.HTTP_POST,
    DELETE    = ngx.HTTP_DELETE,
    OPTIONS   = ngx.HTTP_OPTIONS,
    MKCOL     = ngx.HTTP_MKCOL,
    COPY      = ngx.HTTP_COPY,
    MOVE      = ngx.HTTP_MOVE,
    PROPFIND  = ngx.HTTP_PROPFIND,
    PROPPATCH = ngx.HTTP_PROPPATCH,
    LOCK      = ngx.HTTP_LOCK,
    UNLOCK    = ngx.HTTP_UNLOCK,
    PATCH     = ngx.HTTP_PATCH,
    TRACE     = ngx.HTTP_TRACE,
  }

  function Kong.response()
    error("in Kong.response")
  end
end

function Kong.header_filter()
error("in Kong.header_filter")
end

function Kong.body_filter()
error("in Kong.body_filter")
end

function Kong.log()
error("in Kong.log")
end

function Kong.handle_error()
error("in Kong.handle_error")
end

local function serve_content(module, options)
error("in serve_content")
end

function Kong.admin_content(options)
  kong.worker_events.poll()

  local ctx = ngx.ctx
  if not ctx.workspace then
    ctx.workspace = kong.default_workspace
  end

  return serve_content("kong.api", options)
end

Kong.serve_admin_api = Kong.admin_content

function Kong.admin_header_filter()
error("in Kong.admin_header_filter")
end

function Kong.status_content()
  return serve_content("kong.status")
end

Kong.status_header_filter = Kong.admin_header_filter

function Kong.serve_cluster_listener(options)
error("in Kong.serve_cluster_listener")
end

function Kong.stream_api()
error("in Kong.stream_api")
end

do
  local declarative = require("kong.db.declarative")
  local cjson = require("cjson.safe")

  function Kong.stream_config_listener()
    error("in Kong.stream_config_listener")
  end
end

return Kong
