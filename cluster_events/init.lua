local ngx_debug = ngx.config.debug
local DEBUG     = ngx.DEBUG
local ERR       = ngx.ERR
local CRIT      = ngx.CRIT
local max       = math.max
local type      = type
local error     = error
local pcall     = pcall
local insert    = table.insert
local ngx_log   = ngx.log
local ngx_now   = ngx.now
local timer_at  = ngx.timer.at
local ngx_update_time = ngx.update_time
local knode     = (kong and kong.node) and kong.node or
                  require "kong.pdk.node".new()


local POLL_INTERVAL_LOCK_KEY = "cluster_events:poll_interval"
local POLL_RUNNING_LOCK_KEY  = "cluster_events:poll_running"
local CURRENT_AT_KEY         = "cluster_events:at"


local MIN_EVENT_TTL_IN_DB = 60 * 60 -- 1 hour
local PAGE_SIZE           = 1000


local _init
local poll_handler

local function log(lvl, ...)
  return ngx_log(lvl, "[cluster_events] ", ...)
end


local function nbf_cb_handler(premature, cb, data)
  if premature then
    return
  end

  cb(data)
end

local _M = {}
local mt = { __index = _M }

function _M.new(opts)
  if ngx.get_phase() ~= "init_worker" and ngx.get_phase() ~= "timer" then
    return error("kong.cluster_events must be created during init_worker phase")
  end

  if not ngx_debug and _init then
    return error("kong.cluster_events was already instantiated")
  end

  opts = opts or {}

  if opts.poll_interval and type(opts.poll_interval) ~= "number" then
    return error("opts.poll_interval must be a number")
  end

  if opts.poll_offset and type(opts.poll_offset) ~= "number" then
    return error("opts.poll_offset must be a number")
  end

  if opts.poll_delay and type(opts.poll_delay) ~= "number" then
    return error("opts.poll_delay must be a number")
  end

  if not opts.db then
    return error("opts.db is required")
  end

  local strategy
  local poll_interval = max(opts.poll_interval or 5, 0)
  local poll_offset   = max(opts.poll_offset   or 0, 0)
  local poll_delay    = max(opts.poll_delay    or 0, 0)

  do
    local db_strategy

    if opts.db.strategy == "off" then
      db_strategy = require "kong.cluster_events.strategies.off"
    else
      return error("no cluster_events strategy for " ..
                   opts.db.strategy)
    end

    local event_ttl_in_db = max(poll_offset * 10, MIN_EVENT_TTL_IN_DB)

    strategy = db_strategy.new(opts.db, PAGE_SIZE, event_ttl_in_db)
  end

  local self      = {
    shm           = ngx.shared.kong,
    events_shm    = ngx.shared.kong_cluster_events,
    strategy      = strategy,
    poll_interval = poll_interval,
    poll_offset   = poll_offset,
    poll_delay    = poll_delay,
    event_ttl_shm = poll_interval * 2 + poll_offset,
    node_id       = nil,
    polling       = false,
    channels      = {},
    callbacks     = {},
    use_polling   = strategy:should_use_polling(),
  }

  local now = strategy:server_time() or ngx_now()
  local ok, err = self.shm:safe_set(CURRENT_AT_KEY, now)
  if not ok then
    return nil, "failed to set 'at' in shm: " .. err
  end

  -- set node id (uuid)

  self.node_id, err = knode.get_id()
  if not self.node_id then
    return nil, err
  end

  if ngx_debug and opts.node_id then
    self.node_id = opts.node_id
  end

  _init = true

  return setmetatable(self, mt)
end

function _M:broadcast(channel, data, delay)
error("in broadcast")
end

function _M:subscribe(channel, cb, start_polling)
error("in subscribe")
end

local function process_event(self, row, local_start_time)
error("in process_event")
end

local function poll(self)
error("in poll")
end

if ngx_debug then
  _M.poll = poll
end

local function get_lock(self)
error("in get_lock")
end

poll_handler = function(premature, self)
error("in poll_handler")
end

return _M
