local version      = require "version"

local DAO          = require "kong.db.dao"
local Entity       = require "kong.db.schema.entity"
local Errors       = require "kong.db.errors"
local Strategies   = require "kong.db.strategies"
local MetaSchema   = require "kong.db.schema.metaschema"
local constants    = require "kong.constants"
local log          = require "kong.cmd.utils.log"
local workspaces   = require "kong.workspaces"
local utils        = require "kong.tools.utils"


local fmt          = string.format
local type         = type
local pairs        = pairs
local error        = error
local ipairs       = ipairs
local rawget       = rawget
local setmetatable = setmetatable


local DEFAULT_LOCKS_TTL = 60 -- seconds

local DB = {}
DB.__index = function(self, k)
  return DB[k] or rawget(self, "daos")[k]
end

function DB.new(kong_config, strategy)
  if not kong_config then
    error("missing kong_config", 2)
  end

  if strategy ~= nil and type(strategy) ~= "string" then
    error("strategy must be a string", 2)
  end

  strategy = strategy or kong_config.database

  local errors = Errors.new(strategy)

  local schemas = {}
  do
    for _, entity_name in ipairs(constants.CORE_ENTITIES) do
      local entity_schema = require("kong.db.schema.entities." .. entity_name)

      local ok, err_t = MetaSchema:validate(entity_schema)
      if not ok then
        return nil, fmt("schema of entity '%s' is invalid: %s", entity_name,
                        tostring(errors:schema_violation(err_t)))
      end
      local entity, err = Entity.new(entity_schema)
      if not entity then
        return nil, fmt("schema of entity '%s' is invalid: %s", entity_name,
                        err)
      end
      schemas[entity_name] = entity

      local subschemas
      ok, subschemas = utils.load_module_if_exists("kong.db.schema.entities." .. entity_name .. "_subschemas")
      if ok then
        for name, subschema in pairs(subschemas) do
          local ok, err = entity:new_subschema(name, subschema)
          if not ok then
            return nil, ("error initializing schema for %s: %s"):format(entity_name, err)
          end
        end
      end
    end
  end

  -- load strategy

  local connector, strategies, err = Strategies.new(kong_config, strategy, schemas, errors)
  if err then
    return nil, err
  end

  local daos = {}

  local self   = {
    daos       = daos,       -- each of those has the connector singleton
    strategies = strategies,
    connector  = connector,
    strategy   = strategy,
    errors     = errors,
    infos      = connector:infos(),
    kong_config = kong_config,
  }

  do
    for _, schema in pairs(schemas) do
      local strategy = strategies[schema.name]
      if not strategy then
        return nil, fmt("no strategy found for schema '%s'", schema.name)
      end

      daos[schema.name] = DAO.new(self, schema, strategy, errors)
    end
  end

  return setmetatable(self, DB)
end

local function prefix_err(self, err)
  return "[" .. self.infos.strategy .. " error] " .. err
end


local function fmt_err(self, err, ...)
  return prefix_err(self, fmt(err, ...))
end


function DB:init_connector()
  local ok, err = self.connector:init()
  if not ok then
    return nil, prefix_err(self, err)
  end

  self.infos = self.connector:infos()

  local version_constants = constants.DATABASE[self.strategy:upper()]

  if version_constants then
    error("version_constants")
  end

  return ok
end

function DB:init_worker()
  local ok, err = self.connector:init_worker(self.strategies)
  if not ok then
    return nil, prefix_err(self, err)
  end

  return ok
end

function DB:connect()
  local ok, err = self.connector:connect()
  if not ok then
    return nil, prefix_err(self, err)
  end

  return ok
end

function DB:setkeepalive()
  local ok, err = self.connector:setkeepalive()
  if not ok then
    return nil, prefix_err(self, err)
  end

  return ok
end

function DB:close()
  local ok, err = self.connector:close()
  if not ok then
    return nil, prefix_err(self, err)
  end

  return ok
end

function DB:reset()
  local ok, err = self.connector:reset()
  if not ok then
    return nil, prefix_err(self, err)
  end

  return ok
end

function DB:truncate(table_name)
  if table_name ~= nil and type(table_name) ~= "string" then
    error("table_name must be a string", 2)
  end
  local ok, err

  if table_name then
    ok, err = self.connector:truncate_table(table_name)
  else
    ok, err = self.connector:truncate()
  end

  -- re-create default workspace on full or workspaces truncate
  if not table_name or table_name == "workspaces" then
    workspaces.upsert_default()
  end

  if not ok then
    return nil, prefix_err(self, err)
  end

  return ok
end

function DB:set_events_handler(events)
  for _, dao in pairs(self.daos) do
    dao.events = events
  end
end

function DB:check_version_compat(_min, _deprecated)
  error("in check_version_compat")
end

do
  --local concurrency = require "kong.concurrency"

  local knode = (kong and kong.node) and kong.node or
                require "kong.pdk.node".new()

  local MAX_LOCK_WAIT_STEP = 2 -- seconds

  function DB:cluster_mutex(key, opts, cb)
    error("in cluster_mutex")
  end
end

do
  -- migrations
  local utils = require "kong.tools.utils"
  --local MigrationHelpers = require "kong.db.migrations.helpers"
  local MigrationsState = require "kong.db.migrations.state"

  local last_schema_state

  function DB:schema_state()
    local err
    last_schema_state, err = MigrationsState.load(self)
    return last_schema_state, err
  end

  function DB:last_schema_state()
    return last_schema_state or self:schema_state()
  end

  function DB:schema_bootstrap()
    error("in schema_bootstrap")
  end

  function DB:schema_reset()
    error("in schema_reset")
  end

  function DB:run_migrations(migrations, options)
    error("in run_migrations")
  end
end

return DB
