local utils = require "kong.tools.utils"
local log = require "kong.cmd.utils.log"
local Schema = require "kong.db.schema"
local Migration = require "kong.db.schema.others.migrations"
local Errors = require "kong.db.errors"


local MigrationSchema = Schema.new(Migration)


local fmt = string.format
local max = math.max
local null = ngx.null


local function prefix_err(db, err)
  return "[" .. db.infos.strategy .. " error] " .. err
end


local function fmt_err(db, err, ...)
  return prefix_err(db, fmt(err, ...))
end

local Migrations_mt = {
  __tostring = function(t)
    local subsystems = {}

    local max_length = 0
    for _, subsys in ipairs(t) do
      max_length = max(max_length, #subsys.subsystem)
    end

    for _, subsys in ipairs(t) do
      local names = {}

      for _, migration in ipairs(subsys.migrations) do
        table.insert(names, migration.name)
      end

      table.insert(subsystems, fmt("%" .. max_length .. "s: %s",
                                   subsys.subsystem, table.concat(names, ", ")))
    end

    return table.concat(subsystems, "\n")
  end,
}

local function load_subsystems(db, plugin_names)
  if type(plugin_names) ~= "table" then
    error("plugin_names must be a table", 2)
  end

  local sorted_plugin_names = {}
  for name in pairs(plugin_names) do
    sorted_plugin_names[#sorted_plugin_names + 1] = name
  end
  table.sort(sorted_plugin_names)

  local subsystems = require("kong.db.migrations.subsystems")

  local res = {}
  -- core  *plugins
  for _, ss in ipairs(subsystems) do
    if ss.name:match("%*") then
      for _, plugin_name in ipairs(sorted_plugin_names) do
        local namespace = ss.namespace:gsub("%*", plugin_name)
        local ok, mig_idx = utils.load_module_if_exists(namespace)
        if ok then
          if type(mig_idx) ~= "table" then
            return nil, fmt_err(db, "migrations index from '%s' must be a table",
                                namespace)
          end

          table.insert(res, {
            name = ss.name,
            namespace = namespace,
            migrations_index = mig_idx,
          })
        end
      end
    else
      table.insert(res, {
        name = ss.name,
        namespace = ss.namespace,
        migrations_index = require(ss.namespace),
      })
    end
  end

  for _, subsys in ipairs(res) do
    subsys.migrations = {}

    for _, mig_name in ipairs(subsys.migrations_index) do
      local mig_module = fmt("%s.%s", subsys.namespace, mig_name)
      local ok, migration = utils.load_module_if_exists(mig_module)
      if not ok then
        return nil, fmt_err(db, "failed to load migration '%s' of '%s' subsystem",
                            mig_module, subsys.name)
      end

      migration.name = mig_name
      local ok, errors = MigrationSchema:validate(migration)
      if not ok then
        local err_t = Errors:schema_violation(errors)
        return nil, fmt_err(db, "migration '%s' of '%s' subsystem is invalid: %s",
                            mig_module, subsys.name, tostring(err_t))
      end

      table.insert(subsys.migrations, migration)
    end
  end

  return res
end

local State = {}
State.__index = State

local function get_executed_migrations_for_subsystem(self, subsystem_name)
end

local function value_or_empty_table(value)
  if value == nil or value == null then
    return {}
  end
  return value
end

function State.load(db)
  log.debug("loading subsystems migrations...")

  local subsystems, err = load_subsystems(db, db.kong_config.loaded_plugins)
  if not subsystems then
    return nil, prefix_err(db, err)
  end

  log.verbose("retrieving %s schema state...", db.infos.db_desc)

  local ok, err = db.connector:connect_migrations({ no_keyspace = true })
  if not ok then
    return nil, prefix_err(db, err)
  end

  local rows, err = db.connector:schema_migrations(subsystems)
  if err then
    db.connector:close()
    return nil, prefix_err(db, "failed to check schema state: " .. err)
  end

  db.connector:close()

  log.verbose("schema state retrieved")

  local schema_state = {
    needs_bootstrap = false,
    executed_migrations = nil,
    pending_migrations = nil,
    missing_migrations = nil,
    new_migrations = nil,
  }

  local rows_as_hash = {}

  if not rows then
    schema_state.needs_bootstrap = true

  else
    for _, row in ipairs(rows) do
      rows_as_hash[row.subsystem] = {
        last_executed = row.last_executed,
        executed = value_or_empty_table(row.executed),
        pending = value_or_empty_table(row.pending),
      }
    end
  end

  for _, subsystem in ipairs(subsystems) do
    local subsystem_state = {
      executed_migrations = {},
      pending_migrations = {},
      missing_migrations = {},
      new_migrations = {},
    }

    if not rows_as_hash[subsystem.name] then
      for i, mig in ipairs(subsystem.migrations) do
        subsystem_state.new_migrations[i] = mig
      end
    else
      local n
      for i, mig in ipairs(subsystem.migrations) do
        if mig.name == rows_as_hash[subsystem.name].last_executed then
          n = i + 1
        end

        local found

        for _, db_mig in ipairs(rows_as_hash[subsystem.name].executed) do
          if mig.name == db_mig then
            found = true
            table.insert(subsystem_state.executed_migrations, mig)
            break
          end
        end

        if not found then
          for _, db_mig in ipairs(rows_as_hash[subsystem.name].pending) do
            if mig.name == db_mig then
              found = true
              table.insert(subsystem_state.pending_migrations, mig)
              break
            end
          end
        end

        if not found then
          if not n or i >= n then
            table.insert(subsystem_state.new_migrations, mig)
          else
            table.insert(subsystem_state.missing_migrations, mig)
          end
        end
      end
    end

    for k, v in pairs(subsystem_state) do
      if #v > 0 then
        if not schema_state[k] then
          schema_state[k] = setmetatable({}, Migrations_mt)
        end

        table.insert(schema_state[k], {
            subsystem = subsystem.name,
            namespace = subsystem.namespace,
            migrations = v,
          })
      end
    end
  end

  return setmetatable(schema_state, State)
end

function State:is_up_to_date()
  return not self.needs_bootstrap and not self.new_migrations
end

function State:is_migration_executed(subsystem_name, migration_name)
  error("in is_migration_executed")
end

return State
