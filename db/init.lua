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
        return nil, fmt("schema of entity '%s' is invalid: %s", entity
_name,
                        tostring(errors:schema_violation(err_t)))
      end
      local entity, err = Entity.new(entity_schema)
      if not entity then
        return nil, fmt("schema of entity '%s' is invalid: %s", entity
_name,
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
end



return DB
