local declarative_config = require "kong.db.schema.others.declarative_config"
local workspaces = require "kong.workspaces"


local kong = kong
local fmt = string.format
local type = type
local next = next
local pairs = pairs
local tostring = tostring
local tonumber = tonumber
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64
local null          = ngx.null


local off = {}


local _mt = {}
_mt.__index = _mt


local function empty_list_cb()
  return {}
end


local function nil_cb()
  return nil
end


local function ws(self, options)
  if not self.schema.workspaceable then
    return ""
  end

  if options then
    if options.workspace == null then
      return "*"
    end
    if options.workspace then
      return options.workspace
    end
  end
  return workspaces.get_workspace_id() or kong.default_workspace
end

local function get_entity_ids_tagged(key, tag_names, tags_cond)
  error("in get_entity_ids_tagged")
end

local function page_for_key(self, key, size, offset, options)
  if not size then
    size = self.connector:get_page_size(options)
  end

  if offset then
    local token = decode_base64(offset)
    if not token then
      return nil, self.errors:invalid_offset(offset, "bad base64 encoding")
    end

    local number = tonumber(token)
    if not number then
      return nil, self.errors:invalid_offset(offset, "invalid offset")
    end

    offset = number

  else
    offset = 1
  end

  local cache = kong.core_cache
  if not cache then
    return {}
  end

  local list, err
  if options and options.tags then
    list, err = get_entity_ids_tagged(key, options.tags, options.tags_cond)
  else
    list, err = cache:get(key, nil, empty_list_cb)
  end

  if not list then
    return nil, err
  end

  local ret = {}
  local schema_name = self.schema.name

  local item
  for i = offset, offset + size - 1 do
    item = list[i]
    if not item then
      offset = nil
      break
    end

    if schema_name == "tags" then
      local tag_name, entity_name, uuid = string.match(item, "^([^|]+)|([^|]+)|(.+)$")
      if not tag_name then
        return nil, "Could not parse tag from cache: " .. tostring (item)
      end
    else
      item = cache:get(item, nil, nil_cb)
    end

    if not item then
      return nil, "stale data detected while paginating"
    end

    item = self.schema:process_auto_fields(item, "select", true, {
      no_defaults = true,
      show_ws_id = true,
    })

    ret[i - offset + 1] = item
  end

  if offset then
    return ret, nil, encode_base64(tostring(offset + size), true)
  end

  return ret
end

local function select_by_key(self, key)
  if not kong.core_cache then
    return nil
  end

  local entity, err = kong.core_cache:get(key, nil, nil_cb)
  if not entity then
    return nil, err
  end

  entity = self.schema:process_auto_fields(entity, "select", true, {
    no_defaults = true,
    show_ws_id = true,
  })

  return entity
end

local function page(self, size, offset, options)
  local ws_id = ws(self, options)
  local key = self.schema.name .. "|" .. ws_id .. "|@list"
  return page_for_key(self, key, size, offset, options)
end

local function select(self, pk, options)
  local ws_id = ws(self, options)
  local id = declarative_config.pk_string(self.schema, pk)
  local key = self.schema.name .. ":" .. id .. ":::::" .. ws_id
  return select_by_key(self, key)
end

local function select_by_field(self, field, value, options)
  if type(value) == "table" then
    local _
    _, value = next(value)
  end

  local ws_id = ws(self, options)
  
  if field ~= "cache_key" then
    local unique_across_ws = self.schema.fields[field].unique_across_ws
    if unique_across_ws then
      ws_id = ""
    end
    assert(not options or options.workspace ~= null or unique_across_ws)
  end

  local key = self.schema.name .. "|" .. ws_id .. "|" .. field .. ":" .. value
  return select_by_key(self, key)
end

do
  local unsupported = function(operation)
    return function(self)
      local err = fmt("cannot %s '%s' entities when not using a database",
                      operation, self.schema.name)
      return nil, self.errors:operation_unsupported(err)
    end
  end

  local unsupported_by = function(operation)

    return function(self, field_name)
      local err = fmt("cannot %s '%s' entities by '%s' when not using a database",
                      operation, self.schema.name, '%s')
      return nil, self.errors:operation_unsupported(fmt(err, field_name))
    end
  end


  _mt.select = select
  _mt.page = page
  _mt.select_by_field = select_by_field
  _mt.insert = unsupported("create")
  _mt.update = unsupported("update")
  _mt.upsert = unsupported("create or update")
  _mt.delete = unsupported("remove")
  _mt.update_by_field = unsupported_by("update")
  _mt.upsert_by_field = unsupported_by("create or update")
  _mt.delete_by_field = unsupported_by("remove")
  _mt.truncate = function() return true end
  -- off-strategy specific methods:
  _mt.page_for_key = page_for_key
end

function off.new(connector, schema, errors)
  local self = {
    connector = connector, -- instance of kong.db.strategies.off.connector
    schema = schema,
    errors = errors,
  }

  if not kong.default_workspace then
    kong.default_workspace = "00000000-0000-0000-0000-000000000000"
  end

  local name = self.schema.name
  for fname, fdata in schema:each_field() do
    if fdata.type == "foreign" then
      local entity = fdata.reference
      local method = "page_for_" .. fname
      self[method] = function(_, foreign_key, size, offset, options)
        local ws_id = ws(self, options)

        local key = name .. "|" .. ws_id .. "|" .. entity .. "|" .. foreign_key.id .. "|@list"
        return page_for_key(self, key, size, offset, options)
      end
    end
  end

  return setmetatable(self, _mt)
end

return off
