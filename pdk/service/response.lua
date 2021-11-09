local cjson = require "cjson.safe".new()
local multipart = require "multipart"
local phase_checker = require "kong.pdk.private.phases"


local ngx = ngx
local sub = string.sub
local fmt = string.format
local gsub = string.gsub
local find = string.find
local type = type
local error = error
local lower = string.lower
local pairs = pairs
local tonumber = tonumber
local getmetatable = getmetatable
local setmetatable = setmetatable
local check_phase = phase_checker.check


cjson.decode_array_with_array_mt(true)


local PHASES = phase_checker.phases

local header_body_log = phase_checker.new(PHASES.response,
                                          PHASES.header_filter,
                                          PHASES.body_filter,
                                          PHASES.log)


local attach_resp_headers_mt


do
  local resp_headers_orig_mt_index


  local resp_headers_mt = {
    __index = function(t, name)
      if type(name) == "string" then
        local var = fmt("upstream_http_%s", gsub(lower(name), "-", "_"))
        if not ngx.var[var] then
          return nil
        end
      end

      return resp_headers_orig_mt_index(t, name)
    end,
  }

  attach_resp_headers_mt = function(response_headers, err)
    if not resp_headers_orig_mt_index then
      local mt = getmetatable(response_headers)
      resp_headers_orig_mt_index = mt.__index
    end

    setmetatable(response_headers, resp_headers_mt)

    return response_headers, err
  end
end

local attach_buffered_headers_mt

do
  local EMPTY = {}

  attach_buffered_headers_mt = function(response_headers, max_headers)
    if not response_headers then
      return EMPTY
    end

    return setmetatable({}, { __index = function(_, name)
      if type(name) ~= "string" then
        return nil
      end

      if response_headers[name] then
        return response_headers[name]
      end

      name = lower(name)

      if response_headers[name] then
        return response_headers[name]
      end

      name = gsub(name, "-", "_")

      if response_headers[name] then
        return response_headers[name]
      end

      local i = 1
      for n, v in pairs(response_headers) do
        if i > max_headers then
          return nil
        end

        n = gsub(lower(n), "-", "_")
        if n == name then
          return v
        end

        i = i + 1
      end
    end })
  end
end

local function new(pdk, major_version)
  local response = {}


  local MIN_POST_ARGS          = 1
  local MAX_POST_ARGS_DEFAULT  = 100
  local MAX_POST_ARGS          = 1000

  local CONTENT_TYPE           = "Content-Type"

  local CONTENT_TYPE_POST      = "application/x-www-form-urlencoded"
  local CONTENT_TYPE_JSON      = "application/json"
  local CONTENT_TYPE_FORM_DATA = "multipart/form-data"

  local MIN_HEADERS            = 1
  local MAX_HEADERS_DEFAULT    = 100
  local MAX_HEADERS            = 1000

  function response.get_status()
    check_phase(header_body_log)

    local ctx = ngx.ctx
    if ctx.buffered_status then
      return ctx.buffered_status
    end

    return tonumber(sub(ngx.var.upstream_status or "", -3))
  end

  function response.get_headers(max_headers)
    check_phase(header_body_log)

    local buffered_headers = ngx.ctx.buffered_headers

    if max_headers == nil then
      if buffered_headers then
        return attach_buffered_headers_mt(buffered_headers, MAX_HEADERS_DEFAULT)
      end

      return attach_resp_headers_mt(ngx.resp.get_headers(MAX_HEADERS_DEFAULT))
    end

    if type(max_headers) ~= "number" then
      error("max_headers must be a number", 2)

    elseif max_headers < MIN_HEADERS then
      error("max_headers must be >= " .. MIN_HEADERS, 2)

    elseif max_headers > MAX_HEADERS then
      error("max_headers must be <= " .. MAX_HEADERS, 2)
    end

    if buffered_headers then
      return attach_buffered_headers_mt(buffered_headers, max_headers)
    end

    return attach_resp_headers_mt(ngx.resp.get_headers(max_headers))
  end

  function response.get_header(name)
    check_phase(header_body_log)

    if type(name) ~= "string" then
      error("name must be a string", 2)
    end

    local header_value = response.get_headers()[name]
    if type(header_value) == "table" then
      return header_value[1]
    end

    return header_value
  end

  function response.get_raw_body()
    check_phase(header_body_log)
    local ctx = ngx.ctx
    if not ctx.buffered_proxying then
      error("service body is only available with buffered proxying " ..
            "(see: kong.service.request.enable_buffering function)", 2)
    end

    return ctx.buffered_body or ""
  end

  function response.get_body(mimetype, max_args)
    check_phase(header_body_log)
    if not ngx.ctx.buffered_proxying then
      error("service body is only available with buffered proxying " ..
            "(see: kong.service.request.enable_buffering function)", 2)
    end

    local content_type = mimetype or response.get_header(CONTENT_TYPE)
    if not content_type then
      return nil, "missing content type"
    end

    local content_type_lower = lower(content_type)
    do
      local s = find(content_type_lower, ";", 1, true)
      if s then
        content_type_lower = sub(content_type_lower, 1, s - 1)
      end
    end

    if find(content_type_lower, CONTENT_TYPE_POST, 1, true) == 1 then
      if max_args ~= nil then
        if type(max_args) ~= "number" then
          error("max_args must be a number", 2)

        elseif max_args < MIN_POST_ARGS then
          error("max_args must be >= " .. MIN_POST_ARGS, 2)

        elseif max_args > MAX_POST_ARGS then
          error("max_args must be <= " .. MAX_POST_ARGS, 2)
        end
      end

      local body = response.get_raw_body()
      local pargs, err = ngx.decode_args(body, max_args or MAX_POST_ARGS_DEFAULT)
      if not pargs then
        return nil, err, CONTENT_TYPE_POST
      end

      return pargs, nil, CONTENT_TYPE_POST

    elseif find(content_type_lower, CONTENT_TYPE_JSON, 1, true) == 1 then
      local body = response.get_raw_body()
      local json = cjson.decode(body)
      if type(json) ~= "table" then
        return nil, "invalid json body", CONTENT_TYPE_JSON
      end

      return json, nil, CONTENT_TYPE_JSON

    elseif find(content_type_lower, CONTENT_TYPE_FORM_DATA, 1, true) == 1 then
      local body = response.get_raw_body()

      local parts = multipart(body, content_type)
      if not parts then
        return nil, "unable to decode multipart body", CONTENT_TYPE_FORM_DATA
      end

      local margs = parts:get_all_with_arrays()
      if not margs then
        return nil, "unable to read multipart values", CONTENT_TYPE_FORM_DATA
      end

      return margs, nil, CONTENT_TYPE_FORM_DATA

    else
      return nil, "unsupported content type '" .. content_type .. "'", content_type_lower
    end
  end


  return response
end


return {
  new = new,
}
