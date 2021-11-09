local cjson = require "cjson.safe"
local checks = require "kong.pdk.private.checks"
local phase_checker = require "kong.pdk.private.phases"


local ngx = ngx
local ngx_var = ngx.var
local table_insert = table.insert
local table_sort = table.sort
local table_concat = table.concat
local type = type
local string_find = string.find
local string_sub = string.sub
local string_lower = string.lower
local normalize_header = checks.normalize_header
local normalize_multi_header = checks.normalize_multi_header
local validate_header = checks.validate_header
local validate_headers = checks.validate_headers
local check_phase = phase_checker.check
local escape = require("kong.tools.uri").escape


local PHASES = phase_checker.phases

local access_and_rewrite = phase_checker.new(PHASES.rewrite, PHASES.access)
local preread_and_balancer = phase_checker.new(PHASES.preread, PHASES.balancer)

local function make_ordered_args(args)
  local out = {}
  local t = {}
  for k, v in pairs(args) do
    if type(k) ~= "string" then
      return nil, "arg keys must be strings"
    end

    t[k] = v

    local pok, s = pcall(ngx.encode_args, t)
    if not pok then
      return nil, s
    end

    table_insert(out, s)
    t[k] = nil
  end
  table_sort(out)
  return table_concat(out, "&")
end

local function new(self)

  local request = {}

  -- TODO these constants should be shared with kong.request

  local CONTENT_TYPE           = "Content-Type"

  local CONTENT_TYPE_POST      = "application/x-www-form-urlencoded"
  local CONTENT_TYPE_JSON      = "application/json"
  local CONTENT_TYPE_FORM_DATA = "multipart/form-data"

  request.enable_buffering = function()
    check_phase(access_and_rewrite)

    if ngx.req.http_version() >= 2 then
      error("buffered proxying cannot currently be enabled with http/" ..
            ngx.req.http_version() .. ", please use http/1.x instead", 2)
    end


    ngx.ctx.buffered_proxying = true
  end

  request.set_scheme = function(scheme)
    check_phase(PHASES.access)

    if type(scheme) ~= "string" then
      error("scheme must be a string", 2)
    end

    if scheme ~= "http" and scheme ~= "https" then
      error("invalid scheme: " .. scheme, 2)
    end

    ngx_var.upstream_scheme = scheme
  end

  request.set_path = function(path)
    check_phase(PHASES.access)

    if type(path) ~= "string" then
      error("path must be a string", 2)
    end

    if string_sub(path, 1, 1) ~= "/" then
      error("path must start with /", 2)
    end

    ngx_var.upstream_uri = escape(path)
  end

  request.set_raw_query = function(query)
    check_phase(access_and_rewrite)

    if type(query) ~= "string" then
      error("query must be a string", 2)
    end

    ngx.req.set_uri_args(query)
  end

  do
    local accepted_methods = {
      ["GET"]       = ngx.HTTP_GET,
      ["HEAD"]      = ngx.HTTP_HEAD,
      ["PUT"]       = ngx.HTTP_PUT,
      ["POST"]      = ngx.HTTP_POST,
      ["DELETE"]    = ngx.HTTP_DELETE,
      ["OPTIONS"]   = ngx.HTTP_OPTIONS,
      ["MKCOL"]     = ngx.HTTP_MKCOL,
      ["COPY"]      = ngx.HTTP_COPY,
      ["MOVE"]      = ngx.HTTP_MOVE,
      ["PROPFIND"]  = ngx.HTTP_PROPFIND,
      ["PROPPATCH"] = ngx.HTTP_PROPPATCH,
      ["LOCK"]      = ngx.HTTP_LOCK,
      ["UNLOCK"]    = ngx.HTTP_UNLOCK,
      ["PATCH"]     = ngx.HTTP_PATCH,
      ["TRACE"]     = ngx.HTTP_TRACE,
    }

    request.set_method = function(method)
      check_phase(access_and_rewrite)

      if type(method) ~= "string" then
        error("method must be a string", 2)
      end

      local method_id = accepted_methods[method]
      if not method_id then
        error("invalid method: " .. method, 2)
      end

      ngx.req.set_method(method_id)
    end
  end

  request.set_query = function(args)
    check_phase(access_and_rewrite)

    if type(args) ~= "table" then
      error("args must be a table", 2)
    end

    local querystring, err = make_ordered_args(args)
    if not querystring then
      error(err, 2) -- type error inside the table
    end

    ngx.req.set_uri_args(querystring)
  end

  local set_authority
  if ngx.config.subsystem ~= "stream" then
    set_authority = require("resty.kong.grpc").set_authority
  end

  request.set_header = function(header, value)
    check_phase(access_and_rewrite)

    validate_header(header, value)

    if string_lower(header) == "host" then
      ngx_var.upstream_host = value
    end

    if string_lower(header) == ":authority" then
      if ngx_var.upstream_scheme == "grpc" or
         ngx_var.upstream_scheme == "grpcs"
      then
        return set_authority(value)

      else
        return nil, "cannot set :authority pseudo-header on non-grpc requests"
      end
    end

    ngx.req.set_header(header, normalize_header(value))
  end

  request.add_header = function(header, value)
    check_phase(access_and_rewrite)

    validate_header(header, value)

    if string_lower(header) == "host" then
      ngx_var.upstream_host = value
    end

    local headers = ngx.req.get_headers()[header]
    if type(headers) ~= "table" then
      headers = { headers }
    end

    table_insert(headers, normalize_header(value))

    ngx.req.set_header(header, headers)
  end

  request.clear_header = function(header)
    check_phase(access_and_rewrite)

    if type(header) ~= "string" then
      error("header must be a string", 2)
    end

    ngx.req.clear_header(header)
  end

  request.set_headers = function(headers)
    check_phase(access_and_rewrite)

    if type(headers) ~= "table" then
      error("headers must be a table", 2)
    end

    -- Check for type errors first

    validate_headers(headers)

    -- Now we can use ngx.req.set_header without pcall

    for k, v in pairs(headers) do
      if string_lower(k) == "host" then
        ngx_var.upstream_host = v
      end

      ngx.req.set_header(k, normalize_multi_header(v))
    end

  end

  request.set_raw_body = function(body)
    check_phase(access_and_rewrite)

    if type(body) ~= "string" then
      error("body must be a string", 2)
    end

    ngx.req.read_body()

    ngx.req.set_body_data(body)
  end

  do
    local set_body_handlers = {

      [CONTENT_TYPE_POST] = function(args, mime)
        if type(args) ~= "table" then
          error("args must be a table", 3)
        end

        local querystring, err = make_ordered_args(args)
        if not querystring then
          error(err, 3) -- type error inside the table
        end

        return querystring, mime
      end,

      [CONTENT_TYPE_JSON] = function(args, mime)
        local encoded, err = cjson.encode(args)
        if not encoded then
          error(err, 3)
        end

        return encoded, mime
      end,

      [CONTENT_TYPE_FORM_DATA] = function(args, mime)
        local keys = {}

        local boundary
        local boundary_ok = false
        local at = string_find(mime, "boundary=", 1, true)
        if at then
          at = at + 9
          if string_sub(mime, at, at) == '"' then
            local till = string_find(mime, '"', at + 1, true)
            boundary = string_sub(mime, at + 1, till - 1)
          else
            boundary = string_sub(mime, at)
          end
          boundary_ok = true
        end

        -- This will only loop in the unlikely event that the
        -- boundary is not acceptable and needs to be regenerated.
        repeat

          if not boundary_ok then
            boundary = tostring(math.random(1e10))
            boundary_ok = true
          end

          local boundary_check = "\n--" .. boundary
          local i = 1
          for k, v in pairs(args) do
            if type(k) ~= "string" then
              error(("invalid key %q: got %s, " ..
                     "expected string"):format(k, type(k)), 3)
            end
            local tv = type(v)
            if tv ~= "string" and tv ~= "number" and tv ~= "boolean" then
              error(("invalid value %q: got %s, " ..
                     "expected string, number or boolean"):format(k, tv), 3)
            end
            keys[i] = k
            i = i + 1
            if string_find(tostring(v), boundary_check, 1, true) then
              boundary_ok = false
            end
          end

        until boundary_ok

        table_sort(keys)

        local out = {}
        local i = 1

        for _, k in ipairs(keys) do
          out[i] = "--"
          out[i + 1] = boundary
          out[i + 2] = "\r\n"
          out[i + 3] = 'Content-Disposition: form-data; name="'
          out[i + 4] = k
          out[i + 5] = '"\r\n\r\n'
          local v = args[k]
          out[i + 6] = v
          out[i + 7] = "\r\n"
          i = i + 8
        end
        out[i] = "--"
        out[i + 1] = boundary
        out[i + 2] = "--\r\n"

        local output = table.concat(out)

        return output, CONTENT_TYPE_FORM_DATA .. "; boundary=" .. boundary
      end,

    }

    request.set_body = function(args, mime)
      check_phase(access_and_rewrite)

      if type(args) ~= "table" then
        error("args must be a table", 2)
      end
      if mime and type(mime) ~= "string" then
        error("mime must be a string", 2)
      end
      if not mime then
        mime = ngx.req.get_headers()[CONTENT_TYPE]
        if not mime then
          return nil, "content type was neither explicitly given " ..
                      "as an argument or received as a header"
        end
      end

      local boundaryless_mime = mime
      local s = string_find(mime, ";", 1, true)
      if s then
        boundaryless_mime = string_sub(mime, 1, s - 1)
      end

      local handler_fn = set_body_handlers[boundaryless_mime]
      if not handler_fn then
        error("unsupported content type " .. mime, 2)
      end

      -- Ensure client request body has been read.
      -- This function is a nop if body has already been read,
      -- and necessary to write the request to the service if it has not.
      ngx.req.read_body()

      local body, content_type = handler_fn(args, mime)

      ngx.req.set_body_data(body)
      ngx.req.set_header(CONTENT_TYPE, content_type)

      return true
    end

  end

  if ngx.config.subsystem == "stream" then
    local disable_proxy_ssl = require("resty.kong.tls").disable_proxy_ssl
    request.disable_tls = function()
      check_phase(preread_and_balancer)

      return disable_proxy_ssl()
    end
  end

  return request

end

return {
  new = new,
}
