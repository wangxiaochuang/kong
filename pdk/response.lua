local cjson = require "cjson.safe"
local checks = require "kong.pdk.private.checks"
local phase_checker = require "kong.pdk.private.phases"
local utils = require "kong.tools.utils"


local ngx = ngx
local fmt = string.format
local type = type
local find = string.find
local lower = string.lower
local error = error
local pairs = pairs
local coroutine = coroutine
local normalize_header = checks.normalize_header
local normalize_multi_header = checks.normalize_multi_header
local validate_header = checks.validate_header
local validate_headers = checks.validate_headers
local check_phase = phase_checker.check
local split = utils.split
local add_header
if ngx and ngx.config.subsystem == "http" then
  add_header = require("ngx.resp").add_header
end


local PHASES = phase_checker.phases

local header_body_log = phase_checker.new(PHASES.response,
                                          PHASES.header_filter,
                                          PHASES.body_filter,
                                          PHASES.log,
                                          PHASES.error,
                                          PHASES.admin_api)

local rewrite_access_header = phase_checker.new(PHASES.rewrite,
                                                PHASES.access,
                                                PHASES.response,
                                                PHASES.header_filter,
                                                PHASES.error,
                                                PHASES.admin_api)


local function new(self, major_version)
  local _RESPONSE = {}

  local MIN_HEADERS          = 1
  local MAX_HEADERS_DEFAULT  = 100
  local MAX_HEADERS          = 1000

  local MIN_STATUS_CODE      = 100
  local MAX_STATUS_CODE      = 599
  local MIN_ERR_STATUS_CODE  = 400

  local GRPC_STATUS_UNKNOWN  = 2
  local GRPC_STATUS_NAME     = "grpc-status"
  local GRPC_MESSAGE_NAME    = "grpc-message"

  local CONTENT_LENGTH_NAME  = "Content-Length"
  local CONTENT_TYPE_NAME    = "Content-Type"
  local CONTENT_TYPE_JSON    = "application/json; charset=utf-8"
  local CONTENT_TYPE_GRPC    = "application/grpc"


  local ACCEPT_NAME          = "Accept"

  local HTTP_TO_GRPC_STATUS = {
    [200] = 0,
    [400] = 3,
    [401] = 16,
    [403] = 7,
    [404] = 5,
    [409] = 6,
    [429] = 8,
    [499] = 1,
    [500] = 13,
    [501] = 12,
    [503] = 14,
    [504] = 4,
  }

  local GRPC_MESSAGES = {
    [0]  = "OK",
    [1]  = "Canceled",
    [2]  = "Unknown",
    [3]  = "InvalidArgument",
    [4]  = "DeadlineExceeded",
    [5]  = "NotFound",
    [6]  = "AlreadyExists",
    [7]  = "PermissionDenied",
    [8]  = "ResourceExhausted",
    [9]  = "FailedPrecondition",
    [10] = "Aborted",
    [11] = "OutOfRange",
    [12] = "Unimplemented",
    [13] = "Internal",
    [14] = "Unavailable",
    [15] = "DataLoss",
    [16] = "Unauthenticated",
  }

  local HTTP_MESSAGES = {
    s400 = "Bad request",
    s401 = "Unauthorized",
    s402 = "Payment required",
    s403 = "Forbidden",
    s404 = "Not found",
    s405 = "Method not allowed",
    s406 = "Not acceptable",
    s407 = "Proxy authentication required",
    s408 = "Request timeout",
    s409 = "Conflict",
    s410 = "Gone",
    s411 = "Length required",
    s412 = "Precondition failed",
    s413 = "Payload too large",
    s414 = "URI too long",
    s415 = "Unsupported media type",
    s416 = "Range not satisfiable",
    s417 = "Expectation failed",
    s418 = "I'm a teapot",
    s421 = "Misdirected request",
    s422 = "Unprocessable entity",
    s423 = "Locked",
    s424 = "Failed dependency",
    s425 = "Too early",
    s426 = "Upgrade required",
    s428 = "Precondition required",
    s429 = "Too many requests",
    s431 = "Request header fields too large",
    s451 = "Unavailable for legal reasons",
    s494 = "Request header or cookie too large",
    s500 = "An unexpected error occurred",
    s501 = "Not implemented",
    s502 = "An invalid response was received from the upstream server",
    s503 = "The upstream server is currently unavailable",
    s504 = "The upstream server is timing out",
    s505 = "HTTP version not supported",
    s506 = "Variant also negotiates",
    s507 = "Insufficient storage",
    s508 = "Loop detected",
    s510 = "Not extended",
    s511 = "Network authentication required",
    default = "The upstream server responded with %d"
  }

  function _RESPONSE.get_status()
    check_phase(header_body_log)

    return ngx.status
  end

  function _RESPONSE.get_header(name)
    check_phase(header_body_log)

    if type(name) ~= "string" then
      error("header name must be a string", 2)
    end

    local header_value = _RESPONSE.get_headers()[name]
    if type(header_value) == "table" then
      return header_value[1]
    end

    return header_value
  end

  function _RESPONSE.get_headers(max_headers)
    check_phase(header_body_log)

    if max_headers == nil then
      return ngx.resp.get_headers(MAX_HEADERS_DEFAULT)
    end

    if type(max_headers) ~= "number" then
      error("max_headers must be a number", 2)

    elseif max_headers < MIN_HEADERS then
      error("max_headers must be >= " .. MIN_HEADERS, 2)

    elseif max_headers > MAX_HEADERS then
      error("max_headers must be <= " .. MAX_HEADERS, 2)
    end

    return ngx.resp.get_headers(max_headers)
  end

  function _RESPONSE.get_source(ctx)
    if ctx == nil then
      check_phase(header_body_log)
      ctx = ngx.ctx
    end

    if ctx.KONG_UNEXPECTED then
      return "error"
    end

    if ctx.KONG_EXITED then
      return "exit"
    end

    if ctx.KONG_PROXIED then
      return "service"
    end

    return "error"
  end

  function _RESPONSE.set_status(status)
    check_phase(rewrite_access_header)

    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    if type(status) ~= "number" then
      error("code must be a number", 2)

    elseif status < MIN_STATUS_CODE or status > MAX_STATUS_CODE then
      error(fmt("code must be a number between %u and %u", MIN_STATUS_CODE, MAX_STATUS_CODE), 2)
    end

    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    ngx.status = status
  end

  function _RESPONSE.set_header(name, value)
    check_phase(rewrite_access_header)

    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    validate_header(name, value)

    ngx.header[name] = normalize_header(value)
  end

  function _RESPONSE.add_header(name, value)
    check_phase(rewrite_access_header)

    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    validate_header(name, value)

    add_header(name, normalize_header(value))
  end

  function _RESPONSE.clear_header(name)
    check_phase(rewrite_access_header)

    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    if type(name) ~= "string" then
      error("header name must be a string", 2)
    end

    ngx.header[name] = nil
  end

  function _RESPONSE.set_headers(headers)
    check_phase(rewrite_access_header)

    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    validate_headers(headers)

    for name, value in pairs(headers) do
      ngx.header[name] = normalize_multi_header(value)
    end
  end

  local function is_grpc_request()
    local req_ctype = ngx.var.content_type
    return req_ctype
      and find(req_ctype, CONTENT_TYPE_GRPC, 1, true) == 1
      and ngx.req.http_version() == 2
  end

  local function send(status, body, headers)
    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    ngx.status = status

    local has_content_type
    if headers ~= nil then
      for name, value in pairs(headers) do
        ngx.header[name] = normalize_multi_header(value)
        if not has_content_type then
          local lower_name = lower(name)
          if lower_name == "content-type" or
             lower_name == "content_type" then
            has_content_type = true
          end
        end
      end
    end

    local res_ctype = ngx.header[CONTENT_TYPE_NAME]

    local is_grpc
    local is_grpc_output
    if res_ctype then
      is_grpc = find(res_ctype, CONTENT_TYPE_GRPC, 1, true) == 1
      is_grpc_output = is_grpc
    else
      is_grpc = is_grpc_request()
    end

    local grpc_status
    if is_grpc and not ngx.header[GRPC_STATUS_NAME] then
      grpc_status = HTTP_TO_GRPC_STATUS[status]
      if not grpc_status then
        if status >= 500 and status <= 599 then
          grpc_status = HTTP_TO_GRPC_STATUS[500]
        elseif status >= 400 and status <= 499 then
          grpc_status = HTTP_TO_GRPC_STATUS[400]
        elseif status >= 200 and status <= 299 then
          grpc_status = HTTP_TO_GRPC_STATUS[200]
        else
          grpc_status = GRPC_STATUS_UNKNOWN
        end
      end

      ngx.header[GRPC_STATUS_NAME] = grpc_status
    end

    local json
    if type(body) == "table" then
      if is_grpc then
        if is_grpc_output then
          error("table body encoding with gRPC is not supported", 2)

        elseif type(body.message) == "string" then
          body = body.message

        else
          self.log.warn("body was removed because table body encoding with " ..
                        "gRPC is not supported")
          body = nil
        end

      else
        local err
        json, err = cjson.encode(body)
        if err then
          error(fmt("body encoding failed while flushing response: %s", err), 2)
        end
      end
    end

    local is_header_filter_phase = self.ctx.core.phase == PHASES.header_filter

    if json ~= nil then
      if not has_content_type then
        ngx.header[CONTENT_TYPE_NAME] = CONTENT_TYPE_JSON
      end

      ngx.header[CONTENT_LENGTH_NAME] = #json

      if is_header_filter_phase then
        ngx.ctx.response_body = json

      else
        ngx.print(json)
      end

    elseif body ~= nil then
      if is_grpc and not is_grpc_output then
        ngx.header[CONTENT_LENGTH_NAME] = 0
        ngx.header[GRPC_MESSAGE_NAME] = body

        if is_header_filter_phase then
          ngx.ctx.response_body = ""

        else
          ngx.print() -- avoid default content
        end

      else
        ngx.header[CONTENT_LENGTH_NAME] = #body
        if grpc_status and not ngx.header[GRPC_MESSAGE_NAME] then
          ngx.header[GRPC_MESSAGE_NAME] = GRPC_MESSAGES[grpc_status]
        end

        if is_header_filter_phase then
          ngx.ctx.response_body = body

        else
          ngx.print(body)
        end
      end

    else
      ngx.header[CONTENT_LENGTH_NAME] = 0
      if grpc_status and not ngx.header[GRPC_MESSAGE_NAME] then
        ngx.header[GRPC_MESSAGE_NAME] = GRPC_MESSAGES[grpc_status]
      end

      if is_grpc then
        if is_header_filter_phase then
          ngx.ctx.response_body = ""

        else
          ngx.print() -- avoid default content
        end
      end
    end

    if is_header_filter_phase then
      return ngx.exit(ngx.OK)
    end

    return ngx.exit(status)
  end

  local function flush(ctx)
    ctx = ctx or ngx.ctx
    local response = ctx.delayed_response
    return send(response.status_code, response.content, response.headers)
  end

  if ngx and ngx.config.subsystem == 'http' then
    function _RESPONSE.exit(status, body, headers)
      if self.worker_events and ngx.get_phase() == "content" then
        self.worker_events.poll()
      end

      check_phase(rewrite_access_header)

      if ngx.headers_sent then
        error("headers have already been sent", 2)
      end

      if type(status) ~= "number" then
        error("code must be a number", 2)

      elseif status < MIN_STATUS_CODE or status > MAX_STATUS_CODE then
        error(fmt("code must be a number between %u and %u", MIN_STATUS_CODE, MAX_STATUS_CODE), 2)
      end

      if body ~= nil and type(body) ~= "string" and type(body) ~= "table" then
        error("body must be a nil, string or table", 2)
      end

      if headers ~= nil and type(headers) ~= "table" then
        error("headers must be a nil or table", 2)
      end

      if headers ~= nil then
        validate_headers(headers)
      end

      local ctx = ngx.ctx
      ctx.KONG_EXITED = true

      if ctx.delay_response and not ctx.delayed_response then
        ctx.delayed_response = {
          status_code = status,
          content     = body,
          headers     = headers,
        }

        ctx.delayed_response_callback = flush
        coroutine.yield()

      else
        return send(status, body, headers)
      end
    end

  else
    local VALID_CODES = {
      [200] = true,
      [400] = true,
      [403] = true,
      [500] = true,
      [502] = true,
      [503] = true,
    }

    function _RESPONSE.exit(status, body, headers)
      if type(status) ~= "number" then
        error("code must be a number", 2)

      elseif not VALID_CODES[status] then
        error("unacceptable code, only 200, 400, 403, 500, 502 and 503 " ..
              "are accepted", 2)
      end

      if body ~= nil and type(body) ~= "string" then
        error("body must be a nil or a string", 2)
      end

      if body then
        if status < 400 then
          -- only sends body to the client for 200 status code
          local res, err = ngx.print(body)
          if not res then
            error("unable to send body to client: " .. err, 2)
          end

        else
          self.log.err("unable to proxy stream connection, " ..
                       "status: " .. status .. ", err: ", body)
        end
      end

      return ngx.exit(status)
    end
  end

  local function get_response_type(content_header)
    local type = CONTENT_TYPE_JSON

    if content_header ~= nil then
      local accept_values = split(content_header, ",")
      local max_quality = 0
      for _, value in ipairs(accept_values) do
        local mimetype_values = split(value, ";")
        local name
        local quality = 1
        for _, entry in ipairs(mimetype_values) do
          local m = ngx.re.match(entry, [[^\s*(\S+\/\S+)\s*$]], "ajo")
          if m then
            name = m[1]
          else
            m = ngx.re.match(entry, [[^\s*q=([0-9]*[\.][0-9]+)\s*$]], "ajoi")
            if m then
              quality = tonumber(m[1])
            end
          end
        end

        if quality > max_quality then
          type = utils.get_mime_type(name)
          max_quality = quality
        end
      end

    end

    return type
  end

  function _RESPONSE.error(status, message, headers)
    if self.worker_events and ngx.get_phase() == "content" then
      self.worker_events.poll()
    end

    check_phase(rewrite_access_header)

    if ngx.headers_sent then
      error("headers have already been sent", 2)
    end

    if type(status) ~= "number" then
      error("code must be a number", 2)

    elseif status < MIN_ERR_STATUS_CODE or status > MAX_STATUS_CODE then
      error(fmt("code must be a number between %u and %u", MIN_ERR_STATUS_CODE,
        MAX_STATUS_CODE), 2)
    end

    if message ~= nil and type(message) ~= "string" then
        error("message must be a nil or a string", 2)
    end

    if headers ~= nil and type(headers) ~= "table" then
      error("headers must be a nil or table", 2)
    end

    if headers ~= nil then
      validate_headers(headers)
    else
      headers = {}
    end

    local content_type_header = headers[CONTENT_TYPE_NAME]
    local content_type = content_type_header and content_type_header[1]
      or content_type_header

    if content_type_header == nil then
      if is_grpc_request() then
        content_type = CONTENT_TYPE_GRPC
      else
        content_type_header = ngx.req.get_headers()[ACCEPT_NAME]
        if type(content_type_header) == "table" then
          content_type_header = content_type_header[1]
        end
        content_type = get_response_type(content_type_header)
      end
    end

    headers[CONTENT_TYPE_NAME] = content_type

    local body
    if content_type ~= CONTENT_TYPE_GRPC then
      local actual_message = message or
                             HTTP_MESSAGES["s" .. status] or
                             fmt(HTTP_MESSAGES.default, status)
      body = fmt(utils.get_error_template(content_type), actual_message)
    end

    local ctx = ngx.ctx

    ctx.KONG_EXITED = true

    if ctx.delay_response and not ctx.delayed_response then
      ctx.delayed_response = {
        status_code = status,
        content     = body,
        headers     = headers,
      }

      ctx.delayed_response_callback = flush
      coroutine.yield()

    else
      return send(status, body, headers)
    end
  end

  return _RESPONSE
end

return {
  new = new,
}
