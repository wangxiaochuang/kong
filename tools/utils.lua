local ffi = require "ffi"
local uuid = require "resty.jit-uuid"
local pl_stringx = require "pl.stringx"
local pl_stringio = require "pl.stringio"
local pl_utils = require "pl.utils"
local pl_path = require "pl.path"
local zlib = require "ffi-zlib"

local C             = ffi.C
local ffi_fill      = ffi.fill
local ffi_new       = ffi.new
local ffi_str       = ffi.string
local type          = type
local pairs         = pairs
local ipairs        = ipairs
local select        = select
local tostring      = tostring
local sort          = table.sort
local concat        = table.concat
local insert        = table.insert
local lower         = string.lower
local fmt           = string.format
local find          = string.find
local gsub          = string.gsub
local split         = pl_stringx.split
local re_find       = ngx.re.find
local re_match      = ngx.re.match
local inflate_gzip  = zlib.inflateGzip
local deflate_gzip  = zlib.deflateGzip
local stringio_open = pl_stringio.open

ffi.cdef[[
typedef unsigned char u_char;

int gethostname(char *name, size_t len);

int RAND_bytes(u_char *buf, int num);

unsigned long ERR_get_error(void);
void ERR_load_crypto_strings(void);
void ERR_free_strings(void);

const char *ERR_reason_error_string(unsigned long e);

int open(const char * filename, int flags, int mode);
size_t read(int fd, void *buf, size_t count);
int write(int fd, const void *ptr, int numbytes);
int close(int fd);
char *strerror(int errnum);
]]

local _M = {}

_M.split = split

_M.strip = function(str)
  if str == nil then
    return ""
  end
  str = tostring(str)
  if #str > 200 then
    return str:gsub("^%s+", ""):reverse():gsub("^%s+", ""):reverse()
  else
    return str:match("^%s*(.-)%s*$")
  end
end

_M.pack = function(...) return {n = select("#", ...), ...} end

_M.unpack = function(t, i, j) return unpack(t, i or 1, j or t.n or #t) end

do
  local _system_infos
  function _M.get_system_infos()
    if _system_infos then
      return _system_infos
    end

    _system_infos = {}

    local ok, _, stdout = pl_utils.executeex("getconf _NPROCESSORS_ONLN")
    if ok then
      _system_infos.cores = tonumber(stdout:sub(1, -2))
    end

    ok, _, stdout = pl_utils.executeex("uname -ms")
    if ok then
      _system_infos.uname = stdout:gsub(";", ","):sub(1, -2)
    end

    return _system_infos
  end
end

do
  local trusted_certs_paths = {
    "/etc/ssl/certs/ca-certificates.crt",                -- Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",                  -- Fedora/RHEL 6
    "/etc/ssl/ca-bundle.pem",                            -- OpenSUSE
    "/etc/pki/tls/cacert.pem",                           -- OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", -- CentOS/RHEL 7
    "/etc/ssl/cert.pem",                                 -- OpenBSD, Alpine
  }  

  function _M.get_system_trusted_certs_filepath()
    for _, path in ipairs(trusted_certs_paths) do
      if pl_path.exists(path) then
        return path
      end
    end

    return nil,
           "Could not find trusted certs file in " ..
           "any of the `system`-predefined locations. " ..
           "Please install a certs file there or set " ..
           "lua_ssl_trusted_certificate to an " ..
           "specific filepath instead of `system`"
  end
end

local get_rand_bytes

do
  local ngx_log = ngx.log
  local WARN    = ngx.WARN

  local system_constants = require "lua_system_constants"
  local O_RDONLY = system_constants.O_RDONLY()
  local bytes_buf_t = ffi.typeof "char[?]"

  local function urandom_bytes(buf, size)
    local fd = ffi.C.open("/dev/urandom", O_RDONLY, 0)
    if fd < 0 then
      ngx_log(WARN, "Error opening random fd: ",
                    ffi_str(ffi.C.strerror(ffi.errno())))

      return false
    end

    local res = ffi.C.read(fd, buf, size)
    if res <= 0 then
      ngx_log(WARN, "Error reading from urandom: ",
                    ffi_str(ffi.C.strerror(ffi.errno())))

      return false
    end

    if ffi.C.close(fd) ~= 0 then
      ngx_log(WARN, "Error closing urandom: ",
                    ffi_str(ffi.C.strerror(ffi.errno())))
    end

    return true
  end

  get_rand_bytes = function(n_bytes, urandom)
    local buf = ffi_new(bytes_buf_t, n_bytes)
    ffi_fill(buf, n_bytes, 0x0)

    if urandom then
      local rc = urandom_bytes(buf, n_bytes)

      if rc then
        return ffi_str(buf, n_bytes)
      end
    end

    if C.RAND_bytes(buf, n_bytes) == 0 then
      -- get error code
      local err_code = C.ERR_get_error()
      if err_code == 0 then
        return nil, "could not get SSL error code from the queue"
      end

      -- get human-readable error string
      C.ERR_load_crypto_strings()
      local err = C.ERR_reason_error_string(err_code)
      C.ERR_free_strings()

      return nil, "could not get random bytes (" ..
                  "reason:" .. ffi_str(err) .. ") "
    end

    return ffi_str(buf, n_bytes)
  end

  _M.get_rand_bytes = get_rand_bytes
end

_M.uuid = uuid.generate_v4

do
  local char = string.char
  local rand = math.random
  local encode_base64 = ngx.encode_base64

  local function random_string()
    return encode_base64(get_rand_bytes(24, true))
           :gsub("/", char(rand(48, 57)))  -- 0 - 10
           :gsub("+", char(rand(65, 90)))  -- A - Z
           :gsub("=", char(rand(97, 122))) -- a - z
  end

  _M.random_string = random_string
end

local uuid_regex = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
function _M.is_valid_uuid(str)
  if type(str) ~= 'string' or #str ~= 36 then
    return false
  end
  return re_find(str, uuid_regex, 'ioj') ~= nil
end

do
  local url = require "socket.url"
  local function encode_args_value(key, value, raw)
    if not raw then
      key = url.escape(key)
    end
    if value ~= nil then
      if not raw then
        value = url.escape(value)
      end
      return fmt("%s=%s", key, value)
    else
      return key
    end
  end

  local function compare_keys(a, b)
    local ta = type(a)
    if ta == type(b) then
      return a < b
    end
    return ta == "number"
  end

  local function recursive_encode_args(parent_key, value, raw, no_array_indexes, query)
    local sub_keys = {}
    for sk in pairs(value) do
      sub_keys[#sub_keys + 1] = sk
    end
    sort(sub_keys, compare_keys)

    local sub_value, next_sub_key
    for _, sub_key in ipairs(sub_keys) do
      sub_value = value[sub_key]

      if type(sub_key) == "number" then
        if no_array_indexes then
          next_sub_key = parent_key .. "[]"
        else
          next_sub_key = ("%s[%s]"):format(parent_key, tostring(sub_key))
        end
      else
        next_sub_key = ("%s.%s"):format(parent_key, tostring(sub_key))
      end

      if type(sub_value) == "table" then
        recursive_encode_args(next_sub_key, sub_value, raw, no_array_indexes, query)
      else
        query[#query+1] = encode_args_value(next_sub_key, sub_value, raw)
      end
    end
  end

  function _M.encode_args(args, raw, no_array_indexes)
    local query = {}
    local keys = {}

    for k in pairs(args) do
      keys[#keys+1] = k
    end

    sort(keys, compare_keys)

    for _, key in ipairs(keys) do
      local value = args[key]
      if type(value) == "table" then
        recursive_encode_args(key, value, raw, no_array_indexes, query)
      elseif value == ngx.null then
        query[#query+1] = encode_args_value(key, "")
      elseif  value ~= nil or raw then
        value = tostring(value)
        if value ~= "" then
          query[#query+1] = encode_args_value(key, value, raw)
        elseif raw or value == "" then
          query[#query+1] = key
        end
      end
    end

    return concat(query, "&")
  end

  local function decode_array(t)
    local keys = {}
    local len  = 0
    for k in pairs(t) do
      len = len + 1
      local number = tonumber(k)
      if not number then
        return nil
      end
      keys[len] = number
    end

    table.sort(keys)
    local new_t = {}

    for i=1,len do
      if keys[i] ~= i then
        return nil
      end
      new_t[i] = t[tostring(i)]
    end

    return new_t
  end

  function _M.decode_args(args)
    local new_args = {}

    for k, v in pairs(args) do
      if type(v) == "table" then
        v = decode_array(v) or v
      elseif v == "" then
        v = ngx.null
      elseif v == "true" then
        v = true
      elseif v == "false" then
        v = false
      end
      new_args[k] = v
    end

    return new_args
  end
end

_M.check_https = function(trusted_ip, allow_terminated)
  if ngx.var.scheme:lower() == "https" then
    return true
  end

  if not allow_terminated then
    return false
  end

  if trusted_ip then
    local scheme = ngx.req.get_headers()["x-forwarded-proto"]

    if type(scheme) == "table" then
      return nil, "Only one X-Forwarded-Proto header allowed"
    end

    return tostring(scheme):lower() == "https"
  end

  return false
end

function _M.table_merge(t1, t2)
  if not t1 then
    t1 = {}
  end
  if not t2 then
    t2 = {}
  end

  local res = {}
  for k,v in pairs(t1) do res[k] = v end
  for k,v in pairs(t2) do res[k] = v end
  return res
end

function _M.table_contains(arr, val)
  if arr then
    for _, v in pairs(arr) do
      if v == val then
        return true
      end
    end
  end
  return false
end

do
  local floor = math.floor
  local max = math.max

  local ok, is_array_fast = pcall(require, "table.isarray")
  if not ok then
    is_array_fast = function(t)
      for k in pairs(t) do
          if type(k) ~= "number" or floor(k) ~= k then
            return false
          end
      end
      return true
    end
  end

  local is_array_strict = function(t)
    local m, c = 0, 0
    for k in pairs(t) do
        if type(k) ~= "number" or k < 1 or floor(k) ~= k then
          return false
        end
        m = max(m, k)
        c = c + 1
    end
    return c == m
  end

  local is_array_lapis = function(t)
    if type(t) ~= "table" then
      return false
    end
    local i = 0
    for _ in pairs(t) do
      i = i + 1
      if t[i] == nil and t[tostring(i)] == nil then
        return false
      end
    end
    return true
  end

  function _M.is_array(t, mode)
    if type(t) ~= "table" then
      return false
    end

    if mode == "lapis" then
      return is_array_lapis(t)
    end

    if mode == "fast" then
      return is_array_fast(t)
    end

    return is_array_strict(t)
  end
end

function _M.is_lapis_array(t)
  if type(t) ~= "table" then
    return false
  end
  local i = 0
  for _ in pairs(t) do
    i = i + 1
    if t[i] == nil and t[tostring(i)] == nil then
      return false
    end
  end
  return true
end

function _M.deep_copy(orig, copy_mt)
  if copy_mt == nil then
    copy_mt = true
  end
  local copy
  if type(orig) == "table" then
    copy = {}
    for orig_key, orig_value in next, orig, nil do
      copy[_M.deep_copy(orig_key)] = _M.deep_copy(orig_value, copy_mt)
    end
    if copy_mt then
      setmetatable(copy, _M.deep_copy(getmetatable(orig)))
    end
  else
    copy = orig
  end
  return copy
end

do
  local ok, clone = pcall(require, "table.clone")
  if not ok then
    clone = function(t)
      local copy = {}
      for key, value in pairs(t) do
        copy[key] = value
      end
      return copy
    end
  end

  function _M.shallow_copy(orig)
    local copy
    if type(orig) == "table" then
      copy = clone(orig)
    else -- number, string, boolean, etc
      copy = orig
    end
    return copy
  end
end

function _M.deep_merge(t1, t2)
  local res = _M.deep_copy(t1)

  for k, v in pairs(t2) do
    if type(v) == "table" and type(res[k]) == "table" then
      res[k] = _M.deep_merge(res[k], v)
    else
      res[k] = _M.deep_copy(v) -- returns v when it is not a table
    end
  end

  return res
end

local err_list_mt = {}

function _M.concat(...)
  local result = {}
  local insert = table.insert
  for _, t in ipairs({...}) do
    for _, v in ipairs(t) do insert(result, v) end
  end
  return result
end

function _M.add_error(errors, k, v)
  if not errors then
    errors = {}
  end

  if errors and errors[k] then
    if getmetatable(errors[k]) ~= err_list_mt then
      errors[k] = setmetatable({errors[k]}, err_list_mt)
    end

    insert(errors[k], v)
  else
    errors[k] = v
  end

  return errors
end

function _M.load_module_if_exists(module_name)
  local status, res = xpcall(require, debug.traceback, module_name)
  if status then
    return true, res
  elseif type(res) == "string" and find(res, "module '" .. module_name .. "' not found", nil, true) then
    return false, res
  else
    error("error loading module '" .. module_name .. "':\n" .. res)
  end
end

function _M.validate_utf8(val)
  local str = tostring(val)
  local i, len = 1, #str
  while i <= len do
    if     i == find(str, "[%z\1-\127]", i) then i = i + 1
    elseif i == find(str, "[\194-\223][\123-\191]", i) then i = i + 2
    elseif i == find(str,        "\224[\160-\191][\128-\191]", i)
        or i == find(str, "[\225-\236][\128-\191][\128-\191]", i)
        or i == find(str,        "\237[\128-\159][\128-\191]", i)
        or i == find(str, "[\238-\239][\128-\191][\128-\191]", i) then i = i + 3
    elseif i == find(str,        "\240[\144-\191][\128-\191][\128-\191]", i)
        or i == find(str, "[\241-\243][\128-\191][\128-\191][\128-\191]", i)
        or i == find(str,        "\244[\128-\143][\128-\191][\128-\191]", i) then i = i + 4
    else
      return false, i
    end
  end

  return true
end

do
  local ipmatcher =  require "resty.ipmatcher"
  local sub = string.sub

  local ipv4_prefixes = {}
  for i = 0, 32 do
    ipv4_prefixes[tostring(i)] = i
  end

  local ipv6_prefixes = {}
  for i = 0, 128 do
    ipv6_prefixes[tostring(i)] = i
  end

  local function split_cidr(cidr, prefixes)
    local p = find(cidr, "/", 3, true)
    if not p then
      return
    end

    return sub(cidr, 1, p - 1), prefixes[sub(cidr, p + 1)]
  end

  local validate = function(input, f1, f2, prefixes)
    if type(input) ~= "string" then
      return false
    end

    if prefixes then
      local ip, prefix = split_cidr(input, prefixes)
      if not ip or not prefix then
        return false
      end

      input = ip
    end

    if f1(input) then
      return true
    end

    if f2 and f2(input) then
      return true
    end

    return false
  end

  _M.is_valid_ipv4 = function(ipv4)
    return validate(ipv4, ipmatcher.parse_ipv4)
  end

  _M.is_valid_ipv6 = function(ipv6)
    return validate(ipv6, ipmatcher.parse_ipv6)
  end

  _M.is_valid_ip = function(ip)
    return validate(ip, ipmatcher.parse_ipv4, ipmatcher.parse_ipv6)
  end

  _M.is_valid_cidr_v4 = function(cidr_v4)
    return validate(cidr_v4, ipmatcher.parse_ipv4, nil, ipv4_prefixes)
  end

  _M.is_valid_cidr_v6 = function(cidr_v6)
    return validate(cidr_v6, ipmatcher.parse_ipv6, nil, ipv6_prefixes)
  end

  _M.is_valid_cidr = function(cidr)
    return validate(cidr, _M.is_valid_cidr_v4, _M.is_valid_cidr_v6)
  end

  _M.is_valid_ip_or_cidr_v4 = function(ip_or_cidr_v4)
    return validate(ip_or_cidr_v4, ipmatcher.parse_ipv4, _M.is_valid_cidr_v4)
  end

  _M.is_valid_ip_or_cidr_v6 = function(ip_or_cidr_v6)
    return validate(ip_or_cidr_v6, ipmatcher.parse_ipv6, _M.is_valid_cidr_v6)
  end

  _M.is_valid_ip_or_cidr = function(ip_or_cidr)
    return validate(ip_or_cidr, _M.is_valid_ip,  _M.is_valid_cidr)
  end
end

_M.hostname_type = function(name)
  local remainder, colons = gsub(name, ":", "")
  if colons > 1 then
    return "ipv6"
  end
  if remainder:match("^[%d%.]+$") then
    return "ipv4"
  end
  return "name"
end

_M.normalize_ipv4 = function(address)
  local a,b,c,d,port
  if address:find(":") then
    -- has port number
    a,b,c,d,port = address:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?):(%d+)$")
  else
    -- without port number
    a,b,c,d,port = address:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
  end
  if not a then
    return nil, "invalid ipv4 address: " .. address
  end
  a,b,c,d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if a < 0 or a > 255 or b < 0 or b > 255 or c < 0 or
     c > 255 or d < 0 or d > 255 then
    return nil, "invalid ipv4 address: " .. address
  end
  if port then
    port = tonumber(port)
    if port > 65535 then
      return nil, "invalid port number"
    end
  end

  return fmt("%d.%d.%d.%d",a,b,c,d), port
end

_M.normalize_ipv6 = function(address)
  local check, port = address:match("^(%b[])(.-)$")
  if port == "" then
    port = nil
  end
  if check then
    check = check:sub(2, -2)  -- drop the brackets
    -- we have ipv6 in brackets, now get port if we got something left
    if port then
      port = port:match("^:(%d-)$")
      if not port then
        return nil, "invalid ipv6 address"
      end
      port = tonumber(port)
      if port > 65535 then
        return nil, "invalid port number"
      end
    end
  else
    -- no brackets, so full address only; no brackets, no port
    check = address
    port = nil
  end
  -- check ipv6 format and normalize
  if check:sub(1,1) == ":" then
    check = "0" .. check
  end
  if check:sub(-1,-1) == ":" then
    check = check .. "0"
  end
  if check:find("::") then
    -- expand double colon
    local _, count = gsub(check, ":", "")
    local ins = ":" .. string.rep("0:", 8 - count)
    check = gsub(check, "::", ins, 1)  -- replace only 1 occurence!
  end
  local a,b,c,d,e,f,g,h = check:match("^(%x%x?%x?%x?):(%x%x?%x?%x?):(%x%x?%x?%x?):(%x%x?%x?%x?):(%x%x?%x?%x?):(%x%x?%x?%x?):(%x%x?%x?%x?):(%x%x?%x?%x?)$")
  if not a then
    -- not a valid IPv6 address
    return nil, "invalid ipv6 address: " .. address
  end
  local zeros = "0000"
  return lower(fmt("%s:%s:%s:%s:%s:%s:%s:%s",
      zeros:sub(1, 4 - #a) .. a,
      zeros:sub(1, 4 - #b) .. b,
      zeros:sub(1, 4 - #c) .. c,
      zeros:sub(1, 4 - #d) .. d,
      zeros:sub(1, 4 - #e) .. e,
      zeros:sub(1, 4 - #f) .. f,
      zeros:sub(1, 4 - #g) .. g,
      zeros:sub(1, 4 - #h) .. h)), port
end

_M.check_hostname = function(address)
  local name = address
  local port = address:match(":(%d+)$")
  if port then
    name = name:sub(1, -(#port+2))
    port = tonumber(port)
    if port > 65535 then
      return nil, "invalid port number"
    end
  end
  local match = name:match("^[%d%a%-%.%_]+$")
  if match == nil then
    return nil, "invalid hostname: " .. address
  end

  for index, segment in ipairs(split(name, ".")) do
    if segment:match("-$") or segment:match("^%.") or segment:match("%.$") or
       (segment == "" and index ~= #split(name, ".")) then
      return nil, "invalid hostname: " .. address
    end
  end
  return name, port
end

local verify_types = {
  ipv4 = _M.normalize_ipv4,
  ipv6 = _M.normalize_ipv6,
  name = _M.check_hostname,
}

_M.normalize_ip = function(address)
  local atype = _M.hostname_type(address)
  local addr, port = verify_types[atype](address)
  if not addr then
    return nil, port
  end
  return {
    type = atype,
    host = addr,
    port = port
  }
end

_M.format_host = function(p1, p2)
  local t = type(p1)
  if t == "nil" then
    return p1, p2   -- just pass through any errors passed in
  end
  local host, port, typ
  if t == "table" then
    port = p1.port or p2
    host = p1.host
    typ = p1.type or _M.hostname_type(host)
  elseif t == "string" then
    port = p2
    host = p1
    typ = _M.hostname_type(host)
  else
    return nil, "cannot format type '" .. t .. "'"
  end
  if typ == "ipv6" and not find(host, "[", nil, true) then
    return "[" .. _M.normalize_ipv6(host) .. "]" .. (port and ":" .. port or "")
  else
    return host ..  (port and ":" .. port or "")
  end
end

_M.validate_header_name = function(name)
  if name == nil or name == "" then
    return nil, "no header name provided"
  end

  if re_match(name, "^[a-zA-Z0-9-_]+$", "jo") then
    return name
  end

  return nil, "bad header name '" .. name ..
              "', allowed characters are A-Z, a-z, 0-9, '_', and '-'"
end

_M.validate_cookie_name = function(name)
  if name == nil or name == "" then
    return nil, "no cookie name provided"
  end

  if re_match(name, "^[a-zA-Z0-9-_]+$", "jo") then
    return name
  end

  return nil, "bad cookie name '" .. name ..
              "', allowed characters are A-Z, a-z, 0-9, '_', and '-'"
end

do
  local _overrides = {
    [405] = "Method not allowed",
    [500] = "An unexpected error occurred",
    [502] = "Bad gateway",
  }

  local _defaults = {
    [401] = "Unauthorized",
    [404] = "Not found",
    [503] = "Service unavailable",
  }

  local MIN_STATUS_CODE      = 100
  local MAX_STATUS_CODE      = 599

  function _M.get_default_exit_body(status, message)
    if type(status) ~= "number" then
      error("code must be a number", 2)

    elseif status < MIN_STATUS_CODE or status > MAX_STATUS_CODE then
      error(fmt("code must be a number between %u and %u", MIN_STATUS_CODE, MAX_STATUS_CODE), 2)
    end

    if status == 204 then
      return nil
    end

    local body = _overrides[status] or message or _defaults[status]
    if body ~= nil and type(body) ~= "table" then
      body = { message = body }
    end

    return body
  end
end

function _M.bytes_to_str(bytes, unit, scale)
  if not unit or unit == "" or lower(unit) == "b" then
    return fmt("%d", bytes)
  end

  scale = scale or 2

  if type(scale) ~= "number" or scale < 0 then
    error("scale must be equal or greater than 0", 2)
  end

  local fspec = fmt("%%.%df", scale)

  if lower(unit) == "k" then
    return fmt(fspec .. " KiB", bytes / 2^10)
  end

  if lower(unit) == "m" then
    return fmt(fspec .. " MiB", bytes / 2^20)
  end

  if lower(unit) == "g" then
    return fmt(fspec .. " GiB", bytes / 2^30)
  end

  error("invalid unit '" .. unit .. "' (expected 'k/K', 'm/M', or 'g/G')", 2)
end

do
  local NGX_ERROR = ngx.ERROR

  if not pcall(ffi.typeof, "ngx_uint_t") then
    ffi.cdef [[
      typedef uintptr_t ngx_uint_t;
    ]]
  end

  -- ngx_str_t defined by lua-resty-core
  local s = ffi.new("ngx_str_t[1]")
  s[0].data = "10"
  s[0].len = 2

  if not pcall(function() C.ngx_parse_time(s, 0) end) then
    ffi.cdef [[
      ngx_int_t ngx_parse_time(ngx_str_t *line, ngx_uint_t is_sec);
    ]]
  end

  function _M.nginx_conf_time_to_seconds(str)
    s[0].data = str
    s[0].len = #str

    local ret = C.ngx_parse_time(s, 1)
    if ret == NGX_ERROR then
      error("bad argument #1 'str'", 2)
    end

    return tonumber(ret, 10)
  end
end

do
  -- lua-ffi-zlib allocated buffer of length +1,
  -- so use 64KB - 1 instead
  local GZIP_CHUNK_SIZE = 65535

  local function gzip_helper(op, input)
    local f = stringio_open(input)
    local output_table = {}
    local output_table_n = 0

    local res, err = op(function(size)
      return f:read(size)
    end,
    function(res)
      output_table_n = output_table_n + 1
      output_table[output_table_n] = res
    end, GZIP_CHUNK_SIZE)

    if not res then
      return nil, err
    end

    return concat(output_table)
  end

  function _M.deflate_gzip(str)
    return gzip_helper(deflate_gzip, str)
  end


  function _M.inflate_gzip(gz)
    return gzip_helper(inflate_gzip, gz)
  end
end

local get_mime_type
local get_error_template
do
  local CONTENT_TYPE_JSON    = "application/json"
  local CONTENT_TYPE_GRPC    = "application/grpc"
  local CONTENT_TYPE_HTML    = "text/html"
  local CONTENT_TYPE_XML     = "application/xml"
  local CONTENT_TYPE_PLAIN   = "text/plain"
  local CONTENT_TYPE_APP     = "application"
  local CONTENT_TYPE_TEXT    = "text"
  local CONTENT_TYPE_DEFAULT = "default"
  local CONTENT_TYPE_ANY     = "*"

  local MIME_TYPES = {
    [CONTENT_TYPE_GRPC]     = "",
    [CONTENT_TYPE_HTML]     = "text/html; charset=utf-8",
    [CONTENT_TYPE_JSON]     = "application/json; charset=utf-8",
    [CONTENT_TYPE_PLAIN]    = "text/plain; charset=utf-8",
    [CONTENT_TYPE_XML]      = "application/xml; charset=utf-8",
    [CONTENT_TYPE_APP]      = "application/json; charset=utf-8",
    [CONTENT_TYPE_TEXT]     = "text/plain; charset=utf-8",
    [CONTENT_TYPE_DEFAULT]  = "application/json; charset=utf-8",
  }

  local ERROR_TEMPLATES = {
    [CONTENT_TYPE_GRPC]   = "",
    [CONTENT_TYPE_HTML]   = [[
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Kong Error</title>
  </head>
  <body>
    <h1>Kong Error</h1>
    <p>%s.</p>
  </body>
</html>
]],
    [CONTENT_TYPE_JSON]   = [[
{
  "message":"%s"
}]],
    [CONTENT_TYPE_PLAIN]  = "%s\n",
    [CONTENT_TYPE_XML]    = [[
<?xml version="1.0" encoding="UTF-8"?>
<error>
  <message>%s</message>
</error>
]],
  }

  get_mime_type = function(content_header, use_default)
    use_default = use_default == nil or use_default
    content_header = _M.strip(content_header)
    content_header = _M.split(content_header, ";")[1]
    local mime_type

    local entries = split(content_header, "/")
    if #entries > 1 then
      if entries[2] == CONTENT_TYPE_ANY then
        if entries[1] == CONTENT_TYPE_ANY then
          mime_type = MIME_TYPES["default"]
        else
          mime_type = MIME_TYPES[entries[1]]
        end
      else
        mime_type = MIME_TYPES[content_header]
      end
    end

    if mime_type or use_default then
      return mime_type or MIME_TYPES["default"]
    end

    return nil, "could not find MIME type"
  end

  get_error_template = function(mime_type)
    if mime_type == CONTENT_TYPE_JSON or mime_type == MIME_TYPES[CONTENT_TYPE_JSON] then
      return ERROR_TEMPLATES[CONTENT_TYPE_JSON]

    elseif mime_type == CONTENT_TYPE_HTML or mime_type == MIME_TYPES[CONTENT_TYPE_HTML] then
      return ERROR_TEMPLATES[CONTENT_TYPE_HTML]

    elseif mime_type == CONTENT_TYPE_XML or mime_type == MIME_TYPES[CONTENT_TYPE_XML] then
      return ERROR_TEMPLATES[CONTENT_TYPE_XML]

    elseif mime_type == CONTENT_TYPE_PLAIN or mime_type == MIME_TYPES[CONTENT_TYPE_PLAIN] then
      return ERROR_TEMPLATES[CONTENT_TYPE_PLAIN]

    elseif mime_type == CONTENT_TYPE_GRPC or mime_type == MIME_TYPES[CONTENT_TYPE_GRPC] then
      return ERROR_TEMPLATES[CONTENT_TYPE_GRPC]

    end

    return nil, "no template found for MIME type " .. (mime_type or "empty")
  end

end
_M.get_mime_type = get_mime_type
_M.get_error_template = get_error_template


local topological_sort do

  local function visit(current, neighbors_map, visited, marked, sorted)
    if visited[current] then
      return true
    end

    if marked[current] then
      return nil, "Cycle detected, cannot sort topologically"
    end

    marked[current] = true

    local schemas_pointing_to_current = neighbors_map[current]
    if schemas_pointing_to_current then
      local neighbor, ok, err
      for i = 1, #schemas_pointing_to_current do
        neighbor = schemas_pointing_to_current[i]
        ok, err = visit(neighbor, neighbors_map, visited, marked, sorted)
        if not ok then
          return nil, err
        end
      end
    end
    marked[current] = false

    visited[current] = true

    insert(sorted, 1, current)

    return true
  end

  topological_sort = function(items, get_neighbors)
    local neighbors_map = {}
    local source, destination
    local neighbors
    for i = 1, #items do
      source = items[i] -- services
      neighbors = get_neighbors(source)
      for j = 1, #neighbors do
        destination = neighbors[j] --routes
        neighbors_map[destination] = neighbors_map[destination] or {}
        insert(neighbors_map[destination], source)
      end
    end

    local sorted = {}
    local visited = {}
    local marked = {}

    local current, ok, err
    for i = 1, #items do
      current = items[i]
      if not visited[current] and not marked[current] then
        ok, err = visit(current, neighbors_map, visited, marked, sorted)
        if not ok then
          return nil, err
        end
      end
    end

    return sorted
  end
end
_M.topological_sort = topological_sort

return _M
