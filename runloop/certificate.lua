local singletons = require "kong.singletons"
local ngx_ssl = require "ngx.ssl"
local pl_utils = require "pl.utils"
local mlcache = require "resty.mlcache"
local new_tab = require "table.new"
local openssl_x509_store = require "resty.openssl.x509.store"
local openssl_x509 = require "resty.openssl.x509"

if jit.arch == 'arm64' then
  jit.off(mlcache.get_bulk)        -- "temporary" workaround for issue #5748 on ARM
end

local ngx_log     = ngx.log
local ERR         = ngx.ERR
local DEBUG       = ngx.DEBUG
local re_sub      = ngx.re.sub
local find        = string.find
local server_name = ngx_ssl.server_name
local clear_certs = ngx_ssl.clear_certs
local parse_pem_cert = ngx_ssl.parse_pem_cert
local parse_pem_priv_key = ngx_ssl.parse_pem_priv_key
local set_cert = ngx_ssl.set_cert
local set_priv_key = ngx_ssl.set_priv_key
local tb_concat   = table.concat
local tb_sort   = table.sort
local tostring = tostring
local ipairs = ipairs
local ngx_md5 = ngx.md5


local default_cert_and_key

local DEFAULT_SNI = "*"

local function log(lvl, ...)
  ngx_log(lvl, "[ssl] ", ...)
end

local function parse_key_and_cert(row)
  if row == false then
    return default_cert_and_key
  end

  -- parse cert and priv key for later usage by ngx.ssl

  local cert, err = parse_pem_cert(row.cert)
  if not cert then
    return nil, "could not parse PEM certificate: " .. err
  end

  local key, err = parse_pem_priv_key(row.key)
  if not key then
    return nil, "could not parse PEM private key: " .. err
  end

  local cert_alt
  local key_alt
  if row.cert_alt and row.key_alt then
    cert_alt, err = parse_pem_cert(row.cert_alt)
    if not cert_alt then
      return nil, "could not parse alternate PEM certificate: " .. err
    end

    key_alt, err = parse_pem_priv_key(row.key_alt)
    if not key_alt then
      return nil, "could not parse alternate PEM private key: " .. err
    end
  end

  return {
    cert = cert,
    key = key,
    cert_alt = cert_alt,
    key_alt = key_alt,
  }
end



local function init()
  if singletons.configuration.ssl_cert[1] then
    default_cert_and_key = parse_key_and_cert {
      cert = assert(pl_utils.readfile(singletons.configuration.ssl_cert[1])),
      key = assert(pl_utils.readfile(singletons.configuration.ssl_cert_key[1])),
    }
  end
end

return {
  init = init
}
