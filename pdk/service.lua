local balancer = require "kong.runloop.balancer"
local phase_checker = require "kong.pdk.private.phases"


local ngx = ngx
local check_phase = phase_checker.check


local PHASES = phase_checker.phases
local access_and_rewrite_and_balancer =
    phase_checker.new(PHASES.rewrite, PHASES.access, PHASES.balancer)


local function new()
  local service = {}

  function service.set_upstream(host)
    check_phase(PHASES.access)

    if type(host) ~= "string" then
      error("host must be a string", 2)
    end

    local upstream = balancer.get_upstream_by_name(host)
    if not upstream then
      return nil, "could not find an Upstream named '" .. host .. "'"
    end

    ngx.ctx.balancer_data.host = host
    return true
  end

  function service.set_target(host, port)
    check_phase(PHASES.access)

    if type(host) ~= "string" then
      error("host must be a string", 2)
    end
    if type(port) ~= "number" or math.floor(port) ~= port then
      error("port must be an integer", 2)
    end
    if port < 0 or port > 65535 then
      error("port must be an integer between 0 and 65535: given " .. port, 2)
    end

    ngx.var.upstream_host = host

    local ctx = ngx.ctx
    ctx.balancer_data.host = host
    ctx.balancer_data.port = port
  end

  if ngx.config.subsystem == "http" then
    local tls = require("resty.kong.tls")

    local set_upstream_cert_and_key = tls.set_upstream_cert_and_key
    local set_upstream_ssl_verify = tls.set_upstream_ssl_verify
    local set_upstream_ssl_verify_depth = tls.set_upstream_ssl_verify_depth
    local set_upstream_ssl_trusted_store = tls.set_upstream_ssl_trusted_store

    service.set_tls_cert_key = function(chain, key)
      check_phase(access_and_rewrite_and_balancer)

      if type(chain) ~= "cdata" then
        error("chain must be a parsed cdata object", 2)
      end

      if type(key) ~= "cdata" then
        error("key must be a parsed cdata object", 2)
      end

      local res, err = set_upstream_cert_and_key(chain, key)
      return res, err
    end

    service.set_tls_verify = function(on)
      check_phase(access_and_rewrite_and_balancer)

      if type(on) ~= "boolean" then
        error("argument must be a boolean", 2)
      end

      return set_upstream_ssl_verify(on)
    end

    service.set_tls_verify_depth = function(depth)
      check_phase(access_and_rewrite_and_balancer)

      if type(depth) ~= "number" then
        error("argument must be a number", 2)
      end

      return set_upstream_ssl_verify_depth(depth)
    end

    service.set_tls_verify_store = function(store)
      check_phase(access_and_rewrite_and_balancer)

      if type(store) ~= "table" then
        error("argument must be a resty.openssl.x509.store object", 2)
      end

      return set_upstream_ssl_trusted_store(store)
    end
  end

  return service
end

return {
  new = new,
}
