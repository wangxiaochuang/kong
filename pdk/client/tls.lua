local phase_checker = require "kong.pdk.private.phases"
local kong_tls = require "resty.kong.tls"


local check_phase = phase_checker.check
local error = error
local type = type
local ngx = ngx


local PHASES = phase_checker.phases
local REWRITE_AND_LATER = phase_checker.new(PHASES.rewrite,
                                            PHASES.access,
                                            PHASES.response,
                                            PHASES.balancer,
                                            PHASES.log)
local REWRITE_BEFORE_LOG = phase_checker.new(PHASES.rewrite,
                                             PHASES.access,
                                             PHASES.response,
                                             PHASES.balancer)

local function new()
  local _TLS = {}

  function _TLS.request_client_certificate()
    check_phase(PHASES.certificate)

    return kong_tls.request_client_certificate()
  end

  function _TLS.disable_session_reuse()
    check_phase(PHASES.certificate)

    return kong_tls.disable_session_reuse()
  end

  function _TLS.get_full_client_certificate_chain()
    check_phase(REWRITE_AND_LATER)

    return kong_tls.get_full_client_certificate_chain()
  end

  function _TLS.set_client_verify(v)
    check_phase(REWRITE_BEFORE_LOG)

    assert(type(v) == "string")

    if v ~= "SUCCESS" and v ~= "NONE" and v:sub(1, 7) ~= "FAILED:" then
      error("unknown client verify value: " .. tostring(v) ..
            " accepted values are: \"SUCCESS\", \"NONE\"" ..
            " or \"FAILED:<reason>\"", 2)
    end

    ngx.ctx.CLIENT_VERIFY_OVERRIDE = v
  end

  return _TLS
end

return {
  new = new,
}
