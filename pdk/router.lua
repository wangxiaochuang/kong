local phase_checker = require "kong.pdk.private.phases"


local ngx = ngx
local check_phase = phase_checker.check


local PHASES = phase_checker.phases
local ROUTER_PHASES = phase_checker.new(PHASES.access,
                                        PHASES.header_filter,
                                        PHASES.response,
                                        PHASES.body_filter,
                                        PHASES.log)

local function new(self)
  local _ROUTER = {}

  function _ROUTER.get_route()
    check_phase(ROUTER_PHASES)

    return ngx.ctx.route
  end

  function _ROUTER.get_service()
    check_phase(ROUTER_PHASES)

    return ngx.ctx.service
  end


  return _ROUTER

end

return {
  new = new,
}
