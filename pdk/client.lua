local utils = require "kong.tools.utils"
local phase_checker = require "kong.pdk.private.phases"


local ngx = ngx
local tonumber = tonumber
local check_phase = phase_checker.check
local check_not_phase = phase_checker.check_not


local PHASES = phase_checker.phases
local AUTH_AND_LATER = phase_checker.new(PHASES.access,
                                         PHASES.header_filter,
                                         PHASES.response,
                                         PHASES.body_filter,
                                         PHASES.log)

local TABLE_OR_NIL = { ["table"] = true, ["nil"] = true }

local function new(self)
  local _CLIENT = {}

  function _CLIENT.get_ip()
    check_not_phase(PHASES.init_worker)
    return ngx.var.realip_remote_addr or ngx.var.remote_addr
  end

  function _CLIENT.get_forwarded_ip()
    check_not_phase(PHASES.init_worker)

    return ngx.var.remote_addr
  end

  function _CLIENT.get_port()
    check_not_phase(PHASES.init_worker)

    return tonumber(ngx.var.realip_remote_port or ngx.var.remote_port)
  end

  function _CLIENT.get_forwarded_port()
    check_not_phase(PHASES.init_worker)

    return tonumber(ngx.var.remote_port)
  end

  function _CLIENT.get_credential()
    check_phase(AUTH_AND_LATER)

    return ngx.ctx.authenticated_credential
  end

  function _CLIENT.load_consumer(consumer_id, search_by_username)
    check_phase(AUTH_AND_LATER)

    if not consumer_id or type(consumer_id) ~= "string" then
      error("consumer_id must be a string", 2)
    end

    if not utils.is_valid_uuid(consumer_id) and not search_by_username then
      error("cannot load a consumer with an id that is not a uuid", 2)
    end

    if utils.is_valid_uuid(consumer_id) then
      local result, err = kong.db.consumers:select { id = consumer_id }
      if result then
        return result
      end

      if err then
        return nil, err
      end
    end
    
    if search_by_username then
      return kong.db.consumers:select_by_username(consumer_id)
    end

  end

  function _CLIENT.get_consumer()
    check_phase(AUTH_AND_LATER)

    return ngx.ctx.authenticated_consumer
  end

  function _CLIENT.authenticate(consumer, credential)
    check_phase(PHASES.access)

    if not TABLE_OR_NIL[type(consumer)] then
      error("consumer must be a table or nil", 2)
    elseif not TABLE_OR_NIL[type(credential)] then
      error("credential must be a table or nil", 2)
    elseif credential == nil and consumer == nil then
      error("either credential or consumer must be provided", 2)
    end

    local ctx = ngx.ctx
    ctx.authenticated_consumer = consumer
    ctx.authenticated_credential = credential
  end

  function _CLIENT.get_protocol(allow_terminated)
    check_phase(AUTH_AND_LATER)

    local route = ngx.ctx.route
    if not route then
      return nil, "No active route found"
    end

    local protocols = route.protocols
    if #protocols == 1 then
      return protocols[1]
    end

    if ngx.config.subsystem == "http" then
      local is_trusted = self.ip.is_trusted(self.client.get_ip())
      local is_https, err = utils.check_https(is_trusted, allow_terminated)
      if err then
        return nil, err
      end

      return is_https and "https" or "http"
    end

    local balancer_data = ngx.ctx.balancer_data
    local is_tls = balancer_data and balancer_data.scheme == "tls"

    return is_tls and "tls" or "tcp"
  end

  return _CLIENT
end

return {
  new = new,
}
