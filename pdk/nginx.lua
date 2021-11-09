local ngx = ngx

local function new(self)
  local _NGINX = {}

  function _NGINX.get_subsystem()
    return ngx.config.subsystem
  end


  return _NGINX
end

return {
  new = new,
}
