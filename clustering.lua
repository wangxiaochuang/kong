local _M = {}

function _M.init(conf)
  assert(conf, "conf can not be nil", 2)

  if conf.role ~= "data_plane" and conf.role ~= "control_plane" then
    return
  end

  error("in init")
end

return _M
