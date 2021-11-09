local kong = kong
local CLUSTER_ID_PARAM_KEY = require("kong.constants").CLUSTER_ID_PARAM_KEY

local function fetch_cluster_id()
  local res, err = kong.db.parameters:select({ key = CLUSTER_ID_PARAM_KEY, })
  if not res then
    return nil, err
  end

  return res.value
end

local function new(self)
  local _CLUSTER = {}

  function _CLUSTER.get_id()
    return kong.core_cache:get(CLUSTER_ID_PARAM_KEY, nil, fetch_cluster_id)
  end


  return _CLUSTER
end

return {
  new = new,
}
