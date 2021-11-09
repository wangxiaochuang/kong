local ngx = ngx
local ngx_get_phase = ngx.get_phase


-- shared between all global instances
local _CTX_SHARED_KEY = {}
local _CTX_CORE_KEY = {}


-- dynamic namespaces, also shared between global instances
local _CTX_NAMESPACES_KEY = {}

local function new(self)
  local _CTX = {}
  local _ctx_mt = {}
  local _ns_mt = { __mode = "v" }

  local function get_namespaces(nctx)
    local namespaces = nctx[_CTX_NAMESPACES_KEY]
    if not namespaces then
      namespaces = self.table.new(0, 4)
      nctx[_CTX_NAMESPACES_KEY] = setmetatable(namespaces, _ns_mt)
    end

    return namespaces
  end

  local function set_namespace(namespace, namespace_key)
    local nctx = ngx.ctx
    local namespaces = get_namespaces(nctx)

    local ns = namespaces[namespace]
    if ns and ns == namespace_key then
      return
    end

    namespaces[namespace] = namespace_key
  end

  local function del_namespace(namespace)
    local nctx = ngx.ctx
    local namespaces = get_namespaces(nctx)
    namespaces[namespace] = nil
  end

  function _ctx_mt.__index(t, k)
    if k == "__set_namespace" then
      return set_namespace

    elseif k == "__del_namespace" then
      return del_namespace
    end

    if ngx_get_phase() == "init" then
      return
    end

    local nctx = ngx.ctx
    local key

    if k == "core" then
      key = _CTX_CORE_KEY
    elseif k == "shared" then
      key = _CTX_SHARED_KEY
    else
      local namespaces = get_namespaces(nctx)
      key = namespaces[k]
    end

    if key then
      local ctx = nctx[key]
      if not ctx then
        ctx = {}
        nctx[key] = ctx
      end

      return ctx
    end
  end

  return setmetatable(_CTX, _ctx_mt)
end

return {
  new = new,
}
