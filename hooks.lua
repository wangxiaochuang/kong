local _M = {}

local hooks = {}

local ipairs = ipairs
local pack = table.pack
local unpack = table.unpack
local insert = table.insert

local function wrap_hook(f)
  return function(acc, ...)
    if acc and not acc[1] then
      return acc
    end
    return pack(f(...))
  end
end

function _M.register_hook(name, hook, opts)
  assert(type(hook) == "function", "hook must be a function")

  hooks[name] = hooks[name] or {}

  local f
  if opts and opts.low_level then
    f = hook
  else
    f = wrap_hook(hook)
  end

  insert(hooks[name], f)
end

function _M.run_hook(name, ...)
  if not hooks[name] then
    return (...)
  end

  local acc

  for _, f in ipairs(hooks[name] or {}) do
    acc = f(acc, ...)
  end

  return unpack(acc, 1, acc.n)
end

function _M.clear_hooks()
  hooks = {}
end

return _M
