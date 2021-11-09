local version = setmetatable({
  major = 2,
  minor = 4,
  patch = 1,
}, {
  __tostring = function(t)
    return string.format("%d.%d.%d%s", t.major, t.minor, t.patch,
                          t.suffix or "")
  end
})

return {
  _NAME = "kong",
  _VERSION = tostring(version),
  _VERSION_TABLE = version,
  _SERVER_TOKENS = "kong/" .. tostring(version),
  _DEPENDENCIES = {
    nginx = { "1.19.3.1" },
  }
}
