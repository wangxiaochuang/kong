local utils = require "kong.tools.utils"
local ipmatcher = require "resty.ipmatcher"

local function new(self)
  local _IP = {}

  local ips = self.configuration.trusted_ips or {}
  local n_ips = #ips
  local trusted_ips = self.table.new(n_ips, 0)
  local trust_all_ipv4
  local trust_all_ipv6

  local idx = 1
  for i = 1, n_ips do
    local address = ips[i]

    if utils.is_valid_ip_or_cidr(address) then
      trusted_ips[idx] = address
      idx = idx + 1

      if address == "0.0.0.0/0" then
        trust_all_ipv4 = true
      elseif address == "::/0" then
        trust_all_ipv6 = true
      end
    end
  end

  if #trusted_ips == 0 then
    _IP.is_trusted = function() return false end
  elseif trust_all_ipv4 and trust_all_ipv6 then
    _IP.is_trusted = function() return true end
  else
    local matcher = ipmatcher.new(trusted_ips)
    _IP.is_trusted = function(ip)
      return not not matcher:match(ip)
    end
  end

  return _IP
end

return {
  new = new,
}
