local ran_before

return function(options)
  if ran_before then
    ngx.log(ngx.WARN, debug.traceback("attempt to re-run the globalpatches", 2))
    return
  end

  ngx.log(ngx.DEBUG, "installing the globalpatches")
  ran_before = true


  options = options or {}
  local meta = require "kong.meta"

  require("cjson.safe").encode_sparse_array(nil, nil, 2^15)

  if options.cli then
    setmetatable(_G, nil)
  end

  _G._KONG = {
    _NAME = meta._NAME,
    _VERSION = meta._VERSION
  }

  if options.cli then
    ngx.IS_CLI = true
    ngx.exit = function() end
  end

  do
    local get_phase= ngx.get_phase
    local ngx_sleep = ngx.sleep  
    local alternative_sleep = require("socket").sleep

    ngx.sleep = function(s)
      if get_phase() == "init_worker" then
        ngx.log(ngx.NOTICE, "executing a blocking 'sleep' (", s, " seconds)")
        return alternative_sleep(s)
      end
      return ngx_sleep(s)
    end
  end

  do
    if options.cli then
      local SharedDict = {}
      local function set(data, key, value, expire_at)
        data[key] = {
	  value = value,
	  info = {expire_at = expire_at}
	}
      end
      function SharedDict:new()
        return setmetatable({data = {}}, {__index = self})
      end
      function SharedDict:capacity()
        return 0
      end
      function SharedDict:free_space()
        return 0
      end
      function SharedDict:get(key)
        return self.data[key] and self.data[key].value, nil
      end
      SharedDict.get_stale = SharedDict.get
      function SharedDict:set(key, value)
        set(self.data, key, value)
	return true, nil, false
      end
      SharedDict.safe_set = SharedDict.set
      function SharedDict:add(key, value, exptime)
        if self.data[key] ~= nil then
	  return false, "exists", false
	end

	local expire_at = nil

	if exptime then
	  ngx.timer.at(exptime, function()
	    self.data[key] = nil
	  end)
	  expire_at = ngx.now() + exptime
	end

	set(self.data, key, value, expire_at)
	return true, nil, false
      end
      SharedDict.safe_add = SharedDict.add
      function SharedDict:replace(key, value)
        if self.data[key] == nil then
	  return false, "not found", false
	end
	set(self.data, key, value)
	return true, nil, false
      end
      function SharedDict:delete(key)
        if self.data[key] ~= nil then
	  self.data[key] = nil
	end
	return true
      end
      function SharedDict:incr(key, value, init, init_ttl)
        if not self.data[key] then
	  if not init then
	    return nil, "not found"
	  else
	    self.data[key] = { value = init, info = {} }
	    if init_ttl then
	      self.data[key].info.expire_at = ngx.now() + init_ttl
	      ngx.timer.at(init_ttl, function()
	        self.data[key] = nil
	      end)
	    end
	  end
	elseif type(self.data[key].value) ~= "number" then
	  return nil, "not a number"
	end
	self.data[key].value = self.data[key].value + value
	return self.data[key].value, nil
      end
      function SharedDict:flush_all()
        for _, item in pairs(self.data) do
	  item.info.expire_at = ngx.now()
	end
      end
      function SharedDict:flush_expired(n)
        local data = self.data
	local flushed = 0

	for key, item in pairs(self.data) do
	  if item.info.expire_at and item.info.expire_at <= ngx.now() then
	    data[key] = nil
	    flushed = flushed + 1
	    if n and flushed == n then
	      break
	    end
	  end
	end
	self.data = data
	return flushed
      end
      function SharedDict:get_keys(n)
        n = n or 1024
	local i = 0
	local keys = {}
	for k in pairs(self.data) do
	  keys[#keys+1] = k
	  i = i + 1
	  if n ~= 0 and i == n then
	    break
	  end
	end
	return keys
      end
      function SharedDict:ttl(key)
        local item = self.data[key]
	if item == nil then
	  return nil, "not found"
	else
	  local expire_at = item.info.expire_at
	  if expire_at == nil then
	    return 0
	  else
	    local remaining = expire_at - ngx.now()
	    if remaining < 0 then
	      return nil, "not found"
	    else
	      return remaining
	    end
	  end
	end
      end

      _G.ngx.shared = setmetatable({}, {
        __index = function(self, key)
	  local shm = rawget(self, key)
	  if not shm then
	    shm = SharedDict:new()
	    rawset(self, key, shm)
	  end
	  return shm
	end
      })
    end

  end

  do
    local util = require "kong.tools.utils"
    local seeded = {}
    local randomseed = math.randomseed

    _G.math.randomseed = function()
      local pid = ngx.worker.pid()
      local id
      local is_seeded
      local phase = ngx.get_phase()
      if phase == "init" then
        id = "master"
	is_seeded = seeded.master
      else
        id = ngx.worker.id()
	is_seeded = seeded[pid]
      end

      if is_seeded then
        ngx.log(ngx.DEBUG, debug.traceback("attempt to seed already seeded random number " ..
	                                           "generator on process #" .. tostring(pid), 2))
        return
      end

      if not options.cli and (phase ~= "init_worker" and phase ~= "init") then
        ngx.log(ngx.WARN, debug.traceback("math.randomseed() must be called in " ..
	                                          "init or init_worker context", 2))
      end

      local seed
      local bytes, err = util.get_rand_bytes(8)
      if bytes then
        ngx.log(ngx.DEBUG, "seeding PRNG from OpenSSL RAND_bytes()")

	local t = {}
	for i = 1, #bytes do
	  local byte = string.byte(bytes, i)
	  t[#t+1] = byte
	end

	local str = table.concat(t)
	if #str > 12 then
	  str = string.sub(str, 1, 12)
	end

	seed = tonumber(str)

      else
        ngx.log(ngx.ERR, "could not seed from OpenSSL RAND_bytes, seeding ",
	                         "PRNG with time and process id instead (this can ",
				                          "result to duplicated seeds): ", err)
        seed = ngx.now() * 1000 + pid
      end

      if not options.cli then
        local kong_shm = ngx.shared.kong
	if id == "master" then
	  local worker_count = ngx.worker.count()
	  local old_worker_count = kong_shm:get("worker:count")
	  if old_worker_count and old_worker_count > worker_count then
	    for i = worker_count, old_worker_count - 1 do
	      local old_worker_pid = kong_shm:get("pids:" .. i)
	      if old_worker_pid then
	        seeded[old_worker_pid] = nil
		kong_shm:delete("pids:" .. i)
		kong_shm:delete("kong:mem:" .. old_worker_pid)
	      end
	    end
	  end

	  if old_worker_count ~= worker_count then
	    local ok, err = kong_shm:safe_set("worker:count", worker_count)
	    if not ok then
	      ngx.log(ngx.WARN, "could not store worker count in kong shm: ", err)
	    end
	  end

	  seeded.master = true
	else
	  local old_worker_pid = kong_shm:get("pids:" .. id)
	  if old_worker_pid then
	    seeded[old_worker_pid] = nil
	    kong_shm:delete("kong:mem:" .. old_worker_pid)
	  end

	  local ok, err = kong_shm:safe_set("pids:" .. id, pid)
	  if not ok then
	    ngx.log(ngx.WARN, "could not store process id in kong shm: ", err)
	  end

	  seeded[pid] = true
	end
      end

      return randomseed(seed)
    end
  end

  do
    local sub = string.sub
    require "resty.dns.resolver"
    local toip

    local old_tcp = ngx.socket.tcp
    local old_udp = ngx.socket.udp

    local old_tcp_connect
    local old_udp_setpeername
    local function strip_nils(first, second)
      if second then
        return first, second
      elseif first then
        return first
      end
    end
 
    local function resolve_connect(f, sock, host, port, opts)
      if sub(host, 1, 5) ~= "unix:" then
        local try_list
	host, port, try_list = toip(host, port)
        if not host then
          return nil, "[cosocket] DNS resolution failed: " .. tostring(port) ..
                      ". Tried: " .. tostring(try_list)
        end
      end

      return f(sock, host, strip_nils(port, opts))
    end

    local function tcp_resolve_connect(sock, host, port, opts)
      return resolve_connect(old_tcp_connect, sock, host, port, opts)
    end

    local function udp_resolve_setpeername(sock, host, port)
      return resolve_connect(old_udp_setpeername, sock, host, port)
    end

    _G.ngx.socket.tcp = function(...)
      local sock = old_tcp(...)

      if not old_tcp_connect then
        old_tcp_connect = sock.connect
      end

      sock.connect = tcp_resolve_connect

      return sock
    end

    _G.ngx.socket.udp = function(...)
      local sock = old_udp(...)

      if not old_udp_setpeername then
        old_udp_setpeername = sock.setpeername
      end

      sock.setpeername = udp_resolve_setpeername

      return sock
    end

    toip = require("resty.dns.client").toip
  end

end
