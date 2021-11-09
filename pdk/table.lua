local new_tab
local clear_tab
do
  local ok
  ok, new_tab = pcall(require, "table.new")
  if not ok then
    new_tab = function (narr, nrec) return {} end
  end

  ok, clear_tab = pcall(require, "table.clear")
  if not ok then
    clear_tab = function (tab)
      for k, _ in pairs(tab) do
        tab[k] = nil
      end
    end
  end
end

local function merge_tab(t1, t2)
  local res = {}
  if t1 then
    for k,v in pairs(t1) do
      res[k] = v
    end
  end
  if t2 then
    for k,v in pairs(t2) do
      res[k] = v
    end
  end
  return res
end


local function new(self)
  return {
    new = new_tab,
    clear = clear_tab,
    merge = merge_tab,
  }
end


return {
  new = new,
}
