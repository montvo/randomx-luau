local sent = {}
local ws
ws = {
	OnMessage = { Connect = function(self, fn) ws._onmsg = fn print("H: onmsg connected") end },
	OnClose = { Connect = function(self, fn) ws._onclose = fn end },
	Send = function(self, p) table.insert(sent, p) print("H: sent", p:sub(1,50)) end,
	Close = function() print("H: close") end,
}
local M = require("../miner.test")
local n = 0
local blob = string.rep("ab", 76)
local function decode(s)
	local t = {}
	for k, v in s:gmatch('"([%w_]+)":("?)([^",}]*)"?') do t[k] = v end
	print("H: decoded keys", tostring(t.method), tostring(#(t.blob or "")))
	return t
end
local res = M.run{ bridge="ws://mock", chains=1, iters=8, maxHashes=1, sliceBudget=0,
  connect=function() print("H: connect") return ws end,
  decode=decode,
  wait=function()
    n = n + 1
    print("H: wait", n, #sent)
    if n == 2 then
      ws._onmsg('{"jsonrpc":"2.0","method":"job","params":{"blob":"'..blob..'","seed_hash":"'..string.rep("cd",32)..'","target":"ffffffff","job_id":"j1"}}')
      print("H: job pushed")
    end
  end }
print("H: res", res.hashes, res.shares)
