-- usage: luau t_rx.lua <keyhex> <inputhex> [expecthex]
local args = { ... }
local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")

local function unhex(h)
	local t = {}
	for i = 1, #h, 2 do t[#t + 1] = string.char(tonumber(h:sub(i, i + 1), 16)) end
	return table.concat(t)
end
local key = unhex(args[1])
local input = unhex(args[2])
local t0 = os.clock()
local cache = argon.initCache(blake, key)
local t1 = os.clock()
local out = rx.hash(blake, aes, ss, cache, key, input)
local t2 = os.clock()
local hex = ""
for i = 1, 32 do hex = hex .. string.format("%02x", string.byte(out, i)) end
print("hash     ", hex)
print("expect   ", args[3] or "-")
print("cache s  ", string.format("%.1f", t1 - t0), " hash s", string.format("%.1f", t2 - t1))
print(hex == (args[3] or "") and "PASS" or "FAIL")
