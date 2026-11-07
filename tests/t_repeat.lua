--!nocheck
-- Dva hashe za sebou ve stejnem procesu musi dat stejny vystup.
-- Hlida unik modulu-level stavu (fprc = rezim zaokrouhlovani, rcpCache).
local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")

local function unhex(h) local t = {} for i = 1, #h, 2 do t[#t + 1] = string.char(tonumber(h:sub(i, i + 1), 16)) end return table.concat(t) end
local key, input = unhex("74657374206b657920303030"), unhex("5468697320697320612074657374")
local cache = argon.initCache(blake, key)

-- 512 iteraci staci na to, aby posledni CFROUND nechal fprc nenulove
rx._chains = 1
rx._iters = 512
local a = rx.hash(blake, aes, ss, cache, key, input)
local b = rx.hash(blake, aes, ss, cache, key, input)
rx.noCompile = true
local c = rx.hash(blake, aes, ss, cache, key, input)
rx.noCompile = false
local d = rx.hash(blake, aes, ss, cache, key, input)
assert(a == b, "druhy hash (kompilovany) se lisi od prvniho")
assert(a == c, "hash po prepnuti na interpreter se lisi")
assert(a == d, "hash po navratu ke kompilaci se lisi")
print("PASS: 4 hashe za sebou shodne (" .. #a .. " B)")
