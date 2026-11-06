local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")
rx.traceSp = true
rx._chains = 1
rx._iters = 2
local key = string.char(0)
local cache = argon.initCache(blake, key)
rx.hash(blake, aes, ss, cache, key, string.rep("\0", 16))
