-- cely beh: rg: hash registroveho souboru po kazde iteraci (default 8 x 2048) + finalni hash.
local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")
rx.traceReg = true
local key = string.char(0)
local cache = argon.initCache(blake, key)
print("final " .. rx.hash(blake, aes, ss, cache, key, string.rep("\0", 16)))
