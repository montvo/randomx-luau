-- vytiskne 272bajtovy program chainu (BLOB:) pro srovnani s C generateProgram.
local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")
rx.traceBlob = true rx._chains = 2 rx._iters = 1
local key = string.char(0)
local cache = argon.initCache(blake, key)
rx.hash(blake, aes, ss, cache, key, string.rep("\0", 16))
