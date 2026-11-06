-- per-pc trace jednoho vybraneho chainu/iterace (traceChain/traceIt jsou 1-based).
-- Srovnani: ./trace_dbg 00 00000000000000000000000000000000 <chain> <iter> | grep '^pc'
local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")
rx.tracePC = true rx._chains = 1 rx._iters = 306 rx.traceIt = 306 rx.traceChain = 1
local key = string.char(0)
local cache = argon.initCache(blake, key)
rx.hash(blake, aes, ss, cache, key, string.rep("\0", 16))
