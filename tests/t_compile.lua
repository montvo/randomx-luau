--!nocheck
-- Kompilovana cesta superscalar (loadstring) a fallback do interpreteru musi dat
-- bit na bit stejny hash.
local blake = require("../src/blake2b")
local aes = require("../src/aes")
local argon = require("../src/argon2")
local ss = require("../src/superscalar")
local rx = require("../src/rx")
local function unhex(h) local t = {} for i = 1, #h, 2 do t[#t + 1] = string.char(tonumber(h:sub(i, i + 1), 16)) end return table.concat(t) end
local function hx(s) return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end)) end
local key, input = unhex("74657374206b657920303030"), unhex("5468697320697320612074657374")
local cache = argon.initCache(blake, key)
local a = rx.hash(blake, aes, ss, cache, key, input)
rx.noCompile = true
local b = rx.hash(blake, aes, ss, cache, key, input)
rx.noCompile = false
local c = rx.hash(blake, aes, ss, cache, key, input)
assert(a == b, "kompilovana a interpretovana cesta se rozesly")
assert(b == c, "navrat ke kompilaci se rozesel")
print("PASS: kompilace i fallback davaji stejny hash " .. hx(a):sub(1, 16) .. "…")
