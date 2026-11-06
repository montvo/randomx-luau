--!strict
-- AES-128 (FIPS-197) single round + RandomX custom functions built on it.
-- Ground truth: rxsrc/src/soft_aes.cpp, rxsrc/src/aes_hash.cpp, spec 3.2-3.4.
--
-- encRound = SubBytes, ShiftRows, MixColumns, XOR key
-- decRound = InvShiftRows, InvSubBytes, InvMixColumns, XOR key
-- (byte-exact equivalent of soft_aesenc/soft_aesdec with the portable
--  rx_set_int_vec_i128 word order, i.e. a plain 16-byte AES state.)
--
-- gen1R  = AesGenerator1R  (spec 3.2)
-- gen4R  = AesGenerator4R  (spec 3.3)
-- hash1R = AesHash1R       (spec 3.4)
--
-- Pure Luau, bit32 + precomputed T-tables.

local bit32 = bit32
local band, bxor, shr, shl, ror = bit32.band, bit32.bxor, bit32.rshift, bit32.lshift, bit32.rrotate
local sbyte, schar = string.byte, string.char

local M = {}

--------------------------------------------------------------------------------
-- GF(2^8) helpers / tables
--------------------------------------------------------------------------------

local function gmul(a: number, b: number): number
	local r = 0
	for _ = 1, 8 do
		if band(b, 1) ~= 0 then
			r = bxor(r, a)
		end
		local t = shl(a, 1)
		if t > 0xff then
			t = bxor(t, 0x11b)
		end
		a = t
		b = shr(b, 1)
	end
	return r
end

local function rotl8(x: number, n: number): number
	return band(bxor(shl(x, n), shr(x, 8 - n)), 0xff)
end

local S: { number } = {}
local IS: { number } = {}

do
	-- multiplicative inverses in GF(2^8)
	local inv: { number } = { [0] = 0 }
	for a = 1, 255 do
		for b = 1, 255 do
			if gmul(a, b) == 1 then
				inv[a] = b
				break
			end
		end
	end
	for x = 0, 255 do
		local y = inv[x] or 0
		S[x] = bxor(y, bxor(bxor(bxor(rotl8(y, 1), rotl8(y, 2)), bxor(rotl8(y, 3), rotl8(y, 4))), 0x63))
	end
	for x = 0, 255 do
		IS[S[x]] = x
	end
end

-- T tables: T1..T4 for encryption, D1..D4 for decryption.
-- T1[x] holds [2s, s, s, 3s] with byte 0 in the low 8 bits; T2..T4 are its
-- 8/16/24-bit rotates. D1[x] holds [0e, 09, 0d, 0b] * InvS(x), D2..D4 rotated.
local T1, T2, T3, T4 = {}, {}, {}, {}
local D1, D2, D3, D4 = {}, {}, {}, {}
for x = 0, 255 do
	local s = S[x]
	local w = gmul(s, 2) + s * 0x100 + s * 0x10000 + gmul(s, 3) * 0x1000000
	T1[x], T2[x], T3[x], T4[x] = w, ror(w, 24), ror(w, 16), ror(w, 8)
	local i = IS[x]
	local d = gmul(i, 14) + gmul(i, 9) * 0x100 + gmul(i, 13) * 0x10000 + gmul(i, 11) * 0x1000000
	D1[x], D2[x], D3[x], D4[x] = d, ror(d, 24), ror(d, 16), ror(d, 8)
end

local function packW(w0: number, w1: number, w2: number, w3: number): string
	return schar(
		band(w0, 0xff), band(shr(w0, 8), 0xff), band(shr(w0, 16), 0xff), band(shr(w0, 24), 0xff),
		band(w1, 0xff), band(shr(w1, 8), 0xff), band(shr(w1, 16), 0xff), band(shr(w1, 24), 0xff),
		band(w2, 0xff), band(shr(w2, 8), 0xff), band(shr(w2, 16), 0xff), band(shr(w2, 24), 0xff),
		band(w3, 0xff), band(shr(w3, 8), 0xff), band(shr(w3, 16), 0xff), band(shr(w3, 24), 0xff)
	)
end

-- 16-byte column at `off` of `s`, round key `kw` (4 words) -> 16 bytes
local function encCol(s: string, off: number, kw: { number }): string
	local b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 = sbyte(s, off, off + 15)
	local w0 = bxor(bxor(bxor(T1[b0], T2[b5]), bxor(T3[b10], T4[b15])), kw[1])
	local w1 = bxor(bxor(bxor(T1[b4], T2[b9]), bxor(T3[b14], T4[b3])), kw[2])
	local w2 = bxor(bxor(bxor(T1[b8], T2[b13]), bxor(T3[b2], T4[b7])), kw[3])
	local w3 = bxor(bxor(bxor(T1[b12], T2[b1]), bxor(T3[b6], T4[b11])), kw[4])
	return packW(w0, w1, w2, w3)
end

local function decCol(s: string, off: number, kw: { number }): string
	local b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 = sbyte(s, off, off + 15)
	local w0 = bxor(bxor(bxor(D1[b0], D2[b13]), bxor(D3[b10], D4[b7])), kw[1])
	local w1 = bxor(bxor(bxor(D1[b4], D2[b1]), bxor(D3[b14], D4[b11])), kw[2])
	local w2 = bxor(bxor(bxor(D1[b8], D2[b5]), bxor(D3[b2], D4[b15])), kw[3])
	local w3 = bxor(bxor(bxor(D1[b12], D2[b9]), bxor(D3[b6], D4[b3])), kw[4])
	return packW(w0, w1, w2, w3)
end

local function unhex(h: string): string
	local out = table.create(#h // 2)
	for i = 1, #h, 2 do
		local v = tonumber(string.sub(h, i, i + 1), 16) :: number
		table.insert(out, schar(v))
	end
	return table.concat(out)
end

local function keyWords(key: string): { number }
	local k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15 = sbyte(key, 1, 16)
	return {
		k0 + k1 * 0x100 + k2 * 0x10000 + k3 * 0x1000000,
		k4 + k5 * 0x100 + k6 * 0x10000 + k7 * 0x1000000,
		k8 + k9 * 0x100 + k10 * 0x10000 + k11 * 0x1000000,
		k12 + k13 * 0x100 + k14 * 0x10000 + k15 * 0x1000000,
	}
end

local function wordsAt(s: string, off: number): { number }
	local a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p = sbyte(s, off, off + 15)
	return {
		a + b * 0x100 + c * 0x10000 + d * 0x1000000,
		e + f * 0x100 + g * 0x10000 + h * 0x1000000,
		i + j * 0x100 + k * 0x10000 + l * 0x1000000,
		m + n * 0x100 + o * 0x10000 + p * 0x1000000,
	}
end

--------------------------------------------------------------------------------
-- Public round functions
--------------------------------------------------------------------------------

function M.encRound(state: string, key: string): string
	assert(#state == 16 and #key == 16, "encRound needs 16-byte state and key")
	return encCol(state, 1, keyWords(key))
end

function M.decRound(state: string, key: string): string
	assert(#state == 16 and #key == 16, "decRound needs 16-byte state and key")
	return decCol(state, 1, keyWords(key))
end

--------------------------------------------------------------------------------
-- AesGenerator1R (spec 3.2)
--------------------------------------------------------------------------------

local K1R = {
	keyWords(unhex("53a5ac6d096671622b55b5db1749f4b4")),
	keyWords(unhex("07af7c6d0d716a8478d325174edca10d")),
	keyWords(unhex("f162123fc67e949f4f79c0f445e3203e")),
	keyWords(unhex("3581ef6a7c31bab1884c311654911649")),
}

function M.gen1R(seed: string)
	assert(#seed == 64, "gen1R needs a 64-byte seed")
	local o = { state = seed }
	function o:next(): string
		local s = self.state
		local r = decCol(s, 1, K1R[1])
			.. encCol(s, 17, K1R[2])
			.. decCol(s, 33, K1R[3])
			.. encCol(s, 49, K1R[4])
		self.state = r
		return r
	end
	return o
end

--------------------------------------------------------------------------------
-- AesGenerator4R (spec 3.3)
--------------------------------------------------------------------------------

local K4R = {
	keyWords(unhex("ddaa2164db3d83d12b6d542f3fd2e599")),
	keyWords(unhex("50340eb2553f91b6539df706e5cddfa5")),
	keyWords(unhex("04d93e5caf7b5e519f67a40abf021c17")),
	keyWords(unhex("63376285085d8fe7853767cd91d2ded8")),
	keyWords(unhex("736f82b5a6a7d6e36d8b513db4ff9e22")),
	keyWords(unhex("f36b56c7d9b3109c4e4d02e9d2b772b2")),
	keyWords(unhex("e7c973f28ba365f70a66a92ba7ef3bf6")),
	keyWords(unhex("09d67c7ade395891fdd1060c2d76b0c0")),
}

function M.gen4R(seed: string)
	assert(#seed == 64, "gen4R needs a 64-byte seed")
	local o = { state = seed }
	function o:next(): string
		local s = self.state
		local c0 = decCol(s, 1, K4R[1])
		local c1 = encCol(s, 17, K4R[1])
		local c2 = decCol(s, 33, K4R[5])
		local c3 = encCol(s, 49, K4R[5])
		for r = 2, 4 do
			c0 = decCol(c0, 1, K4R[r])
			c1 = encCol(c1, 1, K4R[r])
			c2 = decCol(c2, 1, K4R[r + 4])
			c3 = encCol(c3, 1, K4R[r + 4])
		end
		local out = c0 .. c1 .. c2 .. c3
		self.state = out
		return out
	end
	return o
end

--------------------------------------------------------------------------------
-- AesHash1R (spec 3.4)
--------------------------------------------------------------------------------

local HSTATE = unhex(
	"0d2cb592de56a89f47db82ccad3a98d7"
	.. "6e998d3398b7c7155a129ef55780e7ac"
	.. "1700776ad0c762ae6b507950e47ca0e8"
	.. "0c240a638d82ad070500a1794849997e"
)
local XKEY0 = keyWords(unhex("8983faf69f94248bbf56dc9001028906"))
local XKEY1 = keyWords(unhex("d163b2613ce0f451c64310ee9bf918ed"))

function M.hash1R(buf: string | buffer): string
	local s: string
	if type(buf) == "buffer" then
		local b = buf :: buffer
		s = buffer.readstring(b, 0, buffer.len(b))
	else
		s = buf :: string
	end
	local len = #s
	assert(len % 64 == 0, "hash1R input size must be a multiple of 64")

	local st = HSTATE
	for off = 1, len, 64 do
		local k0 = wordsAt(s, off)
		local k1 = wordsAt(s, off + 16)
		local k2 = wordsAt(s, off + 32)
		local k3 = wordsAt(s, off + 48)
		st = encCol(st, 1, k0) .. decCol(st, 17, k1) .. encCol(st, 33, k2) .. decCol(st, 49, k3)
	end

	for _, xk in ipairs({ XKEY0, XKEY1 }) do
		st = encCol(st, 1, xk) .. decCol(st, 17, xk) .. encCol(st, 33, xk) .. decCol(st, 49, xk)
	end
	return st
end

return M
