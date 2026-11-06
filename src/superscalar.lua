--!strict
-- SuperscalarHash: program generator + interpreter (pure Luau).
-- Faithful port of rxsrc/src/superscalar.cpp (+ superscalar.hpp,
-- superscalar_program.hpp, blake2_generator.cpp, common.hpp, reciprocal.c).
--
-- Instruction wire format (8 bytes, matches randomx::Instruction):
--   opcode(8) dst(8) src(8) mod(8) imm32(32 LE)
--
-- 64-bit values are pairs of 32-bit halfwords {lo, hi} throughout.

local bit32 = bit32
local band, bor, bxor, lshift, rshift = bit32.band, bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift
local btest = bit32.btest

local M = {}

local MASK32 = 0xFFFFFFFF

--------------------------------------------------------------------------------
-- Constants (common.hpp / superscalar.hpp)
--------------------------------------------------------------------------------

local RANDOMX_SUPERSCALAR_LATENCY = 170
local SuperscalarMaxSize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2
local CYCLE_MAP_SIZE = RANDOMX_SUPERSCALAR_LATENCY + 4
local LOOK_FORWARD_CYCLES = 4
local MAX_THROWAWAY_COUNT = 256
local RegisterNeedsDisplacement = 5 -- x86 r13
local RegistersCount = 8

-- SuperscalarInstructionType
local OP_ISUB_R = 0
local OP_IXOR_R = 1
local OP_IADD_RS = 2
local OP_IMUL_R = 3
local OP_IROR_C = 4
local OP_IADD_C7 = 5
local OP_IXOR_C7 = 6
local OP_IADD_C8 = 7
local OP_IXOR_C8 = 8
local OP_IADD_C9 = 9
local OP_IXOR_C9 = 10
local OP_IMULH_R = 11
local OP_ISMULH_R = 12
local OP_IMUL_RCP = 13
local OP_INVALID = -1

-- ExecutionPort
local PORT_NULL = 0
local PORT_P0 = 1
local PORT_P1 = 2
local PORT_P5 = 4
local PORT_P01 = 3
local PORT_P05 = 5
local PORT_P015 = 7

--------------------------------------------------------------------------------
-- 64-bit helpers (halfword pairs)
--------------------------------------------------------------------------------

local function isZeroOrPowerOf2(x: number): boolean
	return band(x, x - 1) == 0
end

-- shift a 64-bit value left by n (0..63); returns lo, hi (mod 2^32)
local function shl64(lo: number, hi: number, n: number): (number, number)
	if n == 0 then
		return lo, hi
	elseif n == 32 then
		return 0, lo
	elseif n > 32 then
		return lshift(lo, n - 32), bor(lshift(hi, n - 32), rshift(lo, 64 - n))
	end
	return band(lshift(lo, n), MASK32), bor(lshift(hi, n), rshift(lo, 32 - n))
end

local function add64(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local lo = alo + blo
	local carry = 0
	if lo > MASK32 then
		lo = lo - 0x100000000
		carry = 1
	end
	local hi = ahi + bhi + carry
	if hi > MASK32 then
		hi = hi - 0x100000000
	end
	return lo, hi
end

local function sub64(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local lo = alo - blo
	local borrow = 0
	if lo < 0 then
		lo = lo + 0x100000000
		borrow = 1
	end
	local hi = ahi - bhi - borrow
	if hi < 0 then
		hi = hi + 0x100000000
	end
	return lo, hi
end

-- full 64x64 -> 128 multiply, 16-bit limbs; returns c0..c7 (limb 0 = LSB)
local function mul128(alo: number, ahi: number, blo: number, bhi: number): (number, number, number, number, number, number, number, number)
	local a0 = band(alo, 0xFFFF)
	local a1 = rshift(alo, 16)
	local a2 = band(ahi, 0xFFFF)
	local a3 = rshift(ahi, 16)
	local b0 = band(blo, 0xFFFF)
	local b1 = rshift(blo, 16)
	local b2 = band(bhi, 0xFFFF)
	local b3 = rshift(bhi, 16)

	local t = a0 * b0
	local c0 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a0 * b1 + a1 * b0
	local c1 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a0 * b2 + a1 * b1 + a2 * b0
	local c2 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0
	local c3 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a1 * b3 + a2 * b2 + a3 * b1
	local c4 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a2 * b3 + a3 * b2
	local c5 = band(t, 0xFFFF)
	t = math.floor(t / 65536) + a3 * b3
	local c6 = band(t, 0xFFFF)
	local c7 = math.floor(t / 65536)
	return c0, c1, c2, c3, c4, c5, c6, c7
end

local function mul64lo(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local c0, c1, c2, c3 = mul128(alo, ahi, blo, bhi)
	return c0 + c1 * 65536, c2 + c3 * 65536
end

local function mul64hi(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local _, _, _, _, c4, c5, c6, c7 = mul128(alo, ahi, blo, bhi)
	return c4 + c5 * 65536, c6 + c7 * 65536
end

-- signed 64x64 -> high 64 bits (two's complement)
local function smul64hi(alo: number, ahi: number, blo: number, bhi: number): (number, number)
	local lo, hi = mul64hi(alo, ahi, blo, bhi)
	if ahi >= 0x80000000 then -- a < 0: high -= b
		lo, hi = sub64(lo, hi, blo, bhi)
	end
	if bhi >= 0x80000000 then -- b < 0: high -= a
		lo, hi = sub64(lo, hi, alo, ahi)
	end
	return lo, hi
end

-- rotr of a 64-bit value by n (0..63)
local function rotr64(lo: number, hi: number, n: number): (number, number)
	if n == 0 then
		return lo, hi
	elseif n >= 32 then
		lo, hi = hi, lo
		n = n - 32
		if n == 0 then
			return lo, hi
		end
	end
	return bor(rshift(lo, n), lshift(hi, 32 - n)), bor(rshift(hi, n), lshift(lo, 32 - n))
end

-- 64-bit unsigned div/mod by 32-bit divisor (bitwise long division)
local function divmod64by32(hi: number, lo: number, d: number): (number, number, number)
	local qhi, qlo, rem = 0, 0, 0
	for i = 63, 0, -1 do
		local bitv
		if i >= 32 then
			bitv = band(rshift(hi, i - 32), 1)
		else
			bitv = band(rshift(lo, i), 1)
		end
		rem = rem * 2 + bitv
		if rem >= d then
			rem = rem - d
			if i >= 32 then
				qhi = bor(qhi, lshift(1, i - 32))
			else
				qlo = bor(qlo, lshift(1, i))
			end
		end
	end
	return qhi, qlo, rem
end

local function bitLength(x: number): number
	local n = 0
	while x > 0 do
		n = n + 1
		x = math.floor(x / 2)
	end
	return n
end

-- reciprocal.c: 2**x / divisor for the highest x keeping rcp < 2**64
function M.reciprocal(divisor: number): (number, number)
	local shift = bitLength(divisor) -- 64 - __builtin_clzll(divisor)
	local qhi, qlo, r = divmod64by32(0x80000000, 0, divisor) -- q = 2^63 / d, r = 2^63 % d
	local qs_lo, qs_hi = shl64(qlo, qhi, shift)
	local rs_lo, rs_hi = shl64(r, 0, shift)
	local dhi, dlo = divmod64by32(rs_hi, rs_lo, divisor)
	return add64(qs_lo, qs_hi, dlo, dhi)
end

--------------------------------------------------------------------------------
-- Blake2Generator (blake2_generator.cpp)
--------------------------------------------------------------------------------

local maxSeedSize = 60

local Gen = {}
Gen.__index = Gen

function M.newGen(blake, key: string)
	local data = key:sub(1, maxSeedSize)
	data = data .. string.rep("\0", 64 - #data) -- nonce (0) occupies bytes 60..63
	data = blake.blake2b(data, 64) -- dataIndex starts at sizeof(data)
	return setmetatable({ blake = blake, data = data, dataIndex = 0 }, Gen)
end

function Gen.checkData(self, bytesNeeded: number)
	if self.dataIndex + bytesNeeded > 64 then
		self.data = self.blake.blake2b(self.data, 64)
		self.dataIndex = 0
	end
end

function Gen.getByte(self): number
	self:checkData(1)
	self.dataIndex = self.dataIndex + 1
	return string.byte(self.data, self.dataIndex)
end

function Gen.getUInt32(self): number
	self:checkData(4)
	local i = self.dataIndex
	self.dataIndex = i + 4
	local a, b, c, d = string.byte(self.data, i + 1, i + 4)
	return a + b * 256 + c * 65536 + d * 16777216
end

--------------------------------------------------------------------------------
-- MacroOps
--------------------------------------------------------------------------------

type MacroOp = {
	size: number,
	latency: number,
	uop1: number,
	uop2: number,
	dependent: boolean,
}

local function mop(size: number, latency: number, uop1: number, uop2: number?, dependent: boolean?): MacroOp
	return { size = size, latency = latency, uop1 = uop1, uop2 = uop2 or PORT_NULL, dependent = dependent or false }
end

local function isSimple(m: MacroOp): boolean
	return m.uop2 == PORT_NULL
end

local function isEliminated(m: MacroOp): boolean
	return m.uop1 == PORT_NULL
end

local Add_rr = mop(3, 1, PORT_P015)
local Sub_rr = mop(3, 1, PORT_P015)
local Xor_rr = mop(3, 1, PORT_P015)
local Imul_r = mop(3, 4, PORT_P1, PORT_P5)
local Mul_r = mop(3, 4, PORT_P1, PORT_P5)
local Mov_rr = mop(3, 0, PORT_NULL)

local Lea_sib = mop(4, 1, PORT_P01)
local Imul_rr = mop(4, 3, PORT_P1)
local Ror_ri = mop(4, 1, PORT_P05)

local Add_ri = mop(7, 1, PORT_P015)
local Xor_ri = mop(7, 1, PORT_P015)

local Mov_ri64 = mop(10, 1, PORT_P015)

local function dependentOp(parent: MacroOp): MacroOp
	return mop(parent.size, parent.latency, parent.uop1, parent.uop2, true)
end

--------------------------------------------------------------------------------
-- SuperscalarInstructionInfo
--------------------------------------------------------------------------------

type InstrInfo = {
	name: string,
	type: number,
	ops: { MacroOp },
	latency: number,
	resultOp: number,
	dstOp: number,
	srcOp: number,
	isSimple: boolean,
}

local function makeInfo(name: string, t: number, op: MacroOp, srcOp: number): InstrInfo
	return {
		name = name,
		type = t,
		ops = { op },
		latency = op.latency,
		resultOp = 0,
		dstOp = 0,
		srcOp = srcOp,
		isSimple = true,
	}
end

local function makeMultiInfo(name: string, t: number, ops: { MacroOp }, resultOp: number, dstOp: number, srcOp: number): InstrInfo
	local latency = 0
	for i = 1, #ops do
		latency = latency + ops[i].latency
	end
	return {
		name = name,
		type = t,
		ops = ops,
		latency = latency,
		resultOp = resultOp,
		dstOp = dstOp,
		srcOp = srcOp,
		isSimple = false,
	}
end

local INFO_ISUB_R = makeInfo("ISUB_R", OP_ISUB_R, Sub_rr, 0)
local INFO_IXOR_R = makeInfo("IXOR_R", OP_IXOR_R, Xor_rr, 0)
local INFO_IADD_RS = makeInfo("IADD_RS", OP_IADD_RS, Lea_sib, 0)
local INFO_IMUL_R = makeInfo("IMUL_R", OP_IMUL_R, Imul_rr, 0)
local INFO_IROR_C = makeInfo("IROR_C", OP_IROR_C, Ror_ri, -1)
local INFO_IADD_C7 = makeInfo("IADD_C7", OP_IADD_C7, Add_ri, -1)
local INFO_IXOR_C7 = makeInfo("IXOR_C7", OP_IXOR_C7, Xor_ri, -1)
local INFO_IADD_C8 = makeInfo("IADD_C8", OP_IADD_C8, Add_ri, -1)
local INFO_IXOR_C8 = makeInfo("IXOR_C8", OP_IXOR_C8, Xor_ri, -1)
local INFO_IADD_C9 = makeInfo("IADD_C9", OP_IADD_C9, Add_ri, -1)
local INFO_IXOR_C9 = makeInfo("IXOR_C9", OP_IXOR_C9, Xor_ri, -1)
local INFO_IMULH_R = makeMultiInfo("IMULH_R", OP_IMULH_R, { Mov_rr, Mul_r, Mov_rr }, 1, 0, 1)
local INFO_ISMULH_R = makeMultiInfo("ISMULH_R", OP_ISMULH_R, { Mov_rr, Imul_r, Mov_rr }, 1, 0, 1)
local INFO_IMUL_RCP = makeMultiInfo("IMUL_RCP", OP_IMUL_RCP, { Mov_ri64, dependentOp(Imul_rr) }, 1, 1, -1)
local INFO_NOP: InstrInfo = {
	name = "NOP",
	type = OP_INVALID,
	ops = {},
	latency = 0,
	resultOp = 0,
	dstOp = 0,
	srcOp = -1,
	isSimple = false,
}

local function isMultiplication(t: number): boolean
	return t == OP_IMUL_R or t == OP_IMULH_R or t == OP_ISMULH_R or t == OP_IMUL_RCP
end

--------------------------------------------------------------------------------
-- DecoderBuffers
--------------------------------------------------------------------------------

type DecoderBuffer = {
	name: string,
	index: number,
	counts: { number },
	size: number,
}

local DecoderBufferDefault: DecoderBuffer = { name = "default", index = -1, counts = {}, size = 0 }

local decodeBuffer484: DecoderBuffer = { name = "4,8,4", index = 0, counts = { 4, 8, 4 }, size = 3 }
local decodeBuffer7333: DecoderBuffer = { name = "7,3,3,3", index = 1, counts = { 7, 3, 3, 3 }, size = 4 }
local decodeBuffer3733: DecoderBuffer = { name = "3,7,3,3", index = 2, counts = { 3, 7, 3, 3 }, size = 4 }
local decodeBuffer493: DecoderBuffer = { name = "4,9,3", index = 3, counts = { 4, 9, 3 }, size = 3 }
local decodeBuffer4444: DecoderBuffer = { name = "4,4,4,4", index = 4, counts = { 4, 4, 4, 4 }, size = 4 }
local decodeBuffer3310: DecoderBuffer = { name = "3,3,10", index = 5, counts = { 3, 3, 10 }, size = 3 }

local decodeBuffers = { decodeBuffer484, decodeBuffer7333, decodeBuffer3733, decodeBuffer493 }

local function fetchNext(instrType: number, cycle: number, mulCount: number, gen: Gen): DecoderBuffer
	-- IMULH/ISMULH must be followed by a 3-3-10 fetch configuration.
	if instrType == OP_IMULH_R or instrType == OP_ISMULH_R then
		return decodeBuffer3310
	end
	-- Saturate the multiplication port when multiplications are scarce.
	if mulCount < cycle + 1 then
		return decodeBuffer4444
	end
	-- IMUL_RCP needs a 4-byte multiplication slot first.
	if instrType == OP_IMUL_RCP then
		return band(gen:getByte(), 1) ~= 0 and decodeBuffer484 or decodeBuffer493
	end
	-- Default: random fetch configuration.
	return decodeBuffers[band(gen:getByte(), 3) + 1]
end

--------------------------------------------------------------------------------
-- Slots
--------------------------------------------------------------------------------

local slot_3 = { INFO_ISUB_R, INFO_IXOR_R }
local slot_3L = { INFO_ISUB_R, INFO_IXOR_R, INFO_IMULH_R, INFO_ISMULH_R }
local slot_4 = { INFO_IROR_C, INFO_IADD_RS }
local slot_7 = { INFO_IXOR_C7, INFO_IADD_C7 }
local slot_8 = { INFO_IXOR_C8, INFO_IADD_C8 }
local slot_9 = { INFO_IXOR_C9, INFO_IADD_C9 }
local slot_10 = INFO_IMUL_RCP

--------------------------------------------------------------------------------
-- SuperscalarInstruction
--------------------------------------------------------------------------------

type Instr = {
	info: InstrInfo,
	src: number,
	dst: number,
	mod: number,
	imm32: number,
	opGroup: number,
	opGroupPar: number,
	canReuse: boolean,
	groupParIsSource: boolean,
}

local function newInstr(info: InstrInfo): Instr
	return {
		info = info,
		src = -1,
		dst = -1,
		mod = 0,
		imm32 = 0,
		opGroup = OP_INVALID,
		opGroupPar = -1,
		canReuse = false,
		groupParIsSource = false,
	}
end

local function nullInstr(): Instr
	return newInstr(INFO_NOP)
end

type EncodedInstr = { op: number, dst: number, src: number, mod: number, imm: number }

-- translation to a RandomX instruction
local function toInstr(ins: Instr): EncodedInstr
	return {
		op = ins.info.type,
		dst = ins.dst,
		src = ins.src >= 0 and ins.src or ins.dst,
		mod = ins.mod,
		imm = ins.imm32,
	}
end

local function create(ins: Instr, info: InstrInfo, gen: Gen)
	ins.info = info
	ins.src = -1
	ins.dst = -1
	ins.canReuse = false
	ins.groupParIsSource = false
	local t = info.type
	if t == OP_ISUB_R then
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IADD_RS
		ins.groupParIsSource = true
	elseif t == OP_IXOR_R then
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IXOR_R
		ins.groupParIsSource = true
	elseif t == OP_IADD_RS then
		ins.mod = gen:getByte()
		ins.imm32 = 0
		ins.opGroup = OP_IADD_RS
		ins.groupParIsSource = true
	elseif t == OP_IMUL_R then
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IMUL_R
		ins.groupParIsSource = true
	elseif t == OP_IROR_C then
		ins.mod = 0
		repeat
			ins.imm32 = band(gen:getByte(), 63)
		until ins.imm32 ~= 0
		ins.opGroup = OP_IROR_C
		ins.opGroupPar = -1
	elseif t == OP_IADD_C7 or t == OP_IADD_C8 or t == OP_IADD_C9 then
		ins.mod = 0
		ins.imm32 = gen:getUInt32()
		ins.opGroup = OP_IADD_C7
		ins.opGroupPar = -1
	elseif t == OP_IXOR_C7 or t == OP_IXOR_C8 or t == OP_IXOR_C9 then
		ins.mod = 0
		ins.imm32 = gen:getUInt32()
		ins.opGroup = OP_IXOR_C7
		ins.opGroupPar = -1
	elseif t == OP_IMULH_R then
		ins.canReuse = true
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_IMULH_R
		ins.opGroupPar = gen:getUInt32()
	elseif t == OP_ISMULH_R then
		ins.canReuse = true
		ins.mod = 0
		ins.imm32 = 0
		ins.opGroup = OP_ISMULH_R
		ins.opGroupPar = gen:getUInt32()
	elseif t == OP_IMUL_RCP then
		ins.mod = 0
		repeat
			ins.imm32 = gen:getUInt32()
		until not isZeroOrPowerOf2(ins.imm32)
		ins.opGroup = OP_IMUL_RCP
		ins.opGroupPar = -1
	end
end

local function createForSlot(ins: Instr, gen: Gen, slotSize: number, fetchType: number, isLast: boolean)
	if slotSize == 3 then
		if isLast then
			create(ins, slot_3L[band(gen:getByte(), 3) + 1], gen)
		else
			create(ins, slot_3[band(gen:getByte(), 1) + 1], gen)
		end
	elseif slotSize == 4 then
		if fetchType == 4 and not isLast then
			create(ins, INFO_IMUL_R, gen)
		else
			create(ins, slot_4[band(gen:getByte(), 1) + 1], gen)
		end
	elseif slotSize == 7 then
		create(ins, slot_7[band(gen:getByte(), 1) + 1], gen)
	elseif slotSize == 8 then
		create(ins, slot_8[band(gen:getByte(), 1) + 1], gen)
	elseif slotSize == 9 then
		create(ins, slot_9[band(gen:getByte(), 1) + 1], gen)
	elseif slotSize == 10 then
		create(ins, slot_10, gen)
	else
		error("invalid slot size " .. tostring(slotSize))
	end
end

type RegInfo = { latency: number, lastOpGroup: number, lastOpPar: number, value: number }

local function selectRegister(available: { number }, gen: Gen): number
	if #available == 0 then
		return -1
	end
	local index = 1
	if #available > 1 then
		index = math.fmod(gen:getUInt32(), #available) + 1
	end
	return available[index]
end

local function selectDestination(ins: Instr, cycle: number, allowChainedMul: boolean, registers: { RegInfo }, gen: Gen): boolean
	local available = {}
	local t = ins.info.type
	for i = 0, RegistersCount - 1 do
		local ri = registers[i + 1]
		if
			ri.latency <= cycle
			and (ins.canReuse or i ~= ins.src)
			and (allowChainedMul or ins.opGroup ~= OP_IMUL_R or ri.lastOpGroup ~= OP_IMUL_R)
			and (ri.lastOpGroup ~= ins.opGroup or ri.lastOpPar ~= ins.opGroupPar)
			and (t ~= OP_IADD_RS or i ~= RegisterNeedsDisplacement)
		then
			available[#available + 1] = i
		end
	end
	local reg = selectRegister(available, gen)
	if reg < 0 then
		return false
	end
	ins.dst = reg
	return true
end

local function selectSource(ins: Instr, cycle: number, registers: { RegInfo }, gen: Gen): boolean
	local available = {}
	for i = 0, RegistersCount - 1 do
		if registers[i + 1].latency <= cycle then
			available[#available + 1] = i
		end
	end
	-- r5 cannot be the destination of IADD_RS, so prefer it as the source
	if #available == 2 and ins.info.type == OP_IADD_RS then
		if available[1] == RegisterNeedsDisplacement or available[2] == RegisterNeedsDisplacement then
			ins.opGroupPar = RegisterNeedsDisplacement
			ins.src = RegisterNeedsDisplacement
			return true
		end
	end
	local reg = selectRegister(available, gen)
	if reg < 0 then
		return false
	end
	ins.src = reg
	if ins.groupParIsSource then
		ins.opGroupPar = reg
	end
	return true
end

--------------------------------------------------------------------------------
-- Scheduling
--------------------------------------------------------------------------------

type Bools = { boolean }
type PortBusy = { Bools }

local function scheduleUop(uop: number, portBusy: PortBusy, cycle: number, commit: boolean): number
	while cycle < CYCLE_MAP_SIZE do
		local idx = cycle + 1
		if band(uop, PORT_P5) ~= 0 and not portBusy[3][idx] then
			if commit then
				portBusy[3][idx] = true
			end
			return cycle
		end
		if band(uop, PORT_P0) ~= 0 and not portBusy[1][idx] then
			if commit then
				portBusy[1][idx] = true
			end
			return cycle
		end
		if band(uop, PORT_P1) ~= 0 and not portBusy[2][idx] then
			if commit then
				portBusy[2][idx] = true
			end
			return cycle
		end
		cycle = cycle + 1
	end
	return -1
end

local function scheduleMop(m: MacroOp, portBusy: PortBusy, cycle: number, depCycle: number, commit: boolean): number
	-- explicit dependency chain (IMUL_RCP) pushes the start cycle out
	if m.dependent and depCycle > cycle then
		cycle = depCycle
	end
	-- eliminated macro-ops (moves) need no execution unit
	if isEliminated(m) then
		return cycle
	elseif isSimple(m) then
		return scheduleUop(m.uop1, portBusy, cycle, commit)
	else
		-- 2 uOPs must retire in the same cycle
		while cycle < CYCLE_MAP_SIZE do
			local cycle1 = scheduleUop(m.uop1, portBusy, cycle, false)
			local cycle2 = scheduleUop(m.uop2, portBusy, cycle, false)
			if cycle1 >= 0 and cycle1 == cycle2 then
				if commit then
					scheduleUop(m.uop1, portBusy, cycle1, true)
					scheduleUop(m.uop2, portBusy, cycle2, true)
				end
				return cycle1
			end
			cycle = cycle + 1
		end
		return -1
	end
end

--------------------------------------------------------------------------------
-- generateSuperscalar
--------------------------------------------------------------------------------

function M.generate(gen: Gen)
	local portBusy: PortBusy = { {}, {}, {} }
	for i = 1, CYCLE_MAP_SIZE do
		portBusy[1][i] = false
		portBusy[2][i] = false
		portBusy[3][i] = false
	end
	local registers: { RegInfo } = {}
	for i = 1, RegistersCount do
		registers[i] = { latency = 0, lastOpGroup = OP_INVALID, lastOpPar = -1, value = 0 }
	end

	local decodeBuffer = DecoderBufferDefault
	local currentInstruction = nullInstr()
	local macroOpIndex = 0
	local codeSize = 0
	local macroOpCount = 0
	local cycle = 0
	local depCycle = 0
	local retireCycle = 0
	local portsSaturated = false
	local programSize = 0
	local mulCount = 0
	local decodeCycle = 0
	local throwAwayCount = 0
	local program: { EncodedInstr } = {}

	local decodeCycleStop = false
	while decodeCycle < RANDOMX_SUPERSCALAR_LATENCY and not portsSaturated and programSize < SuperscalarMaxSize do
		decodeBuffer = fetchNext(currentInstruction.info.type, decodeCycle, mulCount, gen)

		local bufferIndex = 0
		while bufferIndex < decodeBuffer.size do
			local topCycle = cycle

			-- all macro-ops of the current RandomX instruction issued: pick a new instruction
			if macroOpIndex >= #currentInstruction.info.ops then
				if portsSaturated or programSize >= SuperscalarMaxSize then
					break
				end
				local counts = decodeBuffer.counts
				createForSlot(currentInstruction, gen, counts[bufferIndex + 1], decodeBuffer.index, decodeBuffer.size == bufferIndex + 1)
				macroOpIndex = 0
			end

			local info = currentInstruction.info
			local m = info.ops[macroOpIndex + 1]

			-- earliest cycle this macro-op can be scheduled
			local scheduleCycle = scheduleMop(m, portBusy, cycle, depCycle, false)
			if scheduleCycle < 0 then
				portsSaturated = true
				break
			end

			local threwAway = false

			if macroOpIndex == info.srcOp then
				local forward = 0
				while forward < LOOK_FORWARD_CYCLES and not selectSource(currentInstruction, scheduleCycle, registers, gen) do
					forward = forward + 1
					scheduleCycle = scheduleCycle + 1
					cycle = cycle + 1
				end
				if forward == LOOK_FORWARD_CYCLES then
					if throwAwayCount < MAX_THROWAWAY_COUNT then
						throwAwayCount = throwAwayCount + 1
						macroOpIndex = #info.ops
						threwAway = true
					else
						currentInstruction = nullInstr()
						break
					end
				end
			end

			if not threwAway and macroOpIndex == info.dstOp then
				local forward = 0
				while forward < LOOK_FORWARD_CYCLES and not selectDestination(currentInstruction, scheduleCycle, throwAwayCount > 0, registers, gen) do
					forward = forward + 1
					scheduleCycle = scheduleCycle + 1
					cycle = cycle + 1
				end
				if forward == LOOK_FORWARD_CYCLES then
					if throwAwayCount < MAX_THROWAWAY_COUNT then
						throwAwayCount = throwAwayCount + 1
						macroOpIndex = #info.ops
						threwAway = true
					else
						currentInstruction = nullInstr()
						break
					end
				end
			end

			if threwAway then
				continue
			end

			throwAwayCount = 0

			-- re-schedule with the actual operand availability
			scheduleCycle = scheduleMop(m, portBusy, scheduleCycle, scheduleCycle, true)
			if scheduleCycle < 0 then
				portsSaturated = true
				break
			end

			depCycle = scheduleCycle + m.latency

			if macroOpIndex == info.resultOp then
				local dst = currentInstruction.dst
				local ri = registers[dst + 1]
				retireCycle = depCycle
				ri.latency = retireCycle
				ri.lastOpGroup = currentInstruction.opGroup
				ri.lastOpPar = currentInstruction.opGroupPar
			end

			codeSize = codeSize + m.size
			bufferIndex = bufferIndex + 1
			macroOpIndex = macroOpIndex + 1
			macroOpCount = macroOpCount + 1

			if scheduleCycle >= RANDOMX_SUPERSCALAR_LATENCY then
				portsSaturated = true
			end
			cycle = topCycle

			if macroOpIndex >= #info.ops then
				programSize = programSize + 1
				program[programSize] = toInstr(currentInstruction)
				if isMultiplication(info.type) then
					mulCount = mulCount + 1
				end
			end
		end
		cycle = cycle + 1
		decodeCycle = decodeCycle + 1
	end
	if decodeCycleStop then
		decodeCycle = decodeCycle
	end

	local ipc = macroOpCount / retireCycle

	-- ASIC latency: 1 cycle per operation, unlimited parallelization
	local asicLatencies = { 0, 0, 0, 0, 0, 0, 0, 0 }
	for i = 1, programSize do
		local instr = program[i]
		local latDst = asicLatencies[instr.dst + 1] + 1
		local latSrc = instr.dst ~= instr.src and asicLatencies[instr.src + 1] + 1 or 0
		asicLatencies[instr.dst + 1] = math.max(latDst, latSrc)
	end

	-- address register is the register with the highest ASIC latency
	local asicLatencyMax = 0
	local addressReg = 0
	local cpuLatencies = {}
	for i = 0, RegistersCount - 1 do
		if asicLatencies[i + 1] > asicLatencyMax then
			asicLatencyMax = asicLatencies[i + 1]
			addressReg = i
		end
		cpuLatencies[i + 1] = registers[i + 1].latency
	end

	return {
		size = programSize,
		addrReg = addressReg,
		ins = program,
		asicLatencies = asicLatencies,
		cpuLatencies = cpuLatencies,
		cpuLatency = retireCycle,
		asicLatency = asicLatencyMax,
		codeSize = codeSize,
		macroOps = macroOpCount,
		decodeCycles = decodeCycle,
		ipc = ipc,
		mulCount = mulCount,
	}
end

--------------------------------------------------------------------------------
-- Encoding / interpretation
--------------------------------------------------------------------------------

function M.encode(prog): string
	local parts = {}
	local ins = prog.ins
	for i = 1, prog.size do
		local v = ins[i]
		local imm = v.imm % 0x100000000
		parts[#parts + 1] = string.char(
			band(v.op, 0xFF),
			band(v.dst, 0xFF),
			band(v.src, 0xFF),
			band(v.mod, 0xFF),
			imm % 256,
			math.floor(imm / 256) % 256,
			math.floor(imm / 65536) % 256,
			math.floor(imm / 16777216) % 256
		)
	end
	return table.concat(parts)
end

-- rlo/rhi: 1..8 registers. Each register may be either a {lo, hi} pair stored in
-- rlo[i], or rlo[i]/rhi[i] holding the low/high halfword directly.
function M.execute(prog, rlo, rhi)
	local paired = type(rlo[1]) == "table"
	local lo, hi = {}, {}
	for i = 1, RegistersCount do
		if paired then
			local v = rlo[i]
			lo[i] = (v and v[1]) or 0
			hi[i] = (v and v[2]) or 0
		else
			lo[i] = rlo[i] or 0
			hi[i] = (rhi and rhi[i]) or 0
		end
	end

	local ins = prog.ins
	for j = 1, prog.size do
		local instr = ins[j]
		local dst = instr.dst + 1
		local src = instr.src + 1
		local op = instr.op
		if op == OP_ISUB_R then
			lo[dst], hi[dst] = sub64(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_IXOR_R then
			lo[dst] = bxor(lo[dst], lo[src])
			hi[dst] = bxor(hi[dst], hi[src])
		elseif op == OP_IADD_RS then
			local sh = rshift(instr.mod, 2) % 4
			local slo, shi = shl64(lo[src], hi[src], sh)
			lo[dst], hi[dst] = add64(lo[dst], hi[dst], slo, shi)
		elseif op == OP_IMUL_R then
			lo[dst], hi[dst] = mul64lo(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_IROR_C then
			lo[dst], hi[dst] = rotr64(lo[dst], hi[dst], instr.imm % 64)
		elseif op == OP_IADD_C7 or op == OP_IADD_C8 or op == OP_IADD_C9 then
			local imm = instr.imm
			if imm >= 0x80000000 then
				imm = imm - 0x100000000
			end
			if imm >= 0 then
				lo[dst], hi[dst] = add64(lo[dst], hi[dst], imm, 0)
			else
				lo[dst], hi[dst] = sub64(lo[dst], hi[dst], -imm, 0)
			end
		elseif op == OP_IXOR_C7 or op == OP_IXOR_C8 or op == OP_IXOR_C9 then
			local imm = instr.imm
			if imm >= 0x80000000 then -- sign extend
				imm = imm - 0x100000000
			end
			lo[dst] = bxor(lo[dst], imm % 0x100000000)
			hi[dst] = bxor(hi[dst], imm < 0 and MASK32 or 0)
		elseif op == OP_IMULH_R then
			lo[dst], hi[dst] = mul64hi(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_ISMULH_R then
			lo[dst], hi[dst] = smul64hi(lo[dst], hi[dst], lo[src], hi[src])
		elseif op == OP_IMUL_RCP then
			local rcpLo, rcpHi = M.reciprocal(instr.imm)
			lo[dst], hi[dst] = mul64lo(lo[dst], hi[dst], rcpLo, rcpHi)
		else
			error("invalid opcode " .. tostring(op))
		end
	end

	for i = 1, RegistersCount do
		if paired then
			local v = rlo[i]
			if v then
				v[1] = lo[i]
				v[2] = hi[i]
			else
				rlo[i] = { lo[i], hi[i] }
			end
		else
			rlo[i] = lo[i]
			rhi[i] = hi[i]
		end
	end
end

return M
