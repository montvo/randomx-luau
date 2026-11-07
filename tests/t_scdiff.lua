--!nocheck
-- Kompilovane superscalar programy vs. interpreter: po kazdem programu musi byt
-- registr soubor stejny (600 nahodnych programu).
local blake = require("../src/blake2b")
local ss = require("../src/superscalar")
local rx = require("../src/rx")
local key = string.char(1,2,3,4,5,6,7,8)
local cache = buffer.create(262144*1024)
local sgen = ss.newGen(blake, key)
local band, bor, bxor, lshift, rshift = bit32.band, bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift
local W = 4294967296
local function ad64(alo,ahi,blo,bhi) local lo=alo+blo local c=0 if lo>=W then lo=lo-W c=1 end local hi=ahi+bhi+c return lo,(hi>=W and hi-W or hi) end
local function sb64(alo,ahi,blo,bhi) local lo=alo-blo local b=0 if lo<0 then lo=lo+W b=1 end local hi=ahi-bhi-b return lo,(hi<0 and hi+W or hi) end
local function ml(a0,a1,a2,a3,b0,b1,b2,b3)
	local o={} local t=a0*b0 local o0=t%65536 t=a0*b1+a1*b0+(t-o0)/65536 local o1=t%65536
	t=a0*b2+a1*b1+a2*b0+(t-o1)/65536 local o2=t%65536
	t=a0*b3+a1*b2+a2*b1+a3*b0+(t-o2)/65536 local o3=t%65536
	return o0+o1*65536, o2+o3*65536 end
local function mul64lo(alo,ahi,blo,bhi)
	local a0=alo%65536 local a1=(alo-a0)/65536 local a2=ahi%65536 local a3=(ahi-a2)/65536
	local b0=blo%65536 local b1=(blo-b0)/65536 local b2=bhi%65536 local b3=(bhi-b2)/65536
	return ml(a0,a1,a2,a3,b0,b1,b2,b3) end
local function fullML(alo,ahi,blo,bhi)
	local a0=alo%65536 local a1=(alo-a0)/65536 local a2=ahi%65536 local a3=(ahi-a2)/65536
	local b0=blo%65536 local b1=(blo-b0)/65536 local b2=bhi%65536 local b3=(bhi-b2)/65536
	local c0=a0*b0 local c1=a0*b1+a1*b0 local c2=a0*b2+a1*b1+a2*b0 local c3=a0*b3+a1*b2+a2*b1+a3*b0
	local c4=a1*b3+a2*b2+a3*b1 local c5=a2*b3+a3*b2 local c6=a3*b3
	local function ch(c) local o0 = c%65536 local t=c1+(c-o0)/65536 local o1=t%65536
	t=c2+(t-o1)/65536 local o2=t%65536 t=c3+(t-o2)/65536 local o3=t%65536
	t=c4+(t-o3)/65536 return o0,o1,o2,o3,t end
	local o0,o1,o2,o3,t = ch(c0)
	local q0 = t%65536 t=c5+(t-q0)/65536 local q1=t%65536 t=c6+(t-q1)/65536 local q2=t%65536 local q3=(t-q2)/65536
	return o0,o1,o2,o3,q0,q1,q2,q3 end
local function mul64hi(alo,ahi,blo,bhi) local _,_,_,_,o4,o5,o6,o7 = fullML(alo,ahi,blo,bhi) return o4+o5*65536, o6+o7*65536 end
local function divmod64(dlo,dhi,d)
	local qlo,qhi,rlo,rhi=0,0,0,0
	for i=63,0,-1 do
		local lo1=rlo*2 if lo1>=W then lo1=lo1-W end
		local hi1=rhi*2+(rlo*2-lo1)/W
		local bit if i>=32 then bit=band(rshift(dhi,i-32),1) else bit=band(rshift(dlo,i),1) end
		rlo,rhi=lo1,hi1 rlo=bor(rlo,bit)
		if rhi>0 or rlo>=d then
			local lo2=rlo-d local b=0 if lo2<0 then lo2=lo2+W b=1 end
			rlo=lo2 rhi=rhi-b
			if i>=32 then qhi=bor(qhi,lshift(1,i-32)) else qlo=bor(qlo,lshift(1,i)) end
		end
	end
	return qlo,qhi,rlo,rhi
end
local function shl64(lo,hi,n) if n==0 then return lo,hi end if n>=32 then return 0,lshift(lo,n-32) end return lshift(lo,n),bor(lshift(hi,n),rshift(lo,32-n)) end
local function recip(d)
	local qlo,qhi = divmod64(0,2147483648,d)
	local shift=32 local k=2147483648
	while k>0 do if band(k,d)~=0 then break end k=rshift(k,1) shift=shift-1 end
	local slo,shi=shl64(qlo,qhi,shift)
	return slo,shi
end
local function signExt(imm) if imm>=2147483648 then return imm,0xFFFFFFFF end return imm,0 end
math.randomseed(11)
for it=1,50 do
	local prog = ss.generate(sgen)
	local full = prog.size
	local A,B={},{}
	for i=1,8 do A[i]=math.random(0,4294967295) B[i]=math.random(0,4294967295) end
	for k=1,full do
		prog.size = k
		local C,D={},{} for i=1,8 do C[i]=A[i] D[i]=B[i] end
		local E,F={},{} for i=1,8 do E[i]=A[i] F[i]=B[i] end
		prog.fn = nil rx._runsuper(prog,E,F)
		prog.fn = false rx._runsuper(prog,C,D)
		local diff = false
		for i=1,8 do if E[i]~=C[i] or F[i]~=D[i] then diff=true break end end
		if diff then
			local i2 = prog.ins[k]
			print(string.format("it%d k%d op%d d%d s%d imm%08x mod%08x", it, k, i2.op, i2.dst, i2.src, i2.imm, i2.mod))
			print("radek: " .. tostring((prog.src or ""):match("[^\n]*$")))
			for i=1,8 do if E[i]~=C[i] or F[i]~=D[i] then
				print(string.format("reg%d compiled %08x %08x interp %08x %08x", i, E[i],F[i],C[i],D[i])) end end
			local i2b = prog.ins[k]
			local mini = { size = 1, addrReg = 0, ins = { { op = i2b.op, dst = i2b.dst, src = i2b.src, imm = i2b.imm, mod = i2b.mod } } }
			local G,H,I,J = {},{},{},{}
			for i=1,8 do G[i]=A[i] H[i]=B[i] I[i]=A[i] J[i]=B[i] end
			mini.fn = nil rx._runsuper(mini,G,H)
			mini.fn = false rx._runsuper(mini,I,J)
			print("mini zdroj >>>" .. tostring(mini.src):gsub("\n"," | ") .. "<<<")
			print(string.format("mini in %08x %08x compiled %08x %08x | interp %08x %08x", A[i2b.dst+1],B[i2b.dst+1], G[i2b.dst+1],H[i2b.dst+1],I[i2b.dst+1],J[i2b.dst+1]))
			local lines = {}
			for l in (prog.src or ""):gmatch("[^\n]+") do lines[#lines+1]=l end
			for j=1,k do
				local i2b = prog.ins[j]
				print(string.format("%2d op%-2d d%d s%d imm%08x mod%08x | %s", j, i2b.op, i2b.dst, i2b.src, i2b.imm, i2b.mod, tostring(lines[j+2])))
			end
			return
		end
		-- posun stavu pro dalsi k pomoci interp
		A,B = C,D
	end
end
print("bez rozdilu (600 programu)")
