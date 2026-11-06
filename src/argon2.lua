-- Argon2d "memory fill" exactly as RandomX uses it (no finalization).
-- lanes=1, m_cost=262144 blocks of 1024 B, t_cost=3, version=0x13, type=0.
-- Pure Luau; 64-bit words are (lo, hi) pairs of 32-bit words held in a buffer.
local band, bor, bxor, lshift, rshift =
	bit32.band, bit32.bor, bit32.bxor, bit32.lshift, bit32.rshift
local readu32, writeu32 = buffer.readu32, buffer.writeu32
local W = 4294967296

local LANES = 1
local M_COST = 262144
local T_COST = 3
local VERSION = 0x13
local ARGON2_D = 0
local SEG_LEN = 65536
local LANE_LEN = 262144
local BLOCK = 1024
local SALT = "RandomX" -- 8 bytes, no NUL terminator
local SALT_LEN = 8

local R = table.create(256, 0)
local T = table.create(256, 0)


local function fillBlock(mem, prv, ref, cur)
do
  local pl = readu32(mem, prv + 0)
  local ph = readu32(mem, prv + 4)
  local l0 = bxor(pl, readu32(mem, ref + 0))
  local h0 = bxor(ph, readu32(mem, ref + 4))
  R[1] = l0; R[2] = h0
  T[1] = l0; T[2] = h0
  local pl = readu32(mem, prv + 8)
  local ph = readu32(mem, prv + 12)
  local l1 = bxor(pl, readu32(mem, ref + 8))
  local h1 = bxor(ph, readu32(mem, ref + 12))
  R[3] = l1; R[4] = h1
  T[3] = l1; T[4] = h1
  local pl = readu32(mem, prv + 16)
  local ph = readu32(mem, prv + 20)
  local l2 = bxor(pl, readu32(mem, ref + 16))
  local h2 = bxor(ph, readu32(mem, ref + 20))
  R[5] = l2; R[6] = h2
  T[5] = l2; T[6] = h2
  local pl = readu32(mem, prv + 24)
  local ph = readu32(mem, prv + 28)
  local l3 = bxor(pl, readu32(mem, ref + 24))
  local h3 = bxor(ph, readu32(mem, ref + 28))
  R[7] = l3; R[8] = h3
  T[7] = l3; T[8] = h3
  local pl = readu32(mem, prv + 32)
  local ph = readu32(mem, prv + 36)
  local l4 = bxor(pl, readu32(mem, ref + 32))
  local h4 = bxor(ph, readu32(mem, ref + 36))
  R[9] = l4; R[10] = h4
  T[9] = l4; T[10] = h4
  local pl = readu32(mem, prv + 40)
  local ph = readu32(mem, prv + 44)
  local l5 = bxor(pl, readu32(mem, ref + 40))
  local h5 = bxor(ph, readu32(mem, ref + 44))
  R[11] = l5; R[12] = h5
  T[11] = l5; T[12] = h5
  local pl = readu32(mem, prv + 48)
  local ph = readu32(mem, prv + 52)
  local l6 = bxor(pl, readu32(mem, ref + 48))
  local h6 = bxor(ph, readu32(mem, ref + 52))
  R[13] = l6; R[14] = h6
  T[13] = l6; T[14] = h6
  local pl = readu32(mem, prv + 56)
  local ph = readu32(mem, prv + 60)
  local l7 = bxor(pl, readu32(mem, ref + 56))
  local h7 = bxor(ph, readu32(mem, ref + 60))
  R[15] = l7; R[16] = h7
  T[15] = l7; T[16] = h7
  local pl = readu32(mem, prv + 64)
  local ph = readu32(mem, prv + 68)
  local l8 = bxor(pl, readu32(mem, ref + 64))
  local h8 = bxor(ph, readu32(mem, ref + 68))
  R[17] = l8; R[18] = h8
  T[17] = l8; T[18] = h8
  local pl = readu32(mem, prv + 72)
  local ph = readu32(mem, prv + 76)
  local l9 = bxor(pl, readu32(mem, ref + 72))
  local h9 = bxor(ph, readu32(mem, ref + 76))
  R[19] = l9; R[20] = h9
  T[19] = l9; T[20] = h9
  local pl = readu32(mem, prv + 80)
  local ph = readu32(mem, prv + 84)
  local l10 = bxor(pl, readu32(mem, ref + 80))
  local h10 = bxor(ph, readu32(mem, ref + 84))
  R[21] = l10; R[22] = h10
  T[21] = l10; T[22] = h10
  local pl = readu32(mem, prv + 88)
  local ph = readu32(mem, prv + 92)
  local l11 = bxor(pl, readu32(mem, ref + 88))
  local h11 = bxor(ph, readu32(mem, ref + 92))
  R[23] = l11; R[24] = h11
  T[23] = l11; T[24] = h11
  local pl = readu32(mem, prv + 96)
  local ph = readu32(mem, prv + 100)
  local l12 = bxor(pl, readu32(mem, ref + 96))
  local h12 = bxor(ph, readu32(mem, ref + 100))
  R[25] = l12; R[26] = h12
  T[25] = l12; T[26] = h12
  local pl = readu32(mem, prv + 104)
  local ph = readu32(mem, prv + 108)
  local l13 = bxor(pl, readu32(mem, ref + 104))
  local h13 = bxor(ph, readu32(mem, ref + 108))
  R[27] = l13; R[28] = h13
  T[27] = l13; T[28] = h13
  local pl = readu32(mem, prv + 112)
  local ph = readu32(mem, prv + 116)
  local l14 = bxor(pl, readu32(mem, ref + 112))
  local h14 = bxor(ph, readu32(mem, ref + 116))
  R[29] = l14; R[30] = h14
  T[29] = l14; T[30] = h14
  local pl = readu32(mem, prv + 120)
  local ph = readu32(mem, prv + 124)
  local l15 = bxor(pl, readu32(mem, ref + 120))
  local h15 = bxor(ph, readu32(mem, ref + 124))
  R[31] = l15; R[32] = h15
  T[31] = l15; T[32] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[1] = l0; R[2] = h0
  R[3] = l1; R[4] = h1
  R[5] = l2; R[6] = h2
  R[7] = l3; R[8] = h3
  R[9] = l4; R[10] = h4
  R[11] = l5; R[12] = h5
  R[13] = l6; R[14] = h6
  R[15] = l7; R[16] = h7
  R[17] = l8; R[18] = h8
  R[19] = l9; R[20] = h9
  R[21] = l10; R[22] = h10
  R[23] = l11; R[24] = h11
  R[25] = l12; R[26] = h12
  R[27] = l13; R[28] = h13
  R[29] = l14; R[30] = h14
  R[31] = l15; R[32] = h15
end
do
  local pl = readu32(mem, prv + 128)
  local ph = readu32(mem, prv + 132)
  local l0 = bxor(pl, readu32(mem, ref + 128))
  local h0 = bxor(ph, readu32(mem, ref + 132))
  R[33] = l0; R[34] = h0
  T[33] = l0; T[34] = h0
  local pl = readu32(mem, prv + 136)
  local ph = readu32(mem, prv + 140)
  local l1 = bxor(pl, readu32(mem, ref + 136))
  local h1 = bxor(ph, readu32(mem, ref + 140))
  R[35] = l1; R[36] = h1
  T[35] = l1; T[36] = h1
  local pl = readu32(mem, prv + 144)
  local ph = readu32(mem, prv + 148)
  local l2 = bxor(pl, readu32(mem, ref + 144))
  local h2 = bxor(ph, readu32(mem, ref + 148))
  R[37] = l2; R[38] = h2
  T[37] = l2; T[38] = h2
  local pl = readu32(mem, prv + 152)
  local ph = readu32(mem, prv + 156)
  local l3 = bxor(pl, readu32(mem, ref + 152))
  local h3 = bxor(ph, readu32(mem, ref + 156))
  R[39] = l3; R[40] = h3
  T[39] = l3; T[40] = h3
  local pl = readu32(mem, prv + 160)
  local ph = readu32(mem, prv + 164)
  local l4 = bxor(pl, readu32(mem, ref + 160))
  local h4 = bxor(ph, readu32(mem, ref + 164))
  R[41] = l4; R[42] = h4
  T[41] = l4; T[42] = h4
  local pl = readu32(mem, prv + 168)
  local ph = readu32(mem, prv + 172)
  local l5 = bxor(pl, readu32(mem, ref + 168))
  local h5 = bxor(ph, readu32(mem, ref + 172))
  R[43] = l5; R[44] = h5
  T[43] = l5; T[44] = h5
  local pl = readu32(mem, prv + 176)
  local ph = readu32(mem, prv + 180)
  local l6 = bxor(pl, readu32(mem, ref + 176))
  local h6 = bxor(ph, readu32(mem, ref + 180))
  R[45] = l6; R[46] = h6
  T[45] = l6; T[46] = h6
  local pl = readu32(mem, prv + 184)
  local ph = readu32(mem, prv + 188)
  local l7 = bxor(pl, readu32(mem, ref + 184))
  local h7 = bxor(ph, readu32(mem, ref + 188))
  R[47] = l7; R[48] = h7
  T[47] = l7; T[48] = h7
  local pl = readu32(mem, prv + 192)
  local ph = readu32(mem, prv + 196)
  local l8 = bxor(pl, readu32(mem, ref + 192))
  local h8 = bxor(ph, readu32(mem, ref + 196))
  R[49] = l8; R[50] = h8
  T[49] = l8; T[50] = h8
  local pl = readu32(mem, prv + 200)
  local ph = readu32(mem, prv + 204)
  local l9 = bxor(pl, readu32(mem, ref + 200))
  local h9 = bxor(ph, readu32(mem, ref + 204))
  R[51] = l9; R[52] = h9
  T[51] = l9; T[52] = h9
  local pl = readu32(mem, prv + 208)
  local ph = readu32(mem, prv + 212)
  local l10 = bxor(pl, readu32(mem, ref + 208))
  local h10 = bxor(ph, readu32(mem, ref + 212))
  R[53] = l10; R[54] = h10
  T[53] = l10; T[54] = h10
  local pl = readu32(mem, prv + 216)
  local ph = readu32(mem, prv + 220)
  local l11 = bxor(pl, readu32(mem, ref + 216))
  local h11 = bxor(ph, readu32(mem, ref + 220))
  R[55] = l11; R[56] = h11
  T[55] = l11; T[56] = h11
  local pl = readu32(mem, prv + 224)
  local ph = readu32(mem, prv + 228)
  local l12 = bxor(pl, readu32(mem, ref + 224))
  local h12 = bxor(ph, readu32(mem, ref + 228))
  R[57] = l12; R[58] = h12
  T[57] = l12; T[58] = h12
  local pl = readu32(mem, prv + 232)
  local ph = readu32(mem, prv + 236)
  local l13 = bxor(pl, readu32(mem, ref + 232))
  local h13 = bxor(ph, readu32(mem, ref + 236))
  R[59] = l13; R[60] = h13
  T[59] = l13; T[60] = h13
  local pl = readu32(mem, prv + 240)
  local ph = readu32(mem, prv + 244)
  local l14 = bxor(pl, readu32(mem, ref + 240))
  local h14 = bxor(ph, readu32(mem, ref + 244))
  R[61] = l14; R[62] = h14
  T[61] = l14; T[62] = h14
  local pl = readu32(mem, prv + 248)
  local ph = readu32(mem, prv + 252)
  local l15 = bxor(pl, readu32(mem, ref + 248))
  local h15 = bxor(ph, readu32(mem, ref + 252))
  R[63] = l15; R[64] = h15
  T[63] = l15; T[64] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[33] = l0; R[34] = h0
  R[35] = l1; R[36] = h1
  R[37] = l2; R[38] = h2
  R[39] = l3; R[40] = h3
  R[41] = l4; R[42] = h4
  R[43] = l5; R[44] = h5
  R[45] = l6; R[46] = h6
  R[47] = l7; R[48] = h7
  R[49] = l8; R[50] = h8
  R[51] = l9; R[52] = h9
  R[53] = l10; R[54] = h10
  R[55] = l11; R[56] = h11
  R[57] = l12; R[58] = h12
  R[59] = l13; R[60] = h13
  R[61] = l14; R[62] = h14
  R[63] = l15; R[64] = h15
end
do
  local pl = readu32(mem, prv + 256)
  local ph = readu32(mem, prv + 260)
  local l0 = bxor(pl, readu32(mem, ref + 256))
  local h0 = bxor(ph, readu32(mem, ref + 260))
  R[65] = l0; R[66] = h0
  T[65] = l0; T[66] = h0
  local pl = readu32(mem, prv + 264)
  local ph = readu32(mem, prv + 268)
  local l1 = bxor(pl, readu32(mem, ref + 264))
  local h1 = bxor(ph, readu32(mem, ref + 268))
  R[67] = l1; R[68] = h1
  T[67] = l1; T[68] = h1
  local pl = readu32(mem, prv + 272)
  local ph = readu32(mem, prv + 276)
  local l2 = bxor(pl, readu32(mem, ref + 272))
  local h2 = bxor(ph, readu32(mem, ref + 276))
  R[69] = l2; R[70] = h2
  T[69] = l2; T[70] = h2
  local pl = readu32(mem, prv + 280)
  local ph = readu32(mem, prv + 284)
  local l3 = bxor(pl, readu32(mem, ref + 280))
  local h3 = bxor(ph, readu32(mem, ref + 284))
  R[71] = l3; R[72] = h3
  T[71] = l3; T[72] = h3
  local pl = readu32(mem, prv + 288)
  local ph = readu32(mem, prv + 292)
  local l4 = bxor(pl, readu32(mem, ref + 288))
  local h4 = bxor(ph, readu32(mem, ref + 292))
  R[73] = l4; R[74] = h4
  T[73] = l4; T[74] = h4
  local pl = readu32(mem, prv + 296)
  local ph = readu32(mem, prv + 300)
  local l5 = bxor(pl, readu32(mem, ref + 296))
  local h5 = bxor(ph, readu32(mem, ref + 300))
  R[75] = l5; R[76] = h5
  T[75] = l5; T[76] = h5
  local pl = readu32(mem, prv + 304)
  local ph = readu32(mem, prv + 308)
  local l6 = bxor(pl, readu32(mem, ref + 304))
  local h6 = bxor(ph, readu32(mem, ref + 308))
  R[77] = l6; R[78] = h6
  T[77] = l6; T[78] = h6
  local pl = readu32(mem, prv + 312)
  local ph = readu32(mem, prv + 316)
  local l7 = bxor(pl, readu32(mem, ref + 312))
  local h7 = bxor(ph, readu32(mem, ref + 316))
  R[79] = l7; R[80] = h7
  T[79] = l7; T[80] = h7
  local pl = readu32(mem, prv + 320)
  local ph = readu32(mem, prv + 324)
  local l8 = bxor(pl, readu32(mem, ref + 320))
  local h8 = bxor(ph, readu32(mem, ref + 324))
  R[81] = l8; R[82] = h8
  T[81] = l8; T[82] = h8
  local pl = readu32(mem, prv + 328)
  local ph = readu32(mem, prv + 332)
  local l9 = bxor(pl, readu32(mem, ref + 328))
  local h9 = bxor(ph, readu32(mem, ref + 332))
  R[83] = l9; R[84] = h9
  T[83] = l9; T[84] = h9
  local pl = readu32(mem, prv + 336)
  local ph = readu32(mem, prv + 340)
  local l10 = bxor(pl, readu32(mem, ref + 336))
  local h10 = bxor(ph, readu32(mem, ref + 340))
  R[85] = l10; R[86] = h10
  T[85] = l10; T[86] = h10
  local pl = readu32(mem, prv + 344)
  local ph = readu32(mem, prv + 348)
  local l11 = bxor(pl, readu32(mem, ref + 344))
  local h11 = bxor(ph, readu32(mem, ref + 348))
  R[87] = l11; R[88] = h11
  T[87] = l11; T[88] = h11
  local pl = readu32(mem, prv + 352)
  local ph = readu32(mem, prv + 356)
  local l12 = bxor(pl, readu32(mem, ref + 352))
  local h12 = bxor(ph, readu32(mem, ref + 356))
  R[89] = l12; R[90] = h12
  T[89] = l12; T[90] = h12
  local pl = readu32(mem, prv + 360)
  local ph = readu32(mem, prv + 364)
  local l13 = bxor(pl, readu32(mem, ref + 360))
  local h13 = bxor(ph, readu32(mem, ref + 364))
  R[91] = l13; R[92] = h13
  T[91] = l13; T[92] = h13
  local pl = readu32(mem, prv + 368)
  local ph = readu32(mem, prv + 372)
  local l14 = bxor(pl, readu32(mem, ref + 368))
  local h14 = bxor(ph, readu32(mem, ref + 372))
  R[93] = l14; R[94] = h14
  T[93] = l14; T[94] = h14
  local pl = readu32(mem, prv + 376)
  local ph = readu32(mem, prv + 380)
  local l15 = bxor(pl, readu32(mem, ref + 376))
  local h15 = bxor(ph, readu32(mem, ref + 380))
  R[95] = l15; R[96] = h15
  T[95] = l15; T[96] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[65] = l0; R[66] = h0
  R[67] = l1; R[68] = h1
  R[69] = l2; R[70] = h2
  R[71] = l3; R[72] = h3
  R[73] = l4; R[74] = h4
  R[75] = l5; R[76] = h5
  R[77] = l6; R[78] = h6
  R[79] = l7; R[80] = h7
  R[81] = l8; R[82] = h8
  R[83] = l9; R[84] = h9
  R[85] = l10; R[86] = h10
  R[87] = l11; R[88] = h11
  R[89] = l12; R[90] = h12
  R[91] = l13; R[92] = h13
  R[93] = l14; R[94] = h14
  R[95] = l15; R[96] = h15
end
do
  local pl = readu32(mem, prv + 384)
  local ph = readu32(mem, prv + 388)
  local l0 = bxor(pl, readu32(mem, ref + 384))
  local h0 = bxor(ph, readu32(mem, ref + 388))
  R[97] = l0; R[98] = h0
  T[97] = l0; T[98] = h0
  local pl = readu32(mem, prv + 392)
  local ph = readu32(mem, prv + 396)
  local l1 = bxor(pl, readu32(mem, ref + 392))
  local h1 = bxor(ph, readu32(mem, ref + 396))
  R[99] = l1; R[100] = h1
  T[99] = l1; T[100] = h1
  local pl = readu32(mem, prv + 400)
  local ph = readu32(mem, prv + 404)
  local l2 = bxor(pl, readu32(mem, ref + 400))
  local h2 = bxor(ph, readu32(mem, ref + 404))
  R[101] = l2; R[102] = h2
  T[101] = l2; T[102] = h2
  local pl = readu32(mem, prv + 408)
  local ph = readu32(mem, prv + 412)
  local l3 = bxor(pl, readu32(mem, ref + 408))
  local h3 = bxor(ph, readu32(mem, ref + 412))
  R[103] = l3; R[104] = h3
  T[103] = l3; T[104] = h3
  local pl = readu32(mem, prv + 416)
  local ph = readu32(mem, prv + 420)
  local l4 = bxor(pl, readu32(mem, ref + 416))
  local h4 = bxor(ph, readu32(mem, ref + 420))
  R[105] = l4; R[106] = h4
  T[105] = l4; T[106] = h4
  local pl = readu32(mem, prv + 424)
  local ph = readu32(mem, prv + 428)
  local l5 = bxor(pl, readu32(mem, ref + 424))
  local h5 = bxor(ph, readu32(mem, ref + 428))
  R[107] = l5; R[108] = h5
  T[107] = l5; T[108] = h5
  local pl = readu32(mem, prv + 432)
  local ph = readu32(mem, prv + 436)
  local l6 = bxor(pl, readu32(mem, ref + 432))
  local h6 = bxor(ph, readu32(mem, ref + 436))
  R[109] = l6; R[110] = h6
  T[109] = l6; T[110] = h6
  local pl = readu32(mem, prv + 440)
  local ph = readu32(mem, prv + 444)
  local l7 = bxor(pl, readu32(mem, ref + 440))
  local h7 = bxor(ph, readu32(mem, ref + 444))
  R[111] = l7; R[112] = h7
  T[111] = l7; T[112] = h7
  local pl = readu32(mem, prv + 448)
  local ph = readu32(mem, prv + 452)
  local l8 = bxor(pl, readu32(mem, ref + 448))
  local h8 = bxor(ph, readu32(mem, ref + 452))
  R[113] = l8; R[114] = h8
  T[113] = l8; T[114] = h8
  local pl = readu32(mem, prv + 456)
  local ph = readu32(mem, prv + 460)
  local l9 = bxor(pl, readu32(mem, ref + 456))
  local h9 = bxor(ph, readu32(mem, ref + 460))
  R[115] = l9; R[116] = h9
  T[115] = l9; T[116] = h9
  local pl = readu32(mem, prv + 464)
  local ph = readu32(mem, prv + 468)
  local l10 = bxor(pl, readu32(mem, ref + 464))
  local h10 = bxor(ph, readu32(mem, ref + 468))
  R[117] = l10; R[118] = h10
  T[117] = l10; T[118] = h10
  local pl = readu32(mem, prv + 472)
  local ph = readu32(mem, prv + 476)
  local l11 = bxor(pl, readu32(mem, ref + 472))
  local h11 = bxor(ph, readu32(mem, ref + 476))
  R[119] = l11; R[120] = h11
  T[119] = l11; T[120] = h11
  local pl = readu32(mem, prv + 480)
  local ph = readu32(mem, prv + 484)
  local l12 = bxor(pl, readu32(mem, ref + 480))
  local h12 = bxor(ph, readu32(mem, ref + 484))
  R[121] = l12; R[122] = h12
  T[121] = l12; T[122] = h12
  local pl = readu32(mem, prv + 488)
  local ph = readu32(mem, prv + 492)
  local l13 = bxor(pl, readu32(mem, ref + 488))
  local h13 = bxor(ph, readu32(mem, ref + 492))
  R[123] = l13; R[124] = h13
  T[123] = l13; T[124] = h13
  local pl = readu32(mem, prv + 496)
  local ph = readu32(mem, prv + 500)
  local l14 = bxor(pl, readu32(mem, ref + 496))
  local h14 = bxor(ph, readu32(mem, ref + 500))
  R[125] = l14; R[126] = h14
  T[125] = l14; T[126] = h14
  local pl = readu32(mem, prv + 504)
  local ph = readu32(mem, prv + 508)
  local l15 = bxor(pl, readu32(mem, ref + 504))
  local h15 = bxor(ph, readu32(mem, ref + 508))
  R[127] = l15; R[128] = h15
  T[127] = l15; T[128] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[97] = l0; R[98] = h0
  R[99] = l1; R[100] = h1
  R[101] = l2; R[102] = h2
  R[103] = l3; R[104] = h3
  R[105] = l4; R[106] = h4
  R[107] = l5; R[108] = h5
  R[109] = l6; R[110] = h6
  R[111] = l7; R[112] = h7
  R[113] = l8; R[114] = h8
  R[115] = l9; R[116] = h9
  R[117] = l10; R[118] = h10
  R[119] = l11; R[120] = h11
  R[121] = l12; R[122] = h12
  R[123] = l13; R[124] = h13
  R[125] = l14; R[126] = h14
  R[127] = l15; R[128] = h15
end
do
  local pl = readu32(mem, prv + 512)
  local ph = readu32(mem, prv + 516)
  local l0 = bxor(pl, readu32(mem, ref + 512))
  local h0 = bxor(ph, readu32(mem, ref + 516))
  R[129] = l0; R[130] = h0
  T[129] = l0; T[130] = h0
  local pl = readu32(mem, prv + 520)
  local ph = readu32(mem, prv + 524)
  local l1 = bxor(pl, readu32(mem, ref + 520))
  local h1 = bxor(ph, readu32(mem, ref + 524))
  R[131] = l1; R[132] = h1
  T[131] = l1; T[132] = h1
  local pl = readu32(mem, prv + 528)
  local ph = readu32(mem, prv + 532)
  local l2 = bxor(pl, readu32(mem, ref + 528))
  local h2 = bxor(ph, readu32(mem, ref + 532))
  R[133] = l2; R[134] = h2
  T[133] = l2; T[134] = h2
  local pl = readu32(mem, prv + 536)
  local ph = readu32(mem, prv + 540)
  local l3 = bxor(pl, readu32(mem, ref + 536))
  local h3 = bxor(ph, readu32(mem, ref + 540))
  R[135] = l3; R[136] = h3
  T[135] = l3; T[136] = h3
  local pl = readu32(mem, prv + 544)
  local ph = readu32(mem, prv + 548)
  local l4 = bxor(pl, readu32(mem, ref + 544))
  local h4 = bxor(ph, readu32(mem, ref + 548))
  R[137] = l4; R[138] = h4
  T[137] = l4; T[138] = h4
  local pl = readu32(mem, prv + 552)
  local ph = readu32(mem, prv + 556)
  local l5 = bxor(pl, readu32(mem, ref + 552))
  local h5 = bxor(ph, readu32(mem, ref + 556))
  R[139] = l5; R[140] = h5
  T[139] = l5; T[140] = h5
  local pl = readu32(mem, prv + 560)
  local ph = readu32(mem, prv + 564)
  local l6 = bxor(pl, readu32(mem, ref + 560))
  local h6 = bxor(ph, readu32(mem, ref + 564))
  R[141] = l6; R[142] = h6
  T[141] = l6; T[142] = h6
  local pl = readu32(mem, prv + 568)
  local ph = readu32(mem, prv + 572)
  local l7 = bxor(pl, readu32(mem, ref + 568))
  local h7 = bxor(ph, readu32(mem, ref + 572))
  R[143] = l7; R[144] = h7
  T[143] = l7; T[144] = h7
  local pl = readu32(mem, prv + 576)
  local ph = readu32(mem, prv + 580)
  local l8 = bxor(pl, readu32(mem, ref + 576))
  local h8 = bxor(ph, readu32(mem, ref + 580))
  R[145] = l8; R[146] = h8
  T[145] = l8; T[146] = h8
  local pl = readu32(mem, prv + 584)
  local ph = readu32(mem, prv + 588)
  local l9 = bxor(pl, readu32(mem, ref + 584))
  local h9 = bxor(ph, readu32(mem, ref + 588))
  R[147] = l9; R[148] = h9
  T[147] = l9; T[148] = h9
  local pl = readu32(mem, prv + 592)
  local ph = readu32(mem, prv + 596)
  local l10 = bxor(pl, readu32(mem, ref + 592))
  local h10 = bxor(ph, readu32(mem, ref + 596))
  R[149] = l10; R[150] = h10
  T[149] = l10; T[150] = h10
  local pl = readu32(mem, prv + 600)
  local ph = readu32(mem, prv + 604)
  local l11 = bxor(pl, readu32(mem, ref + 600))
  local h11 = bxor(ph, readu32(mem, ref + 604))
  R[151] = l11; R[152] = h11
  T[151] = l11; T[152] = h11
  local pl = readu32(mem, prv + 608)
  local ph = readu32(mem, prv + 612)
  local l12 = bxor(pl, readu32(mem, ref + 608))
  local h12 = bxor(ph, readu32(mem, ref + 612))
  R[153] = l12; R[154] = h12
  T[153] = l12; T[154] = h12
  local pl = readu32(mem, prv + 616)
  local ph = readu32(mem, prv + 620)
  local l13 = bxor(pl, readu32(mem, ref + 616))
  local h13 = bxor(ph, readu32(mem, ref + 620))
  R[155] = l13; R[156] = h13
  T[155] = l13; T[156] = h13
  local pl = readu32(mem, prv + 624)
  local ph = readu32(mem, prv + 628)
  local l14 = bxor(pl, readu32(mem, ref + 624))
  local h14 = bxor(ph, readu32(mem, ref + 628))
  R[157] = l14; R[158] = h14
  T[157] = l14; T[158] = h14
  local pl = readu32(mem, prv + 632)
  local ph = readu32(mem, prv + 636)
  local l15 = bxor(pl, readu32(mem, ref + 632))
  local h15 = bxor(ph, readu32(mem, ref + 636))
  R[159] = l15; R[160] = h15
  T[159] = l15; T[160] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[129] = l0; R[130] = h0
  R[131] = l1; R[132] = h1
  R[133] = l2; R[134] = h2
  R[135] = l3; R[136] = h3
  R[137] = l4; R[138] = h4
  R[139] = l5; R[140] = h5
  R[141] = l6; R[142] = h6
  R[143] = l7; R[144] = h7
  R[145] = l8; R[146] = h8
  R[147] = l9; R[148] = h9
  R[149] = l10; R[150] = h10
  R[151] = l11; R[152] = h11
  R[153] = l12; R[154] = h12
  R[155] = l13; R[156] = h13
  R[157] = l14; R[158] = h14
  R[159] = l15; R[160] = h15
end
do
  local pl = readu32(mem, prv + 640)
  local ph = readu32(mem, prv + 644)
  local l0 = bxor(pl, readu32(mem, ref + 640))
  local h0 = bxor(ph, readu32(mem, ref + 644))
  R[161] = l0; R[162] = h0
  T[161] = l0; T[162] = h0
  local pl = readu32(mem, prv + 648)
  local ph = readu32(mem, prv + 652)
  local l1 = bxor(pl, readu32(mem, ref + 648))
  local h1 = bxor(ph, readu32(mem, ref + 652))
  R[163] = l1; R[164] = h1
  T[163] = l1; T[164] = h1
  local pl = readu32(mem, prv + 656)
  local ph = readu32(mem, prv + 660)
  local l2 = bxor(pl, readu32(mem, ref + 656))
  local h2 = bxor(ph, readu32(mem, ref + 660))
  R[165] = l2; R[166] = h2
  T[165] = l2; T[166] = h2
  local pl = readu32(mem, prv + 664)
  local ph = readu32(mem, prv + 668)
  local l3 = bxor(pl, readu32(mem, ref + 664))
  local h3 = bxor(ph, readu32(mem, ref + 668))
  R[167] = l3; R[168] = h3
  T[167] = l3; T[168] = h3
  local pl = readu32(mem, prv + 672)
  local ph = readu32(mem, prv + 676)
  local l4 = bxor(pl, readu32(mem, ref + 672))
  local h4 = bxor(ph, readu32(mem, ref + 676))
  R[169] = l4; R[170] = h4
  T[169] = l4; T[170] = h4
  local pl = readu32(mem, prv + 680)
  local ph = readu32(mem, prv + 684)
  local l5 = bxor(pl, readu32(mem, ref + 680))
  local h5 = bxor(ph, readu32(mem, ref + 684))
  R[171] = l5; R[172] = h5
  T[171] = l5; T[172] = h5
  local pl = readu32(mem, prv + 688)
  local ph = readu32(mem, prv + 692)
  local l6 = bxor(pl, readu32(mem, ref + 688))
  local h6 = bxor(ph, readu32(mem, ref + 692))
  R[173] = l6; R[174] = h6
  T[173] = l6; T[174] = h6
  local pl = readu32(mem, prv + 696)
  local ph = readu32(mem, prv + 700)
  local l7 = bxor(pl, readu32(mem, ref + 696))
  local h7 = bxor(ph, readu32(mem, ref + 700))
  R[175] = l7; R[176] = h7
  T[175] = l7; T[176] = h7
  local pl = readu32(mem, prv + 704)
  local ph = readu32(mem, prv + 708)
  local l8 = bxor(pl, readu32(mem, ref + 704))
  local h8 = bxor(ph, readu32(mem, ref + 708))
  R[177] = l8; R[178] = h8
  T[177] = l8; T[178] = h8
  local pl = readu32(mem, prv + 712)
  local ph = readu32(mem, prv + 716)
  local l9 = bxor(pl, readu32(mem, ref + 712))
  local h9 = bxor(ph, readu32(mem, ref + 716))
  R[179] = l9; R[180] = h9
  T[179] = l9; T[180] = h9
  local pl = readu32(mem, prv + 720)
  local ph = readu32(mem, prv + 724)
  local l10 = bxor(pl, readu32(mem, ref + 720))
  local h10 = bxor(ph, readu32(mem, ref + 724))
  R[181] = l10; R[182] = h10
  T[181] = l10; T[182] = h10
  local pl = readu32(mem, prv + 728)
  local ph = readu32(mem, prv + 732)
  local l11 = bxor(pl, readu32(mem, ref + 728))
  local h11 = bxor(ph, readu32(mem, ref + 732))
  R[183] = l11; R[184] = h11
  T[183] = l11; T[184] = h11
  local pl = readu32(mem, prv + 736)
  local ph = readu32(mem, prv + 740)
  local l12 = bxor(pl, readu32(mem, ref + 736))
  local h12 = bxor(ph, readu32(mem, ref + 740))
  R[185] = l12; R[186] = h12
  T[185] = l12; T[186] = h12
  local pl = readu32(mem, prv + 744)
  local ph = readu32(mem, prv + 748)
  local l13 = bxor(pl, readu32(mem, ref + 744))
  local h13 = bxor(ph, readu32(mem, ref + 748))
  R[187] = l13; R[188] = h13
  T[187] = l13; T[188] = h13
  local pl = readu32(mem, prv + 752)
  local ph = readu32(mem, prv + 756)
  local l14 = bxor(pl, readu32(mem, ref + 752))
  local h14 = bxor(ph, readu32(mem, ref + 756))
  R[189] = l14; R[190] = h14
  T[189] = l14; T[190] = h14
  local pl = readu32(mem, prv + 760)
  local ph = readu32(mem, prv + 764)
  local l15 = bxor(pl, readu32(mem, ref + 760))
  local h15 = bxor(ph, readu32(mem, ref + 764))
  R[191] = l15; R[192] = h15
  T[191] = l15; T[192] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[161] = l0; R[162] = h0
  R[163] = l1; R[164] = h1
  R[165] = l2; R[166] = h2
  R[167] = l3; R[168] = h3
  R[169] = l4; R[170] = h4
  R[171] = l5; R[172] = h5
  R[173] = l6; R[174] = h6
  R[175] = l7; R[176] = h7
  R[177] = l8; R[178] = h8
  R[179] = l9; R[180] = h9
  R[181] = l10; R[182] = h10
  R[183] = l11; R[184] = h11
  R[185] = l12; R[186] = h12
  R[187] = l13; R[188] = h13
  R[189] = l14; R[190] = h14
  R[191] = l15; R[192] = h15
end
do
  local pl = readu32(mem, prv + 768)
  local ph = readu32(mem, prv + 772)
  local l0 = bxor(pl, readu32(mem, ref + 768))
  local h0 = bxor(ph, readu32(mem, ref + 772))
  R[193] = l0; R[194] = h0
  T[193] = l0; T[194] = h0
  local pl = readu32(mem, prv + 776)
  local ph = readu32(mem, prv + 780)
  local l1 = bxor(pl, readu32(mem, ref + 776))
  local h1 = bxor(ph, readu32(mem, ref + 780))
  R[195] = l1; R[196] = h1
  T[195] = l1; T[196] = h1
  local pl = readu32(mem, prv + 784)
  local ph = readu32(mem, prv + 788)
  local l2 = bxor(pl, readu32(mem, ref + 784))
  local h2 = bxor(ph, readu32(mem, ref + 788))
  R[197] = l2; R[198] = h2
  T[197] = l2; T[198] = h2
  local pl = readu32(mem, prv + 792)
  local ph = readu32(mem, prv + 796)
  local l3 = bxor(pl, readu32(mem, ref + 792))
  local h3 = bxor(ph, readu32(mem, ref + 796))
  R[199] = l3; R[200] = h3
  T[199] = l3; T[200] = h3
  local pl = readu32(mem, prv + 800)
  local ph = readu32(mem, prv + 804)
  local l4 = bxor(pl, readu32(mem, ref + 800))
  local h4 = bxor(ph, readu32(mem, ref + 804))
  R[201] = l4; R[202] = h4
  T[201] = l4; T[202] = h4
  local pl = readu32(mem, prv + 808)
  local ph = readu32(mem, prv + 812)
  local l5 = bxor(pl, readu32(mem, ref + 808))
  local h5 = bxor(ph, readu32(mem, ref + 812))
  R[203] = l5; R[204] = h5
  T[203] = l5; T[204] = h5
  local pl = readu32(mem, prv + 816)
  local ph = readu32(mem, prv + 820)
  local l6 = bxor(pl, readu32(mem, ref + 816))
  local h6 = bxor(ph, readu32(mem, ref + 820))
  R[205] = l6; R[206] = h6
  T[205] = l6; T[206] = h6
  local pl = readu32(mem, prv + 824)
  local ph = readu32(mem, prv + 828)
  local l7 = bxor(pl, readu32(mem, ref + 824))
  local h7 = bxor(ph, readu32(mem, ref + 828))
  R[207] = l7; R[208] = h7
  T[207] = l7; T[208] = h7
  local pl = readu32(mem, prv + 832)
  local ph = readu32(mem, prv + 836)
  local l8 = bxor(pl, readu32(mem, ref + 832))
  local h8 = bxor(ph, readu32(mem, ref + 836))
  R[209] = l8; R[210] = h8
  T[209] = l8; T[210] = h8
  local pl = readu32(mem, prv + 840)
  local ph = readu32(mem, prv + 844)
  local l9 = bxor(pl, readu32(mem, ref + 840))
  local h9 = bxor(ph, readu32(mem, ref + 844))
  R[211] = l9; R[212] = h9
  T[211] = l9; T[212] = h9
  local pl = readu32(mem, prv + 848)
  local ph = readu32(mem, prv + 852)
  local l10 = bxor(pl, readu32(mem, ref + 848))
  local h10 = bxor(ph, readu32(mem, ref + 852))
  R[213] = l10; R[214] = h10
  T[213] = l10; T[214] = h10
  local pl = readu32(mem, prv + 856)
  local ph = readu32(mem, prv + 860)
  local l11 = bxor(pl, readu32(mem, ref + 856))
  local h11 = bxor(ph, readu32(mem, ref + 860))
  R[215] = l11; R[216] = h11
  T[215] = l11; T[216] = h11
  local pl = readu32(mem, prv + 864)
  local ph = readu32(mem, prv + 868)
  local l12 = bxor(pl, readu32(mem, ref + 864))
  local h12 = bxor(ph, readu32(mem, ref + 868))
  R[217] = l12; R[218] = h12
  T[217] = l12; T[218] = h12
  local pl = readu32(mem, prv + 872)
  local ph = readu32(mem, prv + 876)
  local l13 = bxor(pl, readu32(mem, ref + 872))
  local h13 = bxor(ph, readu32(mem, ref + 876))
  R[219] = l13; R[220] = h13
  T[219] = l13; T[220] = h13
  local pl = readu32(mem, prv + 880)
  local ph = readu32(mem, prv + 884)
  local l14 = bxor(pl, readu32(mem, ref + 880))
  local h14 = bxor(ph, readu32(mem, ref + 884))
  R[221] = l14; R[222] = h14
  T[221] = l14; T[222] = h14
  local pl = readu32(mem, prv + 888)
  local ph = readu32(mem, prv + 892)
  local l15 = bxor(pl, readu32(mem, ref + 888))
  local h15 = bxor(ph, readu32(mem, ref + 892))
  R[223] = l15; R[224] = h15
  T[223] = l15; T[224] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[193] = l0; R[194] = h0
  R[195] = l1; R[196] = h1
  R[197] = l2; R[198] = h2
  R[199] = l3; R[200] = h3
  R[201] = l4; R[202] = h4
  R[203] = l5; R[204] = h5
  R[205] = l6; R[206] = h6
  R[207] = l7; R[208] = h7
  R[209] = l8; R[210] = h8
  R[211] = l9; R[212] = h9
  R[213] = l10; R[214] = h10
  R[215] = l11; R[216] = h11
  R[217] = l12; R[218] = h12
  R[219] = l13; R[220] = h13
  R[221] = l14; R[222] = h14
  R[223] = l15; R[224] = h15
end
do
  local pl = readu32(mem, prv + 896)
  local ph = readu32(mem, prv + 900)
  local l0 = bxor(pl, readu32(mem, ref + 896))
  local h0 = bxor(ph, readu32(mem, ref + 900))
  R[225] = l0; R[226] = h0
  T[225] = l0; T[226] = h0
  local pl = readu32(mem, prv + 904)
  local ph = readu32(mem, prv + 908)
  local l1 = bxor(pl, readu32(mem, ref + 904))
  local h1 = bxor(ph, readu32(mem, ref + 908))
  R[227] = l1; R[228] = h1
  T[227] = l1; T[228] = h1
  local pl = readu32(mem, prv + 912)
  local ph = readu32(mem, prv + 916)
  local l2 = bxor(pl, readu32(mem, ref + 912))
  local h2 = bxor(ph, readu32(mem, ref + 916))
  R[229] = l2; R[230] = h2
  T[229] = l2; T[230] = h2
  local pl = readu32(mem, prv + 920)
  local ph = readu32(mem, prv + 924)
  local l3 = bxor(pl, readu32(mem, ref + 920))
  local h3 = bxor(ph, readu32(mem, ref + 924))
  R[231] = l3; R[232] = h3
  T[231] = l3; T[232] = h3
  local pl = readu32(mem, prv + 928)
  local ph = readu32(mem, prv + 932)
  local l4 = bxor(pl, readu32(mem, ref + 928))
  local h4 = bxor(ph, readu32(mem, ref + 932))
  R[233] = l4; R[234] = h4
  T[233] = l4; T[234] = h4
  local pl = readu32(mem, prv + 936)
  local ph = readu32(mem, prv + 940)
  local l5 = bxor(pl, readu32(mem, ref + 936))
  local h5 = bxor(ph, readu32(mem, ref + 940))
  R[235] = l5; R[236] = h5
  T[235] = l5; T[236] = h5
  local pl = readu32(mem, prv + 944)
  local ph = readu32(mem, prv + 948)
  local l6 = bxor(pl, readu32(mem, ref + 944))
  local h6 = bxor(ph, readu32(mem, ref + 948))
  R[237] = l6; R[238] = h6
  T[237] = l6; T[238] = h6
  local pl = readu32(mem, prv + 952)
  local ph = readu32(mem, prv + 956)
  local l7 = bxor(pl, readu32(mem, ref + 952))
  local h7 = bxor(ph, readu32(mem, ref + 956))
  R[239] = l7; R[240] = h7
  T[239] = l7; T[240] = h7
  local pl = readu32(mem, prv + 960)
  local ph = readu32(mem, prv + 964)
  local l8 = bxor(pl, readu32(mem, ref + 960))
  local h8 = bxor(ph, readu32(mem, ref + 964))
  R[241] = l8; R[242] = h8
  T[241] = l8; T[242] = h8
  local pl = readu32(mem, prv + 968)
  local ph = readu32(mem, prv + 972)
  local l9 = bxor(pl, readu32(mem, ref + 968))
  local h9 = bxor(ph, readu32(mem, ref + 972))
  R[243] = l9; R[244] = h9
  T[243] = l9; T[244] = h9
  local pl = readu32(mem, prv + 976)
  local ph = readu32(mem, prv + 980)
  local l10 = bxor(pl, readu32(mem, ref + 976))
  local h10 = bxor(ph, readu32(mem, ref + 980))
  R[245] = l10; R[246] = h10
  T[245] = l10; T[246] = h10
  local pl = readu32(mem, prv + 984)
  local ph = readu32(mem, prv + 988)
  local l11 = bxor(pl, readu32(mem, ref + 984))
  local h11 = bxor(ph, readu32(mem, ref + 988))
  R[247] = l11; R[248] = h11
  T[247] = l11; T[248] = h11
  local pl = readu32(mem, prv + 992)
  local ph = readu32(mem, prv + 996)
  local l12 = bxor(pl, readu32(mem, ref + 992))
  local h12 = bxor(ph, readu32(mem, ref + 996))
  R[249] = l12; R[250] = h12
  T[249] = l12; T[250] = h12
  local pl = readu32(mem, prv + 1000)
  local ph = readu32(mem, prv + 1004)
  local l13 = bxor(pl, readu32(mem, ref + 1000))
  local h13 = bxor(ph, readu32(mem, ref + 1004))
  R[251] = l13; R[252] = h13
  T[251] = l13; T[252] = h13
  local pl = readu32(mem, prv + 1008)
  local ph = readu32(mem, prv + 1012)
  local l14 = bxor(pl, readu32(mem, ref + 1008))
  local h14 = bxor(ph, readu32(mem, ref + 1012))
  R[253] = l14; R[254] = h14
  T[253] = l14; T[254] = h14
  local pl = readu32(mem, prv + 1016)
  local ph = readu32(mem, prv + 1020)
  local l15 = bxor(pl, readu32(mem, ref + 1016))
  local h15 = bxor(ph, readu32(mem, ref + 1020))
  R[255] = l15; R[256] = h15
  T[255] = l15; T[256] = h15
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[225] = l0; R[226] = h0
  R[227] = l1; R[228] = h1
  R[229] = l2; R[230] = h2
  R[231] = l3; R[232] = h3
  R[233] = l4; R[234] = h4
  R[235] = l5; R[236] = h5
  R[237] = l6; R[238] = h6
  R[239] = l7; R[240] = h7
  R[241] = l8; R[242] = h8
  R[243] = l9; R[244] = h9
  R[245] = l10; R[246] = h10
  R[247] = l11; R[248] = h11
  R[249] = l12; R[250] = h12
  R[251] = l13; R[252] = h13
  R[253] = l14; R[254] = h14
  R[255] = l15; R[256] = h15
end
do
  local l0, h0 = R[1], R[2]
  local l1, h1 = R[3], R[4]
  local l2, h2 = R[33], R[34]
  local l3, h3 = R[35], R[36]
  local l4, h4 = R[65], R[66]
  local l5, h5 = R[67], R[68]
  local l6, h6 = R[97], R[98]
  local l7, h7 = R[99], R[100]
  local l8, h8 = R[129], R[130]
  local l9, h9 = R[131], R[132]
  local l10, h10 = R[161], R[162]
  local l11, h11 = R[163], R[164]
  local l12, h12 = R[193], R[194]
  local l13, h13 = R[195], R[196]
  local l14, h14 = R[225], R[226]
  local l15, h15 = R[227], R[228]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 0, bxor(T[1], l0))
  writeu32(mem, cur + 4, bxor(T[2], h0))
  writeu32(mem, cur + 8, bxor(T[3], l1))
  writeu32(mem, cur + 12, bxor(T[4], h1))
  writeu32(mem, cur + 128, bxor(T[33], l2))
  writeu32(mem, cur + 132, bxor(T[34], h2))
  writeu32(mem, cur + 136, bxor(T[35], l3))
  writeu32(mem, cur + 140, bxor(T[36], h3))
  writeu32(mem, cur + 256, bxor(T[65], l4))
  writeu32(mem, cur + 260, bxor(T[66], h4))
  writeu32(mem, cur + 264, bxor(T[67], l5))
  writeu32(mem, cur + 268, bxor(T[68], h5))
  writeu32(mem, cur + 384, bxor(T[97], l6))
  writeu32(mem, cur + 388, bxor(T[98], h6))
  writeu32(mem, cur + 392, bxor(T[99], l7))
  writeu32(mem, cur + 396, bxor(T[100], h7))
  writeu32(mem, cur + 512, bxor(T[129], l8))
  writeu32(mem, cur + 516, bxor(T[130], h8))
  writeu32(mem, cur + 520, bxor(T[131], l9))
  writeu32(mem, cur + 524, bxor(T[132], h9))
  writeu32(mem, cur + 640, bxor(T[161], l10))
  writeu32(mem, cur + 644, bxor(T[162], h10))
  writeu32(mem, cur + 648, bxor(T[163], l11))
  writeu32(mem, cur + 652, bxor(T[164], h11))
  writeu32(mem, cur + 768, bxor(T[193], l12))
  writeu32(mem, cur + 772, bxor(T[194], h12))
  writeu32(mem, cur + 776, bxor(T[195], l13))
  writeu32(mem, cur + 780, bxor(T[196], h13))
  writeu32(mem, cur + 896, bxor(T[225], l14))
  writeu32(mem, cur + 900, bxor(T[226], h14))
  writeu32(mem, cur + 904, bxor(T[227], l15))
  writeu32(mem, cur + 908, bxor(T[228], h15))
end
do
  local l0, h0 = R[5], R[6]
  local l1, h1 = R[7], R[8]
  local l2, h2 = R[37], R[38]
  local l3, h3 = R[39], R[40]
  local l4, h4 = R[69], R[70]
  local l5, h5 = R[71], R[72]
  local l6, h6 = R[101], R[102]
  local l7, h7 = R[103], R[104]
  local l8, h8 = R[133], R[134]
  local l9, h9 = R[135], R[136]
  local l10, h10 = R[165], R[166]
  local l11, h11 = R[167], R[168]
  local l12, h12 = R[197], R[198]
  local l13, h13 = R[199], R[200]
  local l14, h14 = R[229], R[230]
  local l15, h15 = R[231], R[232]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 16, bxor(T[5], l0))
  writeu32(mem, cur + 20, bxor(T[6], h0))
  writeu32(mem, cur + 24, bxor(T[7], l1))
  writeu32(mem, cur + 28, bxor(T[8], h1))
  writeu32(mem, cur + 144, bxor(T[37], l2))
  writeu32(mem, cur + 148, bxor(T[38], h2))
  writeu32(mem, cur + 152, bxor(T[39], l3))
  writeu32(mem, cur + 156, bxor(T[40], h3))
  writeu32(mem, cur + 272, bxor(T[69], l4))
  writeu32(mem, cur + 276, bxor(T[70], h4))
  writeu32(mem, cur + 280, bxor(T[71], l5))
  writeu32(mem, cur + 284, bxor(T[72], h5))
  writeu32(mem, cur + 400, bxor(T[101], l6))
  writeu32(mem, cur + 404, bxor(T[102], h6))
  writeu32(mem, cur + 408, bxor(T[103], l7))
  writeu32(mem, cur + 412, bxor(T[104], h7))
  writeu32(mem, cur + 528, bxor(T[133], l8))
  writeu32(mem, cur + 532, bxor(T[134], h8))
  writeu32(mem, cur + 536, bxor(T[135], l9))
  writeu32(mem, cur + 540, bxor(T[136], h9))
  writeu32(mem, cur + 656, bxor(T[165], l10))
  writeu32(mem, cur + 660, bxor(T[166], h10))
  writeu32(mem, cur + 664, bxor(T[167], l11))
  writeu32(mem, cur + 668, bxor(T[168], h11))
  writeu32(mem, cur + 784, bxor(T[197], l12))
  writeu32(mem, cur + 788, bxor(T[198], h12))
  writeu32(mem, cur + 792, bxor(T[199], l13))
  writeu32(mem, cur + 796, bxor(T[200], h13))
  writeu32(mem, cur + 912, bxor(T[229], l14))
  writeu32(mem, cur + 916, bxor(T[230], h14))
  writeu32(mem, cur + 920, bxor(T[231], l15))
  writeu32(mem, cur + 924, bxor(T[232], h15))
end
do
  local l0, h0 = R[9], R[10]
  local l1, h1 = R[11], R[12]
  local l2, h2 = R[41], R[42]
  local l3, h3 = R[43], R[44]
  local l4, h4 = R[73], R[74]
  local l5, h5 = R[75], R[76]
  local l6, h6 = R[105], R[106]
  local l7, h7 = R[107], R[108]
  local l8, h8 = R[137], R[138]
  local l9, h9 = R[139], R[140]
  local l10, h10 = R[169], R[170]
  local l11, h11 = R[171], R[172]
  local l12, h12 = R[201], R[202]
  local l13, h13 = R[203], R[204]
  local l14, h14 = R[233], R[234]
  local l15, h15 = R[235], R[236]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 32, bxor(T[9], l0))
  writeu32(mem, cur + 36, bxor(T[10], h0))
  writeu32(mem, cur + 40, bxor(T[11], l1))
  writeu32(mem, cur + 44, bxor(T[12], h1))
  writeu32(mem, cur + 160, bxor(T[41], l2))
  writeu32(mem, cur + 164, bxor(T[42], h2))
  writeu32(mem, cur + 168, bxor(T[43], l3))
  writeu32(mem, cur + 172, bxor(T[44], h3))
  writeu32(mem, cur + 288, bxor(T[73], l4))
  writeu32(mem, cur + 292, bxor(T[74], h4))
  writeu32(mem, cur + 296, bxor(T[75], l5))
  writeu32(mem, cur + 300, bxor(T[76], h5))
  writeu32(mem, cur + 416, bxor(T[105], l6))
  writeu32(mem, cur + 420, bxor(T[106], h6))
  writeu32(mem, cur + 424, bxor(T[107], l7))
  writeu32(mem, cur + 428, bxor(T[108], h7))
  writeu32(mem, cur + 544, bxor(T[137], l8))
  writeu32(mem, cur + 548, bxor(T[138], h8))
  writeu32(mem, cur + 552, bxor(T[139], l9))
  writeu32(mem, cur + 556, bxor(T[140], h9))
  writeu32(mem, cur + 672, bxor(T[169], l10))
  writeu32(mem, cur + 676, bxor(T[170], h10))
  writeu32(mem, cur + 680, bxor(T[171], l11))
  writeu32(mem, cur + 684, bxor(T[172], h11))
  writeu32(mem, cur + 800, bxor(T[201], l12))
  writeu32(mem, cur + 804, bxor(T[202], h12))
  writeu32(mem, cur + 808, bxor(T[203], l13))
  writeu32(mem, cur + 812, bxor(T[204], h13))
  writeu32(mem, cur + 928, bxor(T[233], l14))
  writeu32(mem, cur + 932, bxor(T[234], h14))
  writeu32(mem, cur + 936, bxor(T[235], l15))
  writeu32(mem, cur + 940, bxor(T[236], h15))
end
do
  local l0, h0 = R[13], R[14]
  local l1, h1 = R[15], R[16]
  local l2, h2 = R[45], R[46]
  local l3, h3 = R[47], R[48]
  local l4, h4 = R[77], R[78]
  local l5, h5 = R[79], R[80]
  local l6, h6 = R[109], R[110]
  local l7, h7 = R[111], R[112]
  local l8, h8 = R[141], R[142]
  local l9, h9 = R[143], R[144]
  local l10, h10 = R[173], R[174]
  local l11, h11 = R[175], R[176]
  local l12, h12 = R[205], R[206]
  local l13, h13 = R[207], R[208]
  local l14, h14 = R[237], R[238]
  local l15, h15 = R[239], R[240]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 48, bxor(T[13], l0))
  writeu32(mem, cur + 52, bxor(T[14], h0))
  writeu32(mem, cur + 56, bxor(T[15], l1))
  writeu32(mem, cur + 60, bxor(T[16], h1))
  writeu32(mem, cur + 176, bxor(T[45], l2))
  writeu32(mem, cur + 180, bxor(T[46], h2))
  writeu32(mem, cur + 184, bxor(T[47], l3))
  writeu32(mem, cur + 188, bxor(T[48], h3))
  writeu32(mem, cur + 304, bxor(T[77], l4))
  writeu32(mem, cur + 308, bxor(T[78], h4))
  writeu32(mem, cur + 312, bxor(T[79], l5))
  writeu32(mem, cur + 316, bxor(T[80], h5))
  writeu32(mem, cur + 432, bxor(T[109], l6))
  writeu32(mem, cur + 436, bxor(T[110], h6))
  writeu32(mem, cur + 440, bxor(T[111], l7))
  writeu32(mem, cur + 444, bxor(T[112], h7))
  writeu32(mem, cur + 560, bxor(T[141], l8))
  writeu32(mem, cur + 564, bxor(T[142], h8))
  writeu32(mem, cur + 568, bxor(T[143], l9))
  writeu32(mem, cur + 572, bxor(T[144], h9))
  writeu32(mem, cur + 688, bxor(T[173], l10))
  writeu32(mem, cur + 692, bxor(T[174], h10))
  writeu32(mem, cur + 696, bxor(T[175], l11))
  writeu32(mem, cur + 700, bxor(T[176], h11))
  writeu32(mem, cur + 816, bxor(T[205], l12))
  writeu32(mem, cur + 820, bxor(T[206], h12))
  writeu32(mem, cur + 824, bxor(T[207], l13))
  writeu32(mem, cur + 828, bxor(T[208], h13))
  writeu32(mem, cur + 944, bxor(T[237], l14))
  writeu32(mem, cur + 948, bxor(T[238], h14))
  writeu32(mem, cur + 952, bxor(T[239], l15))
  writeu32(mem, cur + 956, bxor(T[240], h15))
end
do
  local l0, h0 = R[17], R[18]
  local l1, h1 = R[19], R[20]
  local l2, h2 = R[49], R[50]
  local l3, h3 = R[51], R[52]
  local l4, h4 = R[81], R[82]
  local l5, h5 = R[83], R[84]
  local l6, h6 = R[113], R[114]
  local l7, h7 = R[115], R[116]
  local l8, h8 = R[145], R[146]
  local l9, h9 = R[147], R[148]
  local l10, h10 = R[177], R[178]
  local l11, h11 = R[179], R[180]
  local l12, h12 = R[209], R[210]
  local l13, h13 = R[211], R[212]
  local l14, h14 = R[241], R[242]
  local l15, h15 = R[243], R[244]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 64, bxor(T[17], l0))
  writeu32(mem, cur + 68, bxor(T[18], h0))
  writeu32(mem, cur + 72, bxor(T[19], l1))
  writeu32(mem, cur + 76, bxor(T[20], h1))
  writeu32(mem, cur + 192, bxor(T[49], l2))
  writeu32(mem, cur + 196, bxor(T[50], h2))
  writeu32(mem, cur + 200, bxor(T[51], l3))
  writeu32(mem, cur + 204, bxor(T[52], h3))
  writeu32(mem, cur + 320, bxor(T[81], l4))
  writeu32(mem, cur + 324, bxor(T[82], h4))
  writeu32(mem, cur + 328, bxor(T[83], l5))
  writeu32(mem, cur + 332, bxor(T[84], h5))
  writeu32(mem, cur + 448, bxor(T[113], l6))
  writeu32(mem, cur + 452, bxor(T[114], h6))
  writeu32(mem, cur + 456, bxor(T[115], l7))
  writeu32(mem, cur + 460, bxor(T[116], h7))
  writeu32(mem, cur + 576, bxor(T[145], l8))
  writeu32(mem, cur + 580, bxor(T[146], h8))
  writeu32(mem, cur + 584, bxor(T[147], l9))
  writeu32(mem, cur + 588, bxor(T[148], h9))
  writeu32(mem, cur + 704, bxor(T[177], l10))
  writeu32(mem, cur + 708, bxor(T[178], h10))
  writeu32(mem, cur + 712, bxor(T[179], l11))
  writeu32(mem, cur + 716, bxor(T[180], h11))
  writeu32(mem, cur + 832, bxor(T[209], l12))
  writeu32(mem, cur + 836, bxor(T[210], h12))
  writeu32(mem, cur + 840, bxor(T[211], l13))
  writeu32(mem, cur + 844, bxor(T[212], h13))
  writeu32(mem, cur + 960, bxor(T[241], l14))
  writeu32(mem, cur + 964, bxor(T[242], h14))
  writeu32(mem, cur + 968, bxor(T[243], l15))
  writeu32(mem, cur + 972, bxor(T[244], h15))
end
do
  local l0, h0 = R[21], R[22]
  local l1, h1 = R[23], R[24]
  local l2, h2 = R[53], R[54]
  local l3, h3 = R[55], R[56]
  local l4, h4 = R[85], R[86]
  local l5, h5 = R[87], R[88]
  local l6, h6 = R[117], R[118]
  local l7, h7 = R[119], R[120]
  local l8, h8 = R[149], R[150]
  local l9, h9 = R[151], R[152]
  local l10, h10 = R[181], R[182]
  local l11, h11 = R[183], R[184]
  local l12, h12 = R[213], R[214]
  local l13, h13 = R[215], R[216]
  local l14, h14 = R[245], R[246]
  local l15, h15 = R[247], R[248]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 80, bxor(T[21], l0))
  writeu32(mem, cur + 84, bxor(T[22], h0))
  writeu32(mem, cur + 88, bxor(T[23], l1))
  writeu32(mem, cur + 92, bxor(T[24], h1))
  writeu32(mem, cur + 208, bxor(T[53], l2))
  writeu32(mem, cur + 212, bxor(T[54], h2))
  writeu32(mem, cur + 216, bxor(T[55], l3))
  writeu32(mem, cur + 220, bxor(T[56], h3))
  writeu32(mem, cur + 336, bxor(T[85], l4))
  writeu32(mem, cur + 340, bxor(T[86], h4))
  writeu32(mem, cur + 344, bxor(T[87], l5))
  writeu32(mem, cur + 348, bxor(T[88], h5))
  writeu32(mem, cur + 464, bxor(T[117], l6))
  writeu32(mem, cur + 468, bxor(T[118], h6))
  writeu32(mem, cur + 472, bxor(T[119], l7))
  writeu32(mem, cur + 476, bxor(T[120], h7))
  writeu32(mem, cur + 592, bxor(T[149], l8))
  writeu32(mem, cur + 596, bxor(T[150], h8))
  writeu32(mem, cur + 600, bxor(T[151], l9))
  writeu32(mem, cur + 604, bxor(T[152], h9))
  writeu32(mem, cur + 720, bxor(T[181], l10))
  writeu32(mem, cur + 724, bxor(T[182], h10))
  writeu32(mem, cur + 728, bxor(T[183], l11))
  writeu32(mem, cur + 732, bxor(T[184], h11))
  writeu32(mem, cur + 848, bxor(T[213], l12))
  writeu32(mem, cur + 852, bxor(T[214], h12))
  writeu32(mem, cur + 856, bxor(T[215], l13))
  writeu32(mem, cur + 860, bxor(T[216], h13))
  writeu32(mem, cur + 976, bxor(T[245], l14))
  writeu32(mem, cur + 980, bxor(T[246], h14))
  writeu32(mem, cur + 984, bxor(T[247], l15))
  writeu32(mem, cur + 988, bxor(T[248], h15))
end
do
  local l0, h0 = R[25], R[26]
  local l1, h1 = R[27], R[28]
  local l2, h2 = R[57], R[58]
  local l3, h3 = R[59], R[60]
  local l4, h4 = R[89], R[90]
  local l5, h5 = R[91], R[92]
  local l6, h6 = R[121], R[122]
  local l7, h7 = R[123], R[124]
  local l8, h8 = R[153], R[154]
  local l9, h9 = R[155], R[156]
  local l10, h10 = R[185], R[186]
  local l11, h11 = R[187], R[188]
  local l12, h12 = R[217], R[218]
  local l13, h13 = R[219], R[220]
  local l14, h14 = R[249], R[250]
  local l15, h15 = R[251], R[252]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 96, bxor(T[25], l0))
  writeu32(mem, cur + 100, bxor(T[26], h0))
  writeu32(mem, cur + 104, bxor(T[27], l1))
  writeu32(mem, cur + 108, bxor(T[28], h1))
  writeu32(mem, cur + 224, bxor(T[57], l2))
  writeu32(mem, cur + 228, bxor(T[58], h2))
  writeu32(mem, cur + 232, bxor(T[59], l3))
  writeu32(mem, cur + 236, bxor(T[60], h3))
  writeu32(mem, cur + 352, bxor(T[89], l4))
  writeu32(mem, cur + 356, bxor(T[90], h4))
  writeu32(mem, cur + 360, bxor(T[91], l5))
  writeu32(mem, cur + 364, bxor(T[92], h5))
  writeu32(mem, cur + 480, bxor(T[121], l6))
  writeu32(mem, cur + 484, bxor(T[122], h6))
  writeu32(mem, cur + 488, bxor(T[123], l7))
  writeu32(mem, cur + 492, bxor(T[124], h7))
  writeu32(mem, cur + 608, bxor(T[153], l8))
  writeu32(mem, cur + 612, bxor(T[154], h8))
  writeu32(mem, cur + 616, bxor(T[155], l9))
  writeu32(mem, cur + 620, bxor(T[156], h9))
  writeu32(mem, cur + 736, bxor(T[185], l10))
  writeu32(mem, cur + 740, bxor(T[186], h10))
  writeu32(mem, cur + 744, bxor(T[187], l11))
  writeu32(mem, cur + 748, bxor(T[188], h11))
  writeu32(mem, cur + 864, bxor(T[217], l12))
  writeu32(mem, cur + 868, bxor(T[218], h12))
  writeu32(mem, cur + 872, bxor(T[219], l13))
  writeu32(mem, cur + 876, bxor(T[220], h13))
  writeu32(mem, cur + 992, bxor(T[249], l14))
  writeu32(mem, cur + 996, bxor(T[250], h14))
  writeu32(mem, cur + 1000, bxor(T[251], l15))
  writeu32(mem, cur + 1004, bxor(T[252], h15))
end
do
  local l0, h0 = R[29], R[30]
  local l1, h1 = R[31], R[32]
  local l2, h2 = R[61], R[62]
  local l3, h3 = R[63], R[64]
  local l4, h4 = R[93], R[94]
  local l5, h5 = R[95], R[96]
  local l6, h6 = R[125], R[126]
  local l7, h7 = R[127], R[128]
  local l8, h8 = R[157], R[158]
  local l9, h9 = R[159], R[160]
  local l10, h10 = R[189], R[190]
  local l11, h11 = R[191], R[192]
  local l12, h12 = R[221], R[222]
  local l13, h13 = R[223], R[224]
  local l14, h14 = R[253], R[254]
  local l15, h15 = R[255], R[256]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 112, bxor(T[29], l0))
  writeu32(mem, cur + 116, bxor(T[30], h0))
  writeu32(mem, cur + 120, bxor(T[31], l1))
  writeu32(mem, cur + 124, bxor(T[32], h1))
  writeu32(mem, cur + 240, bxor(T[61], l2))
  writeu32(mem, cur + 244, bxor(T[62], h2))
  writeu32(mem, cur + 248, bxor(T[63], l3))
  writeu32(mem, cur + 252, bxor(T[64], h3))
  writeu32(mem, cur + 368, bxor(T[93], l4))
  writeu32(mem, cur + 372, bxor(T[94], h4))
  writeu32(mem, cur + 376, bxor(T[95], l5))
  writeu32(mem, cur + 380, bxor(T[96], h5))
  writeu32(mem, cur + 496, bxor(T[125], l6))
  writeu32(mem, cur + 500, bxor(T[126], h6))
  writeu32(mem, cur + 504, bxor(T[127], l7))
  writeu32(mem, cur + 508, bxor(T[128], h7))
  writeu32(mem, cur + 624, bxor(T[157], l8))
  writeu32(mem, cur + 628, bxor(T[158], h8))
  writeu32(mem, cur + 632, bxor(T[159], l9))
  writeu32(mem, cur + 636, bxor(T[160], h9))
  writeu32(mem, cur + 752, bxor(T[189], l10))
  writeu32(mem, cur + 756, bxor(T[190], h10))
  writeu32(mem, cur + 760, bxor(T[191], l11))
  writeu32(mem, cur + 764, bxor(T[192], h11))
  writeu32(mem, cur + 880, bxor(T[221], l12))
  writeu32(mem, cur + 884, bxor(T[222], h12))
  writeu32(mem, cur + 888, bxor(T[223], l13))
  writeu32(mem, cur + 892, bxor(T[224], h13))
  writeu32(mem, cur + 1008, bxor(T[253], l14))
  writeu32(mem, cur + 1012, bxor(T[254], h14))
  writeu32(mem, cur + 1016, bxor(T[255], l15))
  writeu32(mem, cur + 1020, bxor(T[256], h15))
end
end

local function fillBlockX(mem, prv, ref, cur)
do
  local pl = readu32(mem, prv + 0)
  local ph = readu32(mem, prv + 4)
  local l0 = bxor(pl, readu32(mem, ref + 0))
  local h0 = bxor(ph, readu32(mem, ref + 4))
  R[1] = l0; R[2] = h0
  T[1] = bxor(l0, readu32(mem, cur + 0))
  T[2] = bxor(h0, readu32(mem, cur + 4))
  local pl = readu32(mem, prv + 8)
  local ph = readu32(mem, prv + 12)
  local l1 = bxor(pl, readu32(mem, ref + 8))
  local h1 = bxor(ph, readu32(mem, ref + 12))
  R[3] = l1; R[4] = h1
  T[3] = bxor(l1, readu32(mem, cur + 8))
  T[4] = bxor(h1, readu32(mem, cur + 12))
  local pl = readu32(mem, prv + 16)
  local ph = readu32(mem, prv + 20)
  local l2 = bxor(pl, readu32(mem, ref + 16))
  local h2 = bxor(ph, readu32(mem, ref + 20))
  R[5] = l2; R[6] = h2
  T[5] = bxor(l2, readu32(mem, cur + 16))
  T[6] = bxor(h2, readu32(mem, cur + 20))
  local pl = readu32(mem, prv + 24)
  local ph = readu32(mem, prv + 28)
  local l3 = bxor(pl, readu32(mem, ref + 24))
  local h3 = bxor(ph, readu32(mem, ref + 28))
  R[7] = l3; R[8] = h3
  T[7] = bxor(l3, readu32(mem, cur + 24))
  T[8] = bxor(h3, readu32(mem, cur + 28))
  local pl = readu32(mem, prv + 32)
  local ph = readu32(mem, prv + 36)
  local l4 = bxor(pl, readu32(mem, ref + 32))
  local h4 = bxor(ph, readu32(mem, ref + 36))
  R[9] = l4; R[10] = h4
  T[9] = bxor(l4, readu32(mem, cur + 32))
  T[10] = bxor(h4, readu32(mem, cur + 36))
  local pl = readu32(mem, prv + 40)
  local ph = readu32(mem, prv + 44)
  local l5 = bxor(pl, readu32(mem, ref + 40))
  local h5 = bxor(ph, readu32(mem, ref + 44))
  R[11] = l5; R[12] = h5
  T[11] = bxor(l5, readu32(mem, cur + 40))
  T[12] = bxor(h5, readu32(mem, cur + 44))
  local pl = readu32(mem, prv + 48)
  local ph = readu32(mem, prv + 52)
  local l6 = bxor(pl, readu32(mem, ref + 48))
  local h6 = bxor(ph, readu32(mem, ref + 52))
  R[13] = l6; R[14] = h6
  T[13] = bxor(l6, readu32(mem, cur + 48))
  T[14] = bxor(h6, readu32(mem, cur + 52))
  local pl = readu32(mem, prv + 56)
  local ph = readu32(mem, prv + 60)
  local l7 = bxor(pl, readu32(mem, ref + 56))
  local h7 = bxor(ph, readu32(mem, ref + 60))
  R[15] = l7; R[16] = h7
  T[15] = bxor(l7, readu32(mem, cur + 56))
  T[16] = bxor(h7, readu32(mem, cur + 60))
  local pl = readu32(mem, prv + 64)
  local ph = readu32(mem, prv + 68)
  local l8 = bxor(pl, readu32(mem, ref + 64))
  local h8 = bxor(ph, readu32(mem, ref + 68))
  R[17] = l8; R[18] = h8
  T[17] = bxor(l8, readu32(mem, cur + 64))
  T[18] = bxor(h8, readu32(mem, cur + 68))
  local pl = readu32(mem, prv + 72)
  local ph = readu32(mem, prv + 76)
  local l9 = bxor(pl, readu32(mem, ref + 72))
  local h9 = bxor(ph, readu32(mem, ref + 76))
  R[19] = l9; R[20] = h9
  T[19] = bxor(l9, readu32(mem, cur + 72))
  T[20] = bxor(h9, readu32(mem, cur + 76))
  local pl = readu32(mem, prv + 80)
  local ph = readu32(mem, prv + 84)
  local l10 = bxor(pl, readu32(mem, ref + 80))
  local h10 = bxor(ph, readu32(mem, ref + 84))
  R[21] = l10; R[22] = h10
  T[21] = bxor(l10, readu32(mem, cur + 80))
  T[22] = bxor(h10, readu32(mem, cur + 84))
  local pl = readu32(mem, prv + 88)
  local ph = readu32(mem, prv + 92)
  local l11 = bxor(pl, readu32(mem, ref + 88))
  local h11 = bxor(ph, readu32(mem, ref + 92))
  R[23] = l11; R[24] = h11
  T[23] = bxor(l11, readu32(mem, cur + 88))
  T[24] = bxor(h11, readu32(mem, cur + 92))
  local pl = readu32(mem, prv + 96)
  local ph = readu32(mem, prv + 100)
  local l12 = bxor(pl, readu32(mem, ref + 96))
  local h12 = bxor(ph, readu32(mem, ref + 100))
  R[25] = l12; R[26] = h12
  T[25] = bxor(l12, readu32(mem, cur + 96))
  T[26] = bxor(h12, readu32(mem, cur + 100))
  local pl = readu32(mem, prv + 104)
  local ph = readu32(mem, prv + 108)
  local l13 = bxor(pl, readu32(mem, ref + 104))
  local h13 = bxor(ph, readu32(mem, ref + 108))
  R[27] = l13; R[28] = h13
  T[27] = bxor(l13, readu32(mem, cur + 104))
  T[28] = bxor(h13, readu32(mem, cur + 108))
  local pl = readu32(mem, prv + 112)
  local ph = readu32(mem, prv + 116)
  local l14 = bxor(pl, readu32(mem, ref + 112))
  local h14 = bxor(ph, readu32(mem, ref + 116))
  R[29] = l14; R[30] = h14
  T[29] = bxor(l14, readu32(mem, cur + 112))
  T[30] = bxor(h14, readu32(mem, cur + 116))
  local pl = readu32(mem, prv + 120)
  local ph = readu32(mem, prv + 124)
  local l15 = bxor(pl, readu32(mem, ref + 120))
  local h15 = bxor(ph, readu32(mem, ref + 124))
  R[31] = l15; R[32] = h15
  T[31] = bxor(l15, readu32(mem, cur + 120))
  T[32] = bxor(h15, readu32(mem, cur + 124))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[1] = l0; R[2] = h0
  R[3] = l1; R[4] = h1
  R[5] = l2; R[6] = h2
  R[7] = l3; R[8] = h3
  R[9] = l4; R[10] = h4
  R[11] = l5; R[12] = h5
  R[13] = l6; R[14] = h6
  R[15] = l7; R[16] = h7
  R[17] = l8; R[18] = h8
  R[19] = l9; R[20] = h9
  R[21] = l10; R[22] = h10
  R[23] = l11; R[24] = h11
  R[25] = l12; R[26] = h12
  R[27] = l13; R[28] = h13
  R[29] = l14; R[30] = h14
  R[31] = l15; R[32] = h15
end
do
  local pl = readu32(mem, prv + 128)
  local ph = readu32(mem, prv + 132)
  local l0 = bxor(pl, readu32(mem, ref + 128))
  local h0 = bxor(ph, readu32(mem, ref + 132))
  R[33] = l0; R[34] = h0
  T[33] = bxor(l0, readu32(mem, cur + 128))
  T[34] = bxor(h0, readu32(mem, cur + 132))
  local pl = readu32(mem, prv + 136)
  local ph = readu32(mem, prv + 140)
  local l1 = bxor(pl, readu32(mem, ref + 136))
  local h1 = bxor(ph, readu32(mem, ref + 140))
  R[35] = l1; R[36] = h1
  T[35] = bxor(l1, readu32(mem, cur + 136))
  T[36] = bxor(h1, readu32(mem, cur + 140))
  local pl = readu32(mem, prv + 144)
  local ph = readu32(mem, prv + 148)
  local l2 = bxor(pl, readu32(mem, ref + 144))
  local h2 = bxor(ph, readu32(mem, ref + 148))
  R[37] = l2; R[38] = h2
  T[37] = bxor(l2, readu32(mem, cur + 144))
  T[38] = bxor(h2, readu32(mem, cur + 148))
  local pl = readu32(mem, prv + 152)
  local ph = readu32(mem, prv + 156)
  local l3 = bxor(pl, readu32(mem, ref + 152))
  local h3 = bxor(ph, readu32(mem, ref + 156))
  R[39] = l3; R[40] = h3
  T[39] = bxor(l3, readu32(mem, cur + 152))
  T[40] = bxor(h3, readu32(mem, cur + 156))
  local pl = readu32(mem, prv + 160)
  local ph = readu32(mem, prv + 164)
  local l4 = bxor(pl, readu32(mem, ref + 160))
  local h4 = bxor(ph, readu32(mem, ref + 164))
  R[41] = l4; R[42] = h4
  T[41] = bxor(l4, readu32(mem, cur + 160))
  T[42] = bxor(h4, readu32(mem, cur + 164))
  local pl = readu32(mem, prv + 168)
  local ph = readu32(mem, prv + 172)
  local l5 = bxor(pl, readu32(mem, ref + 168))
  local h5 = bxor(ph, readu32(mem, ref + 172))
  R[43] = l5; R[44] = h5
  T[43] = bxor(l5, readu32(mem, cur + 168))
  T[44] = bxor(h5, readu32(mem, cur + 172))
  local pl = readu32(mem, prv + 176)
  local ph = readu32(mem, prv + 180)
  local l6 = bxor(pl, readu32(mem, ref + 176))
  local h6 = bxor(ph, readu32(mem, ref + 180))
  R[45] = l6; R[46] = h6
  T[45] = bxor(l6, readu32(mem, cur + 176))
  T[46] = bxor(h6, readu32(mem, cur + 180))
  local pl = readu32(mem, prv + 184)
  local ph = readu32(mem, prv + 188)
  local l7 = bxor(pl, readu32(mem, ref + 184))
  local h7 = bxor(ph, readu32(mem, ref + 188))
  R[47] = l7; R[48] = h7
  T[47] = bxor(l7, readu32(mem, cur + 184))
  T[48] = bxor(h7, readu32(mem, cur + 188))
  local pl = readu32(mem, prv + 192)
  local ph = readu32(mem, prv + 196)
  local l8 = bxor(pl, readu32(mem, ref + 192))
  local h8 = bxor(ph, readu32(mem, ref + 196))
  R[49] = l8; R[50] = h8
  T[49] = bxor(l8, readu32(mem, cur + 192))
  T[50] = bxor(h8, readu32(mem, cur + 196))
  local pl = readu32(mem, prv + 200)
  local ph = readu32(mem, prv + 204)
  local l9 = bxor(pl, readu32(mem, ref + 200))
  local h9 = bxor(ph, readu32(mem, ref + 204))
  R[51] = l9; R[52] = h9
  T[51] = bxor(l9, readu32(mem, cur + 200))
  T[52] = bxor(h9, readu32(mem, cur + 204))
  local pl = readu32(mem, prv + 208)
  local ph = readu32(mem, prv + 212)
  local l10 = bxor(pl, readu32(mem, ref + 208))
  local h10 = bxor(ph, readu32(mem, ref + 212))
  R[53] = l10; R[54] = h10
  T[53] = bxor(l10, readu32(mem, cur + 208))
  T[54] = bxor(h10, readu32(mem, cur + 212))
  local pl = readu32(mem, prv + 216)
  local ph = readu32(mem, prv + 220)
  local l11 = bxor(pl, readu32(mem, ref + 216))
  local h11 = bxor(ph, readu32(mem, ref + 220))
  R[55] = l11; R[56] = h11
  T[55] = bxor(l11, readu32(mem, cur + 216))
  T[56] = bxor(h11, readu32(mem, cur + 220))
  local pl = readu32(mem, prv + 224)
  local ph = readu32(mem, prv + 228)
  local l12 = bxor(pl, readu32(mem, ref + 224))
  local h12 = bxor(ph, readu32(mem, ref + 228))
  R[57] = l12; R[58] = h12
  T[57] = bxor(l12, readu32(mem, cur + 224))
  T[58] = bxor(h12, readu32(mem, cur + 228))
  local pl = readu32(mem, prv + 232)
  local ph = readu32(mem, prv + 236)
  local l13 = bxor(pl, readu32(mem, ref + 232))
  local h13 = bxor(ph, readu32(mem, ref + 236))
  R[59] = l13; R[60] = h13
  T[59] = bxor(l13, readu32(mem, cur + 232))
  T[60] = bxor(h13, readu32(mem, cur + 236))
  local pl = readu32(mem, prv + 240)
  local ph = readu32(mem, prv + 244)
  local l14 = bxor(pl, readu32(mem, ref + 240))
  local h14 = bxor(ph, readu32(mem, ref + 244))
  R[61] = l14; R[62] = h14
  T[61] = bxor(l14, readu32(mem, cur + 240))
  T[62] = bxor(h14, readu32(mem, cur + 244))
  local pl = readu32(mem, prv + 248)
  local ph = readu32(mem, prv + 252)
  local l15 = bxor(pl, readu32(mem, ref + 248))
  local h15 = bxor(ph, readu32(mem, ref + 252))
  R[63] = l15; R[64] = h15
  T[63] = bxor(l15, readu32(mem, cur + 248))
  T[64] = bxor(h15, readu32(mem, cur + 252))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[33] = l0; R[34] = h0
  R[35] = l1; R[36] = h1
  R[37] = l2; R[38] = h2
  R[39] = l3; R[40] = h3
  R[41] = l4; R[42] = h4
  R[43] = l5; R[44] = h5
  R[45] = l6; R[46] = h6
  R[47] = l7; R[48] = h7
  R[49] = l8; R[50] = h8
  R[51] = l9; R[52] = h9
  R[53] = l10; R[54] = h10
  R[55] = l11; R[56] = h11
  R[57] = l12; R[58] = h12
  R[59] = l13; R[60] = h13
  R[61] = l14; R[62] = h14
  R[63] = l15; R[64] = h15
end
do
  local pl = readu32(mem, prv + 256)
  local ph = readu32(mem, prv + 260)
  local l0 = bxor(pl, readu32(mem, ref + 256))
  local h0 = bxor(ph, readu32(mem, ref + 260))
  R[65] = l0; R[66] = h0
  T[65] = bxor(l0, readu32(mem, cur + 256))
  T[66] = bxor(h0, readu32(mem, cur + 260))
  local pl = readu32(mem, prv + 264)
  local ph = readu32(mem, prv + 268)
  local l1 = bxor(pl, readu32(mem, ref + 264))
  local h1 = bxor(ph, readu32(mem, ref + 268))
  R[67] = l1; R[68] = h1
  T[67] = bxor(l1, readu32(mem, cur + 264))
  T[68] = bxor(h1, readu32(mem, cur + 268))
  local pl = readu32(mem, prv + 272)
  local ph = readu32(mem, prv + 276)
  local l2 = bxor(pl, readu32(mem, ref + 272))
  local h2 = bxor(ph, readu32(mem, ref + 276))
  R[69] = l2; R[70] = h2
  T[69] = bxor(l2, readu32(mem, cur + 272))
  T[70] = bxor(h2, readu32(mem, cur + 276))
  local pl = readu32(mem, prv + 280)
  local ph = readu32(mem, prv + 284)
  local l3 = bxor(pl, readu32(mem, ref + 280))
  local h3 = bxor(ph, readu32(mem, ref + 284))
  R[71] = l3; R[72] = h3
  T[71] = bxor(l3, readu32(mem, cur + 280))
  T[72] = bxor(h3, readu32(mem, cur + 284))
  local pl = readu32(mem, prv + 288)
  local ph = readu32(mem, prv + 292)
  local l4 = bxor(pl, readu32(mem, ref + 288))
  local h4 = bxor(ph, readu32(mem, ref + 292))
  R[73] = l4; R[74] = h4
  T[73] = bxor(l4, readu32(mem, cur + 288))
  T[74] = bxor(h4, readu32(mem, cur + 292))
  local pl = readu32(mem, prv + 296)
  local ph = readu32(mem, prv + 300)
  local l5 = bxor(pl, readu32(mem, ref + 296))
  local h5 = bxor(ph, readu32(mem, ref + 300))
  R[75] = l5; R[76] = h5
  T[75] = bxor(l5, readu32(mem, cur + 296))
  T[76] = bxor(h5, readu32(mem, cur + 300))
  local pl = readu32(mem, prv + 304)
  local ph = readu32(mem, prv + 308)
  local l6 = bxor(pl, readu32(mem, ref + 304))
  local h6 = bxor(ph, readu32(mem, ref + 308))
  R[77] = l6; R[78] = h6
  T[77] = bxor(l6, readu32(mem, cur + 304))
  T[78] = bxor(h6, readu32(mem, cur + 308))
  local pl = readu32(mem, prv + 312)
  local ph = readu32(mem, prv + 316)
  local l7 = bxor(pl, readu32(mem, ref + 312))
  local h7 = bxor(ph, readu32(mem, ref + 316))
  R[79] = l7; R[80] = h7
  T[79] = bxor(l7, readu32(mem, cur + 312))
  T[80] = bxor(h7, readu32(mem, cur + 316))
  local pl = readu32(mem, prv + 320)
  local ph = readu32(mem, prv + 324)
  local l8 = bxor(pl, readu32(mem, ref + 320))
  local h8 = bxor(ph, readu32(mem, ref + 324))
  R[81] = l8; R[82] = h8
  T[81] = bxor(l8, readu32(mem, cur + 320))
  T[82] = bxor(h8, readu32(mem, cur + 324))
  local pl = readu32(mem, prv + 328)
  local ph = readu32(mem, prv + 332)
  local l9 = bxor(pl, readu32(mem, ref + 328))
  local h9 = bxor(ph, readu32(mem, ref + 332))
  R[83] = l9; R[84] = h9
  T[83] = bxor(l9, readu32(mem, cur + 328))
  T[84] = bxor(h9, readu32(mem, cur + 332))
  local pl = readu32(mem, prv + 336)
  local ph = readu32(mem, prv + 340)
  local l10 = bxor(pl, readu32(mem, ref + 336))
  local h10 = bxor(ph, readu32(mem, ref + 340))
  R[85] = l10; R[86] = h10
  T[85] = bxor(l10, readu32(mem, cur + 336))
  T[86] = bxor(h10, readu32(mem, cur + 340))
  local pl = readu32(mem, prv + 344)
  local ph = readu32(mem, prv + 348)
  local l11 = bxor(pl, readu32(mem, ref + 344))
  local h11 = bxor(ph, readu32(mem, ref + 348))
  R[87] = l11; R[88] = h11
  T[87] = bxor(l11, readu32(mem, cur + 344))
  T[88] = bxor(h11, readu32(mem, cur + 348))
  local pl = readu32(mem, prv + 352)
  local ph = readu32(mem, prv + 356)
  local l12 = bxor(pl, readu32(mem, ref + 352))
  local h12 = bxor(ph, readu32(mem, ref + 356))
  R[89] = l12; R[90] = h12
  T[89] = bxor(l12, readu32(mem, cur + 352))
  T[90] = bxor(h12, readu32(mem, cur + 356))
  local pl = readu32(mem, prv + 360)
  local ph = readu32(mem, prv + 364)
  local l13 = bxor(pl, readu32(mem, ref + 360))
  local h13 = bxor(ph, readu32(mem, ref + 364))
  R[91] = l13; R[92] = h13
  T[91] = bxor(l13, readu32(mem, cur + 360))
  T[92] = bxor(h13, readu32(mem, cur + 364))
  local pl = readu32(mem, prv + 368)
  local ph = readu32(mem, prv + 372)
  local l14 = bxor(pl, readu32(mem, ref + 368))
  local h14 = bxor(ph, readu32(mem, ref + 372))
  R[93] = l14; R[94] = h14
  T[93] = bxor(l14, readu32(mem, cur + 368))
  T[94] = bxor(h14, readu32(mem, cur + 372))
  local pl = readu32(mem, prv + 376)
  local ph = readu32(mem, prv + 380)
  local l15 = bxor(pl, readu32(mem, ref + 376))
  local h15 = bxor(ph, readu32(mem, ref + 380))
  R[95] = l15; R[96] = h15
  T[95] = bxor(l15, readu32(mem, cur + 376))
  T[96] = bxor(h15, readu32(mem, cur + 380))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[65] = l0; R[66] = h0
  R[67] = l1; R[68] = h1
  R[69] = l2; R[70] = h2
  R[71] = l3; R[72] = h3
  R[73] = l4; R[74] = h4
  R[75] = l5; R[76] = h5
  R[77] = l6; R[78] = h6
  R[79] = l7; R[80] = h7
  R[81] = l8; R[82] = h8
  R[83] = l9; R[84] = h9
  R[85] = l10; R[86] = h10
  R[87] = l11; R[88] = h11
  R[89] = l12; R[90] = h12
  R[91] = l13; R[92] = h13
  R[93] = l14; R[94] = h14
  R[95] = l15; R[96] = h15
end
do
  local pl = readu32(mem, prv + 384)
  local ph = readu32(mem, prv + 388)
  local l0 = bxor(pl, readu32(mem, ref + 384))
  local h0 = bxor(ph, readu32(mem, ref + 388))
  R[97] = l0; R[98] = h0
  T[97] = bxor(l0, readu32(mem, cur + 384))
  T[98] = bxor(h0, readu32(mem, cur + 388))
  local pl = readu32(mem, prv + 392)
  local ph = readu32(mem, prv + 396)
  local l1 = bxor(pl, readu32(mem, ref + 392))
  local h1 = bxor(ph, readu32(mem, ref + 396))
  R[99] = l1; R[100] = h1
  T[99] = bxor(l1, readu32(mem, cur + 392))
  T[100] = bxor(h1, readu32(mem, cur + 396))
  local pl = readu32(mem, prv + 400)
  local ph = readu32(mem, prv + 404)
  local l2 = bxor(pl, readu32(mem, ref + 400))
  local h2 = bxor(ph, readu32(mem, ref + 404))
  R[101] = l2; R[102] = h2
  T[101] = bxor(l2, readu32(mem, cur + 400))
  T[102] = bxor(h2, readu32(mem, cur + 404))
  local pl = readu32(mem, prv + 408)
  local ph = readu32(mem, prv + 412)
  local l3 = bxor(pl, readu32(mem, ref + 408))
  local h3 = bxor(ph, readu32(mem, ref + 412))
  R[103] = l3; R[104] = h3
  T[103] = bxor(l3, readu32(mem, cur + 408))
  T[104] = bxor(h3, readu32(mem, cur + 412))
  local pl = readu32(mem, prv + 416)
  local ph = readu32(mem, prv + 420)
  local l4 = bxor(pl, readu32(mem, ref + 416))
  local h4 = bxor(ph, readu32(mem, ref + 420))
  R[105] = l4; R[106] = h4
  T[105] = bxor(l4, readu32(mem, cur + 416))
  T[106] = bxor(h4, readu32(mem, cur + 420))
  local pl = readu32(mem, prv + 424)
  local ph = readu32(mem, prv + 428)
  local l5 = bxor(pl, readu32(mem, ref + 424))
  local h5 = bxor(ph, readu32(mem, ref + 428))
  R[107] = l5; R[108] = h5
  T[107] = bxor(l5, readu32(mem, cur + 424))
  T[108] = bxor(h5, readu32(mem, cur + 428))
  local pl = readu32(mem, prv + 432)
  local ph = readu32(mem, prv + 436)
  local l6 = bxor(pl, readu32(mem, ref + 432))
  local h6 = bxor(ph, readu32(mem, ref + 436))
  R[109] = l6; R[110] = h6
  T[109] = bxor(l6, readu32(mem, cur + 432))
  T[110] = bxor(h6, readu32(mem, cur + 436))
  local pl = readu32(mem, prv + 440)
  local ph = readu32(mem, prv + 444)
  local l7 = bxor(pl, readu32(mem, ref + 440))
  local h7 = bxor(ph, readu32(mem, ref + 444))
  R[111] = l7; R[112] = h7
  T[111] = bxor(l7, readu32(mem, cur + 440))
  T[112] = bxor(h7, readu32(mem, cur + 444))
  local pl = readu32(mem, prv + 448)
  local ph = readu32(mem, prv + 452)
  local l8 = bxor(pl, readu32(mem, ref + 448))
  local h8 = bxor(ph, readu32(mem, ref + 452))
  R[113] = l8; R[114] = h8
  T[113] = bxor(l8, readu32(mem, cur + 448))
  T[114] = bxor(h8, readu32(mem, cur + 452))
  local pl = readu32(mem, prv + 456)
  local ph = readu32(mem, prv + 460)
  local l9 = bxor(pl, readu32(mem, ref + 456))
  local h9 = bxor(ph, readu32(mem, ref + 460))
  R[115] = l9; R[116] = h9
  T[115] = bxor(l9, readu32(mem, cur + 456))
  T[116] = bxor(h9, readu32(mem, cur + 460))
  local pl = readu32(mem, prv + 464)
  local ph = readu32(mem, prv + 468)
  local l10 = bxor(pl, readu32(mem, ref + 464))
  local h10 = bxor(ph, readu32(mem, ref + 468))
  R[117] = l10; R[118] = h10
  T[117] = bxor(l10, readu32(mem, cur + 464))
  T[118] = bxor(h10, readu32(mem, cur + 468))
  local pl = readu32(mem, prv + 472)
  local ph = readu32(mem, prv + 476)
  local l11 = bxor(pl, readu32(mem, ref + 472))
  local h11 = bxor(ph, readu32(mem, ref + 476))
  R[119] = l11; R[120] = h11
  T[119] = bxor(l11, readu32(mem, cur + 472))
  T[120] = bxor(h11, readu32(mem, cur + 476))
  local pl = readu32(mem, prv + 480)
  local ph = readu32(mem, prv + 484)
  local l12 = bxor(pl, readu32(mem, ref + 480))
  local h12 = bxor(ph, readu32(mem, ref + 484))
  R[121] = l12; R[122] = h12
  T[121] = bxor(l12, readu32(mem, cur + 480))
  T[122] = bxor(h12, readu32(mem, cur + 484))
  local pl = readu32(mem, prv + 488)
  local ph = readu32(mem, prv + 492)
  local l13 = bxor(pl, readu32(mem, ref + 488))
  local h13 = bxor(ph, readu32(mem, ref + 492))
  R[123] = l13; R[124] = h13
  T[123] = bxor(l13, readu32(mem, cur + 488))
  T[124] = bxor(h13, readu32(mem, cur + 492))
  local pl = readu32(mem, prv + 496)
  local ph = readu32(mem, prv + 500)
  local l14 = bxor(pl, readu32(mem, ref + 496))
  local h14 = bxor(ph, readu32(mem, ref + 500))
  R[125] = l14; R[126] = h14
  T[125] = bxor(l14, readu32(mem, cur + 496))
  T[126] = bxor(h14, readu32(mem, cur + 500))
  local pl = readu32(mem, prv + 504)
  local ph = readu32(mem, prv + 508)
  local l15 = bxor(pl, readu32(mem, ref + 504))
  local h15 = bxor(ph, readu32(mem, ref + 508))
  R[127] = l15; R[128] = h15
  T[127] = bxor(l15, readu32(mem, cur + 504))
  T[128] = bxor(h15, readu32(mem, cur + 508))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[97] = l0; R[98] = h0
  R[99] = l1; R[100] = h1
  R[101] = l2; R[102] = h2
  R[103] = l3; R[104] = h3
  R[105] = l4; R[106] = h4
  R[107] = l5; R[108] = h5
  R[109] = l6; R[110] = h6
  R[111] = l7; R[112] = h7
  R[113] = l8; R[114] = h8
  R[115] = l9; R[116] = h9
  R[117] = l10; R[118] = h10
  R[119] = l11; R[120] = h11
  R[121] = l12; R[122] = h12
  R[123] = l13; R[124] = h13
  R[125] = l14; R[126] = h14
  R[127] = l15; R[128] = h15
end
do
  local pl = readu32(mem, prv + 512)
  local ph = readu32(mem, prv + 516)
  local l0 = bxor(pl, readu32(mem, ref + 512))
  local h0 = bxor(ph, readu32(mem, ref + 516))
  R[129] = l0; R[130] = h0
  T[129] = bxor(l0, readu32(mem, cur + 512))
  T[130] = bxor(h0, readu32(mem, cur + 516))
  local pl = readu32(mem, prv + 520)
  local ph = readu32(mem, prv + 524)
  local l1 = bxor(pl, readu32(mem, ref + 520))
  local h1 = bxor(ph, readu32(mem, ref + 524))
  R[131] = l1; R[132] = h1
  T[131] = bxor(l1, readu32(mem, cur + 520))
  T[132] = bxor(h1, readu32(mem, cur + 524))
  local pl = readu32(mem, prv + 528)
  local ph = readu32(mem, prv + 532)
  local l2 = bxor(pl, readu32(mem, ref + 528))
  local h2 = bxor(ph, readu32(mem, ref + 532))
  R[133] = l2; R[134] = h2
  T[133] = bxor(l2, readu32(mem, cur + 528))
  T[134] = bxor(h2, readu32(mem, cur + 532))
  local pl = readu32(mem, prv + 536)
  local ph = readu32(mem, prv + 540)
  local l3 = bxor(pl, readu32(mem, ref + 536))
  local h3 = bxor(ph, readu32(mem, ref + 540))
  R[135] = l3; R[136] = h3
  T[135] = bxor(l3, readu32(mem, cur + 536))
  T[136] = bxor(h3, readu32(mem, cur + 540))
  local pl = readu32(mem, prv + 544)
  local ph = readu32(mem, prv + 548)
  local l4 = bxor(pl, readu32(mem, ref + 544))
  local h4 = bxor(ph, readu32(mem, ref + 548))
  R[137] = l4; R[138] = h4
  T[137] = bxor(l4, readu32(mem, cur + 544))
  T[138] = bxor(h4, readu32(mem, cur + 548))
  local pl = readu32(mem, prv + 552)
  local ph = readu32(mem, prv + 556)
  local l5 = bxor(pl, readu32(mem, ref + 552))
  local h5 = bxor(ph, readu32(mem, ref + 556))
  R[139] = l5; R[140] = h5
  T[139] = bxor(l5, readu32(mem, cur + 552))
  T[140] = bxor(h5, readu32(mem, cur + 556))
  local pl = readu32(mem, prv + 560)
  local ph = readu32(mem, prv + 564)
  local l6 = bxor(pl, readu32(mem, ref + 560))
  local h6 = bxor(ph, readu32(mem, ref + 564))
  R[141] = l6; R[142] = h6
  T[141] = bxor(l6, readu32(mem, cur + 560))
  T[142] = bxor(h6, readu32(mem, cur + 564))
  local pl = readu32(mem, prv + 568)
  local ph = readu32(mem, prv + 572)
  local l7 = bxor(pl, readu32(mem, ref + 568))
  local h7 = bxor(ph, readu32(mem, ref + 572))
  R[143] = l7; R[144] = h7
  T[143] = bxor(l7, readu32(mem, cur + 568))
  T[144] = bxor(h7, readu32(mem, cur + 572))
  local pl = readu32(mem, prv + 576)
  local ph = readu32(mem, prv + 580)
  local l8 = bxor(pl, readu32(mem, ref + 576))
  local h8 = bxor(ph, readu32(mem, ref + 580))
  R[145] = l8; R[146] = h8
  T[145] = bxor(l8, readu32(mem, cur + 576))
  T[146] = bxor(h8, readu32(mem, cur + 580))
  local pl = readu32(mem, prv + 584)
  local ph = readu32(mem, prv + 588)
  local l9 = bxor(pl, readu32(mem, ref + 584))
  local h9 = bxor(ph, readu32(mem, ref + 588))
  R[147] = l9; R[148] = h9
  T[147] = bxor(l9, readu32(mem, cur + 584))
  T[148] = bxor(h9, readu32(mem, cur + 588))
  local pl = readu32(mem, prv + 592)
  local ph = readu32(mem, prv + 596)
  local l10 = bxor(pl, readu32(mem, ref + 592))
  local h10 = bxor(ph, readu32(mem, ref + 596))
  R[149] = l10; R[150] = h10
  T[149] = bxor(l10, readu32(mem, cur + 592))
  T[150] = bxor(h10, readu32(mem, cur + 596))
  local pl = readu32(mem, prv + 600)
  local ph = readu32(mem, prv + 604)
  local l11 = bxor(pl, readu32(mem, ref + 600))
  local h11 = bxor(ph, readu32(mem, ref + 604))
  R[151] = l11; R[152] = h11
  T[151] = bxor(l11, readu32(mem, cur + 600))
  T[152] = bxor(h11, readu32(mem, cur + 604))
  local pl = readu32(mem, prv + 608)
  local ph = readu32(mem, prv + 612)
  local l12 = bxor(pl, readu32(mem, ref + 608))
  local h12 = bxor(ph, readu32(mem, ref + 612))
  R[153] = l12; R[154] = h12
  T[153] = bxor(l12, readu32(mem, cur + 608))
  T[154] = bxor(h12, readu32(mem, cur + 612))
  local pl = readu32(mem, prv + 616)
  local ph = readu32(mem, prv + 620)
  local l13 = bxor(pl, readu32(mem, ref + 616))
  local h13 = bxor(ph, readu32(mem, ref + 620))
  R[155] = l13; R[156] = h13
  T[155] = bxor(l13, readu32(mem, cur + 616))
  T[156] = bxor(h13, readu32(mem, cur + 620))
  local pl = readu32(mem, prv + 624)
  local ph = readu32(mem, prv + 628)
  local l14 = bxor(pl, readu32(mem, ref + 624))
  local h14 = bxor(ph, readu32(mem, ref + 628))
  R[157] = l14; R[158] = h14
  T[157] = bxor(l14, readu32(mem, cur + 624))
  T[158] = bxor(h14, readu32(mem, cur + 628))
  local pl = readu32(mem, prv + 632)
  local ph = readu32(mem, prv + 636)
  local l15 = bxor(pl, readu32(mem, ref + 632))
  local h15 = bxor(ph, readu32(mem, ref + 636))
  R[159] = l15; R[160] = h15
  T[159] = bxor(l15, readu32(mem, cur + 632))
  T[160] = bxor(h15, readu32(mem, cur + 636))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[129] = l0; R[130] = h0
  R[131] = l1; R[132] = h1
  R[133] = l2; R[134] = h2
  R[135] = l3; R[136] = h3
  R[137] = l4; R[138] = h4
  R[139] = l5; R[140] = h5
  R[141] = l6; R[142] = h6
  R[143] = l7; R[144] = h7
  R[145] = l8; R[146] = h8
  R[147] = l9; R[148] = h9
  R[149] = l10; R[150] = h10
  R[151] = l11; R[152] = h11
  R[153] = l12; R[154] = h12
  R[155] = l13; R[156] = h13
  R[157] = l14; R[158] = h14
  R[159] = l15; R[160] = h15
end
do
  local pl = readu32(mem, prv + 640)
  local ph = readu32(mem, prv + 644)
  local l0 = bxor(pl, readu32(mem, ref + 640))
  local h0 = bxor(ph, readu32(mem, ref + 644))
  R[161] = l0; R[162] = h0
  T[161] = bxor(l0, readu32(mem, cur + 640))
  T[162] = bxor(h0, readu32(mem, cur + 644))
  local pl = readu32(mem, prv + 648)
  local ph = readu32(mem, prv + 652)
  local l1 = bxor(pl, readu32(mem, ref + 648))
  local h1 = bxor(ph, readu32(mem, ref + 652))
  R[163] = l1; R[164] = h1
  T[163] = bxor(l1, readu32(mem, cur + 648))
  T[164] = bxor(h1, readu32(mem, cur + 652))
  local pl = readu32(mem, prv + 656)
  local ph = readu32(mem, prv + 660)
  local l2 = bxor(pl, readu32(mem, ref + 656))
  local h2 = bxor(ph, readu32(mem, ref + 660))
  R[165] = l2; R[166] = h2
  T[165] = bxor(l2, readu32(mem, cur + 656))
  T[166] = bxor(h2, readu32(mem, cur + 660))
  local pl = readu32(mem, prv + 664)
  local ph = readu32(mem, prv + 668)
  local l3 = bxor(pl, readu32(mem, ref + 664))
  local h3 = bxor(ph, readu32(mem, ref + 668))
  R[167] = l3; R[168] = h3
  T[167] = bxor(l3, readu32(mem, cur + 664))
  T[168] = bxor(h3, readu32(mem, cur + 668))
  local pl = readu32(mem, prv + 672)
  local ph = readu32(mem, prv + 676)
  local l4 = bxor(pl, readu32(mem, ref + 672))
  local h4 = bxor(ph, readu32(mem, ref + 676))
  R[169] = l4; R[170] = h4
  T[169] = bxor(l4, readu32(mem, cur + 672))
  T[170] = bxor(h4, readu32(mem, cur + 676))
  local pl = readu32(mem, prv + 680)
  local ph = readu32(mem, prv + 684)
  local l5 = bxor(pl, readu32(mem, ref + 680))
  local h5 = bxor(ph, readu32(mem, ref + 684))
  R[171] = l5; R[172] = h5
  T[171] = bxor(l5, readu32(mem, cur + 680))
  T[172] = bxor(h5, readu32(mem, cur + 684))
  local pl = readu32(mem, prv + 688)
  local ph = readu32(mem, prv + 692)
  local l6 = bxor(pl, readu32(mem, ref + 688))
  local h6 = bxor(ph, readu32(mem, ref + 692))
  R[173] = l6; R[174] = h6
  T[173] = bxor(l6, readu32(mem, cur + 688))
  T[174] = bxor(h6, readu32(mem, cur + 692))
  local pl = readu32(mem, prv + 696)
  local ph = readu32(mem, prv + 700)
  local l7 = bxor(pl, readu32(mem, ref + 696))
  local h7 = bxor(ph, readu32(mem, ref + 700))
  R[175] = l7; R[176] = h7
  T[175] = bxor(l7, readu32(mem, cur + 696))
  T[176] = bxor(h7, readu32(mem, cur + 700))
  local pl = readu32(mem, prv + 704)
  local ph = readu32(mem, prv + 708)
  local l8 = bxor(pl, readu32(mem, ref + 704))
  local h8 = bxor(ph, readu32(mem, ref + 708))
  R[177] = l8; R[178] = h8
  T[177] = bxor(l8, readu32(mem, cur + 704))
  T[178] = bxor(h8, readu32(mem, cur + 708))
  local pl = readu32(mem, prv + 712)
  local ph = readu32(mem, prv + 716)
  local l9 = bxor(pl, readu32(mem, ref + 712))
  local h9 = bxor(ph, readu32(mem, ref + 716))
  R[179] = l9; R[180] = h9
  T[179] = bxor(l9, readu32(mem, cur + 712))
  T[180] = bxor(h9, readu32(mem, cur + 716))
  local pl = readu32(mem, prv + 720)
  local ph = readu32(mem, prv + 724)
  local l10 = bxor(pl, readu32(mem, ref + 720))
  local h10 = bxor(ph, readu32(mem, ref + 724))
  R[181] = l10; R[182] = h10
  T[181] = bxor(l10, readu32(mem, cur + 720))
  T[182] = bxor(h10, readu32(mem, cur + 724))
  local pl = readu32(mem, prv + 728)
  local ph = readu32(mem, prv + 732)
  local l11 = bxor(pl, readu32(mem, ref + 728))
  local h11 = bxor(ph, readu32(mem, ref + 732))
  R[183] = l11; R[184] = h11
  T[183] = bxor(l11, readu32(mem, cur + 728))
  T[184] = bxor(h11, readu32(mem, cur + 732))
  local pl = readu32(mem, prv + 736)
  local ph = readu32(mem, prv + 740)
  local l12 = bxor(pl, readu32(mem, ref + 736))
  local h12 = bxor(ph, readu32(mem, ref + 740))
  R[185] = l12; R[186] = h12
  T[185] = bxor(l12, readu32(mem, cur + 736))
  T[186] = bxor(h12, readu32(mem, cur + 740))
  local pl = readu32(mem, prv + 744)
  local ph = readu32(mem, prv + 748)
  local l13 = bxor(pl, readu32(mem, ref + 744))
  local h13 = bxor(ph, readu32(mem, ref + 748))
  R[187] = l13; R[188] = h13
  T[187] = bxor(l13, readu32(mem, cur + 744))
  T[188] = bxor(h13, readu32(mem, cur + 748))
  local pl = readu32(mem, prv + 752)
  local ph = readu32(mem, prv + 756)
  local l14 = bxor(pl, readu32(mem, ref + 752))
  local h14 = bxor(ph, readu32(mem, ref + 756))
  R[189] = l14; R[190] = h14
  T[189] = bxor(l14, readu32(mem, cur + 752))
  T[190] = bxor(h14, readu32(mem, cur + 756))
  local pl = readu32(mem, prv + 760)
  local ph = readu32(mem, prv + 764)
  local l15 = bxor(pl, readu32(mem, ref + 760))
  local h15 = bxor(ph, readu32(mem, ref + 764))
  R[191] = l15; R[192] = h15
  T[191] = bxor(l15, readu32(mem, cur + 760))
  T[192] = bxor(h15, readu32(mem, cur + 764))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[161] = l0; R[162] = h0
  R[163] = l1; R[164] = h1
  R[165] = l2; R[166] = h2
  R[167] = l3; R[168] = h3
  R[169] = l4; R[170] = h4
  R[171] = l5; R[172] = h5
  R[173] = l6; R[174] = h6
  R[175] = l7; R[176] = h7
  R[177] = l8; R[178] = h8
  R[179] = l9; R[180] = h9
  R[181] = l10; R[182] = h10
  R[183] = l11; R[184] = h11
  R[185] = l12; R[186] = h12
  R[187] = l13; R[188] = h13
  R[189] = l14; R[190] = h14
  R[191] = l15; R[192] = h15
end
do
  local pl = readu32(mem, prv + 768)
  local ph = readu32(mem, prv + 772)
  local l0 = bxor(pl, readu32(mem, ref + 768))
  local h0 = bxor(ph, readu32(mem, ref + 772))
  R[193] = l0; R[194] = h0
  T[193] = bxor(l0, readu32(mem, cur + 768))
  T[194] = bxor(h0, readu32(mem, cur + 772))
  local pl = readu32(mem, prv + 776)
  local ph = readu32(mem, prv + 780)
  local l1 = bxor(pl, readu32(mem, ref + 776))
  local h1 = bxor(ph, readu32(mem, ref + 780))
  R[195] = l1; R[196] = h1
  T[195] = bxor(l1, readu32(mem, cur + 776))
  T[196] = bxor(h1, readu32(mem, cur + 780))
  local pl = readu32(mem, prv + 784)
  local ph = readu32(mem, prv + 788)
  local l2 = bxor(pl, readu32(mem, ref + 784))
  local h2 = bxor(ph, readu32(mem, ref + 788))
  R[197] = l2; R[198] = h2
  T[197] = bxor(l2, readu32(mem, cur + 784))
  T[198] = bxor(h2, readu32(mem, cur + 788))
  local pl = readu32(mem, prv + 792)
  local ph = readu32(mem, prv + 796)
  local l3 = bxor(pl, readu32(mem, ref + 792))
  local h3 = bxor(ph, readu32(mem, ref + 796))
  R[199] = l3; R[200] = h3
  T[199] = bxor(l3, readu32(mem, cur + 792))
  T[200] = bxor(h3, readu32(mem, cur + 796))
  local pl = readu32(mem, prv + 800)
  local ph = readu32(mem, prv + 804)
  local l4 = bxor(pl, readu32(mem, ref + 800))
  local h4 = bxor(ph, readu32(mem, ref + 804))
  R[201] = l4; R[202] = h4
  T[201] = bxor(l4, readu32(mem, cur + 800))
  T[202] = bxor(h4, readu32(mem, cur + 804))
  local pl = readu32(mem, prv + 808)
  local ph = readu32(mem, prv + 812)
  local l5 = bxor(pl, readu32(mem, ref + 808))
  local h5 = bxor(ph, readu32(mem, ref + 812))
  R[203] = l5; R[204] = h5
  T[203] = bxor(l5, readu32(mem, cur + 808))
  T[204] = bxor(h5, readu32(mem, cur + 812))
  local pl = readu32(mem, prv + 816)
  local ph = readu32(mem, prv + 820)
  local l6 = bxor(pl, readu32(mem, ref + 816))
  local h6 = bxor(ph, readu32(mem, ref + 820))
  R[205] = l6; R[206] = h6
  T[205] = bxor(l6, readu32(mem, cur + 816))
  T[206] = bxor(h6, readu32(mem, cur + 820))
  local pl = readu32(mem, prv + 824)
  local ph = readu32(mem, prv + 828)
  local l7 = bxor(pl, readu32(mem, ref + 824))
  local h7 = bxor(ph, readu32(mem, ref + 828))
  R[207] = l7; R[208] = h7
  T[207] = bxor(l7, readu32(mem, cur + 824))
  T[208] = bxor(h7, readu32(mem, cur + 828))
  local pl = readu32(mem, prv + 832)
  local ph = readu32(mem, prv + 836)
  local l8 = bxor(pl, readu32(mem, ref + 832))
  local h8 = bxor(ph, readu32(mem, ref + 836))
  R[209] = l8; R[210] = h8
  T[209] = bxor(l8, readu32(mem, cur + 832))
  T[210] = bxor(h8, readu32(mem, cur + 836))
  local pl = readu32(mem, prv + 840)
  local ph = readu32(mem, prv + 844)
  local l9 = bxor(pl, readu32(mem, ref + 840))
  local h9 = bxor(ph, readu32(mem, ref + 844))
  R[211] = l9; R[212] = h9
  T[211] = bxor(l9, readu32(mem, cur + 840))
  T[212] = bxor(h9, readu32(mem, cur + 844))
  local pl = readu32(mem, prv + 848)
  local ph = readu32(mem, prv + 852)
  local l10 = bxor(pl, readu32(mem, ref + 848))
  local h10 = bxor(ph, readu32(mem, ref + 852))
  R[213] = l10; R[214] = h10
  T[213] = bxor(l10, readu32(mem, cur + 848))
  T[214] = bxor(h10, readu32(mem, cur + 852))
  local pl = readu32(mem, prv + 856)
  local ph = readu32(mem, prv + 860)
  local l11 = bxor(pl, readu32(mem, ref + 856))
  local h11 = bxor(ph, readu32(mem, ref + 860))
  R[215] = l11; R[216] = h11
  T[215] = bxor(l11, readu32(mem, cur + 856))
  T[216] = bxor(h11, readu32(mem, cur + 860))
  local pl = readu32(mem, prv + 864)
  local ph = readu32(mem, prv + 868)
  local l12 = bxor(pl, readu32(mem, ref + 864))
  local h12 = bxor(ph, readu32(mem, ref + 868))
  R[217] = l12; R[218] = h12
  T[217] = bxor(l12, readu32(mem, cur + 864))
  T[218] = bxor(h12, readu32(mem, cur + 868))
  local pl = readu32(mem, prv + 872)
  local ph = readu32(mem, prv + 876)
  local l13 = bxor(pl, readu32(mem, ref + 872))
  local h13 = bxor(ph, readu32(mem, ref + 876))
  R[219] = l13; R[220] = h13
  T[219] = bxor(l13, readu32(mem, cur + 872))
  T[220] = bxor(h13, readu32(mem, cur + 876))
  local pl = readu32(mem, prv + 880)
  local ph = readu32(mem, prv + 884)
  local l14 = bxor(pl, readu32(mem, ref + 880))
  local h14 = bxor(ph, readu32(mem, ref + 884))
  R[221] = l14; R[222] = h14
  T[221] = bxor(l14, readu32(mem, cur + 880))
  T[222] = bxor(h14, readu32(mem, cur + 884))
  local pl = readu32(mem, prv + 888)
  local ph = readu32(mem, prv + 892)
  local l15 = bxor(pl, readu32(mem, ref + 888))
  local h15 = bxor(ph, readu32(mem, ref + 892))
  R[223] = l15; R[224] = h15
  T[223] = bxor(l15, readu32(mem, cur + 888))
  T[224] = bxor(h15, readu32(mem, cur + 892))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[193] = l0; R[194] = h0
  R[195] = l1; R[196] = h1
  R[197] = l2; R[198] = h2
  R[199] = l3; R[200] = h3
  R[201] = l4; R[202] = h4
  R[203] = l5; R[204] = h5
  R[205] = l6; R[206] = h6
  R[207] = l7; R[208] = h7
  R[209] = l8; R[210] = h8
  R[211] = l9; R[212] = h9
  R[213] = l10; R[214] = h10
  R[215] = l11; R[216] = h11
  R[217] = l12; R[218] = h12
  R[219] = l13; R[220] = h13
  R[221] = l14; R[222] = h14
  R[223] = l15; R[224] = h15
end
do
  local pl = readu32(mem, prv + 896)
  local ph = readu32(mem, prv + 900)
  local l0 = bxor(pl, readu32(mem, ref + 896))
  local h0 = bxor(ph, readu32(mem, ref + 900))
  R[225] = l0; R[226] = h0
  T[225] = bxor(l0, readu32(mem, cur + 896))
  T[226] = bxor(h0, readu32(mem, cur + 900))
  local pl = readu32(mem, prv + 904)
  local ph = readu32(mem, prv + 908)
  local l1 = bxor(pl, readu32(mem, ref + 904))
  local h1 = bxor(ph, readu32(mem, ref + 908))
  R[227] = l1; R[228] = h1
  T[227] = bxor(l1, readu32(mem, cur + 904))
  T[228] = bxor(h1, readu32(mem, cur + 908))
  local pl = readu32(mem, prv + 912)
  local ph = readu32(mem, prv + 916)
  local l2 = bxor(pl, readu32(mem, ref + 912))
  local h2 = bxor(ph, readu32(mem, ref + 916))
  R[229] = l2; R[230] = h2
  T[229] = bxor(l2, readu32(mem, cur + 912))
  T[230] = bxor(h2, readu32(mem, cur + 916))
  local pl = readu32(mem, prv + 920)
  local ph = readu32(mem, prv + 924)
  local l3 = bxor(pl, readu32(mem, ref + 920))
  local h3 = bxor(ph, readu32(mem, ref + 924))
  R[231] = l3; R[232] = h3
  T[231] = bxor(l3, readu32(mem, cur + 920))
  T[232] = bxor(h3, readu32(mem, cur + 924))
  local pl = readu32(mem, prv + 928)
  local ph = readu32(mem, prv + 932)
  local l4 = bxor(pl, readu32(mem, ref + 928))
  local h4 = bxor(ph, readu32(mem, ref + 932))
  R[233] = l4; R[234] = h4
  T[233] = bxor(l4, readu32(mem, cur + 928))
  T[234] = bxor(h4, readu32(mem, cur + 932))
  local pl = readu32(mem, prv + 936)
  local ph = readu32(mem, prv + 940)
  local l5 = bxor(pl, readu32(mem, ref + 936))
  local h5 = bxor(ph, readu32(mem, ref + 940))
  R[235] = l5; R[236] = h5
  T[235] = bxor(l5, readu32(mem, cur + 936))
  T[236] = bxor(h5, readu32(mem, cur + 940))
  local pl = readu32(mem, prv + 944)
  local ph = readu32(mem, prv + 948)
  local l6 = bxor(pl, readu32(mem, ref + 944))
  local h6 = bxor(ph, readu32(mem, ref + 948))
  R[237] = l6; R[238] = h6
  T[237] = bxor(l6, readu32(mem, cur + 944))
  T[238] = bxor(h6, readu32(mem, cur + 948))
  local pl = readu32(mem, prv + 952)
  local ph = readu32(mem, prv + 956)
  local l7 = bxor(pl, readu32(mem, ref + 952))
  local h7 = bxor(ph, readu32(mem, ref + 956))
  R[239] = l7; R[240] = h7
  T[239] = bxor(l7, readu32(mem, cur + 952))
  T[240] = bxor(h7, readu32(mem, cur + 956))
  local pl = readu32(mem, prv + 960)
  local ph = readu32(mem, prv + 964)
  local l8 = bxor(pl, readu32(mem, ref + 960))
  local h8 = bxor(ph, readu32(mem, ref + 964))
  R[241] = l8; R[242] = h8
  T[241] = bxor(l8, readu32(mem, cur + 960))
  T[242] = bxor(h8, readu32(mem, cur + 964))
  local pl = readu32(mem, prv + 968)
  local ph = readu32(mem, prv + 972)
  local l9 = bxor(pl, readu32(mem, ref + 968))
  local h9 = bxor(ph, readu32(mem, ref + 972))
  R[243] = l9; R[244] = h9
  T[243] = bxor(l9, readu32(mem, cur + 968))
  T[244] = bxor(h9, readu32(mem, cur + 972))
  local pl = readu32(mem, prv + 976)
  local ph = readu32(mem, prv + 980)
  local l10 = bxor(pl, readu32(mem, ref + 976))
  local h10 = bxor(ph, readu32(mem, ref + 980))
  R[245] = l10; R[246] = h10
  T[245] = bxor(l10, readu32(mem, cur + 976))
  T[246] = bxor(h10, readu32(mem, cur + 980))
  local pl = readu32(mem, prv + 984)
  local ph = readu32(mem, prv + 988)
  local l11 = bxor(pl, readu32(mem, ref + 984))
  local h11 = bxor(ph, readu32(mem, ref + 988))
  R[247] = l11; R[248] = h11
  T[247] = bxor(l11, readu32(mem, cur + 984))
  T[248] = bxor(h11, readu32(mem, cur + 988))
  local pl = readu32(mem, prv + 992)
  local ph = readu32(mem, prv + 996)
  local l12 = bxor(pl, readu32(mem, ref + 992))
  local h12 = bxor(ph, readu32(mem, ref + 996))
  R[249] = l12; R[250] = h12
  T[249] = bxor(l12, readu32(mem, cur + 992))
  T[250] = bxor(h12, readu32(mem, cur + 996))
  local pl = readu32(mem, prv + 1000)
  local ph = readu32(mem, prv + 1004)
  local l13 = bxor(pl, readu32(mem, ref + 1000))
  local h13 = bxor(ph, readu32(mem, ref + 1004))
  R[251] = l13; R[252] = h13
  T[251] = bxor(l13, readu32(mem, cur + 1000))
  T[252] = bxor(h13, readu32(mem, cur + 1004))
  local pl = readu32(mem, prv + 1008)
  local ph = readu32(mem, prv + 1012)
  local l14 = bxor(pl, readu32(mem, ref + 1008))
  local h14 = bxor(ph, readu32(mem, ref + 1012))
  R[253] = l14; R[254] = h14
  T[253] = bxor(l14, readu32(mem, cur + 1008))
  T[254] = bxor(h14, readu32(mem, cur + 1012))
  local pl = readu32(mem, prv + 1016)
  local ph = readu32(mem, prv + 1020)
  local l15 = bxor(pl, readu32(mem, ref + 1016))
  local h15 = bxor(ph, readu32(mem, ref + 1020))
  R[255] = l15; R[256] = h15
  T[255] = bxor(l15, readu32(mem, cur + 1016))
  T[256] = bxor(h15, readu32(mem, cur + 1020))
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  R[225] = l0; R[226] = h0
  R[227] = l1; R[228] = h1
  R[229] = l2; R[230] = h2
  R[231] = l3; R[232] = h3
  R[233] = l4; R[234] = h4
  R[235] = l5; R[236] = h5
  R[237] = l6; R[238] = h6
  R[239] = l7; R[240] = h7
  R[241] = l8; R[242] = h8
  R[243] = l9; R[244] = h9
  R[245] = l10; R[246] = h10
  R[247] = l11; R[248] = h11
  R[249] = l12; R[250] = h12
  R[251] = l13; R[252] = h13
  R[253] = l14; R[254] = h14
  R[255] = l15; R[256] = h15
end
do
  local l0, h0 = R[1], R[2]
  local l1, h1 = R[3], R[4]
  local l2, h2 = R[33], R[34]
  local l3, h3 = R[35], R[36]
  local l4, h4 = R[65], R[66]
  local l5, h5 = R[67], R[68]
  local l6, h6 = R[97], R[98]
  local l7, h7 = R[99], R[100]
  local l8, h8 = R[129], R[130]
  local l9, h9 = R[131], R[132]
  local l10, h10 = R[161], R[162]
  local l11, h11 = R[163], R[164]
  local l12, h12 = R[193], R[194]
  local l13, h13 = R[195], R[196]
  local l14, h14 = R[225], R[226]
  local l15, h15 = R[227], R[228]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 0, bxor(T[1], l0))
  writeu32(mem, cur + 4, bxor(T[2], h0))
  writeu32(mem, cur + 8, bxor(T[3], l1))
  writeu32(mem, cur + 12, bxor(T[4], h1))
  writeu32(mem, cur + 128, bxor(T[33], l2))
  writeu32(mem, cur + 132, bxor(T[34], h2))
  writeu32(mem, cur + 136, bxor(T[35], l3))
  writeu32(mem, cur + 140, bxor(T[36], h3))
  writeu32(mem, cur + 256, bxor(T[65], l4))
  writeu32(mem, cur + 260, bxor(T[66], h4))
  writeu32(mem, cur + 264, bxor(T[67], l5))
  writeu32(mem, cur + 268, bxor(T[68], h5))
  writeu32(mem, cur + 384, bxor(T[97], l6))
  writeu32(mem, cur + 388, bxor(T[98], h6))
  writeu32(mem, cur + 392, bxor(T[99], l7))
  writeu32(mem, cur + 396, bxor(T[100], h7))
  writeu32(mem, cur + 512, bxor(T[129], l8))
  writeu32(mem, cur + 516, bxor(T[130], h8))
  writeu32(mem, cur + 520, bxor(T[131], l9))
  writeu32(mem, cur + 524, bxor(T[132], h9))
  writeu32(mem, cur + 640, bxor(T[161], l10))
  writeu32(mem, cur + 644, bxor(T[162], h10))
  writeu32(mem, cur + 648, bxor(T[163], l11))
  writeu32(mem, cur + 652, bxor(T[164], h11))
  writeu32(mem, cur + 768, bxor(T[193], l12))
  writeu32(mem, cur + 772, bxor(T[194], h12))
  writeu32(mem, cur + 776, bxor(T[195], l13))
  writeu32(mem, cur + 780, bxor(T[196], h13))
  writeu32(mem, cur + 896, bxor(T[225], l14))
  writeu32(mem, cur + 900, bxor(T[226], h14))
  writeu32(mem, cur + 904, bxor(T[227], l15))
  writeu32(mem, cur + 908, bxor(T[228], h15))
end
do
  local l0, h0 = R[5], R[6]
  local l1, h1 = R[7], R[8]
  local l2, h2 = R[37], R[38]
  local l3, h3 = R[39], R[40]
  local l4, h4 = R[69], R[70]
  local l5, h5 = R[71], R[72]
  local l6, h6 = R[101], R[102]
  local l7, h7 = R[103], R[104]
  local l8, h8 = R[133], R[134]
  local l9, h9 = R[135], R[136]
  local l10, h10 = R[165], R[166]
  local l11, h11 = R[167], R[168]
  local l12, h12 = R[197], R[198]
  local l13, h13 = R[199], R[200]
  local l14, h14 = R[229], R[230]
  local l15, h15 = R[231], R[232]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 16, bxor(T[5], l0))
  writeu32(mem, cur + 20, bxor(T[6], h0))
  writeu32(mem, cur + 24, bxor(T[7], l1))
  writeu32(mem, cur + 28, bxor(T[8], h1))
  writeu32(mem, cur + 144, bxor(T[37], l2))
  writeu32(mem, cur + 148, bxor(T[38], h2))
  writeu32(mem, cur + 152, bxor(T[39], l3))
  writeu32(mem, cur + 156, bxor(T[40], h3))
  writeu32(mem, cur + 272, bxor(T[69], l4))
  writeu32(mem, cur + 276, bxor(T[70], h4))
  writeu32(mem, cur + 280, bxor(T[71], l5))
  writeu32(mem, cur + 284, bxor(T[72], h5))
  writeu32(mem, cur + 400, bxor(T[101], l6))
  writeu32(mem, cur + 404, bxor(T[102], h6))
  writeu32(mem, cur + 408, bxor(T[103], l7))
  writeu32(mem, cur + 412, bxor(T[104], h7))
  writeu32(mem, cur + 528, bxor(T[133], l8))
  writeu32(mem, cur + 532, bxor(T[134], h8))
  writeu32(mem, cur + 536, bxor(T[135], l9))
  writeu32(mem, cur + 540, bxor(T[136], h9))
  writeu32(mem, cur + 656, bxor(T[165], l10))
  writeu32(mem, cur + 660, bxor(T[166], h10))
  writeu32(mem, cur + 664, bxor(T[167], l11))
  writeu32(mem, cur + 668, bxor(T[168], h11))
  writeu32(mem, cur + 784, bxor(T[197], l12))
  writeu32(mem, cur + 788, bxor(T[198], h12))
  writeu32(mem, cur + 792, bxor(T[199], l13))
  writeu32(mem, cur + 796, bxor(T[200], h13))
  writeu32(mem, cur + 912, bxor(T[229], l14))
  writeu32(mem, cur + 916, bxor(T[230], h14))
  writeu32(mem, cur + 920, bxor(T[231], l15))
  writeu32(mem, cur + 924, bxor(T[232], h15))
end
do
  local l0, h0 = R[9], R[10]
  local l1, h1 = R[11], R[12]
  local l2, h2 = R[41], R[42]
  local l3, h3 = R[43], R[44]
  local l4, h4 = R[73], R[74]
  local l5, h5 = R[75], R[76]
  local l6, h6 = R[105], R[106]
  local l7, h7 = R[107], R[108]
  local l8, h8 = R[137], R[138]
  local l9, h9 = R[139], R[140]
  local l10, h10 = R[169], R[170]
  local l11, h11 = R[171], R[172]
  local l12, h12 = R[201], R[202]
  local l13, h13 = R[203], R[204]
  local l14, h14 = R[233], R[234]
  local l15, h15 = R[235], R[236]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 32, bxor(T[9], l0))
  writeu32(mem, cur + 36, bxor(T[10], h0))
  writeu32(mem, cur + 40, bxor(T[11], l1))
  writeu32(mem, cur + 44, bxor(T[12], h1))
  writeu32(mem, cur + 160, bxor(T[41], l2))
  writeu32(mem, cur + 164, bxor(T[42], h2))
  writeu32(mem, cur + 168, bxor(T[43], l3))
  writeu32(mem, cur + 172, bxor(T[44], h3))
  writeu32(mem, cur + 288, bxor(T[73], l4))
  writeu32(mem, cur + 292, bxor(T[74], h4))
  writeu32(mem, cur + 296, bxor(T[75], l5))
  writeu32(mem, cur + 300, bxor(T[76], h5))
  writeu32(mem, cur + 416, bxor(T[105], l6))
  writeu32(mem, cur + 420, bxor(T[106], h6))
  writeu32(mem, cur + 424, bxor(T[107], l7))
  writeu32(mem, cur + 428, bxor(T[108], h7))
  writeu32(mem, cur + 544, bxor(T[137], l8))
  writeu32(mem, cur + 548, bxor(T[138], h8))
  writeu32(mem, cur + 552, bxor(T[139], l9))
  writeu32(mem, cur + 556, bxor(T[140], h9))
  writeu32(mem, cur + 672, bxor(T[169], l10))
  writeu32(mem, cur + 676, bxor(T[170], h10))
  writeu32(mem, cur + 680, bxor(T[171], l11))
  writeu32(mem, cur + 684, bxor(T[172], h11))
  writeu32(mem, cur + 800, bxor(T[201], l12))
  writeu32(mem, cur + 804, bxor(T[202], h12))
  writeu32(mem, cur + 808, bxor(T[203], l13))
  writeu32(mem, cur + 812, bxor(T[204], h13))
  writeu32(mem, cur + 928, bxor(T[233], l14))
  writeu32(mem, cur + 932, bxor(T[234], h14))
  writeu32(mem, cur + 936, bxor(T[235], l15))
  writeu32(mem, cur + 940, bxor(T[236], h15))
end
do
  local l0, h0 = R[13], R[14]
  local l1, h1 = R[15], R[16]
  local l2, h2 = R[45], R[46]
  local l3, h3 = R[47], R[48]
  local l4, h4 = R[77], R[78]
  local l5, h5 = R[79], R[80]
  local l6, h6 = R[109], R[110]
  local l7, h7 = R[111], R[112]
  local l8, h8 = R[141], R[142]
  local l9, h9 = R[143], R[144]
  local l10, h10 = R[173], R[174]
  local l11, h11 = R[175], R[176]
  local l12, h12 = R[205], R[206]
  local l13, h13 = R[207], R[208]
  local l14, h14 = R[237], R[238]
  local l15, h15 = R[239], R[240]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 48, bxor(T[13], l0))
  writeu32(mem, cur + 52, bxor(T[14], h0))
  writeu32(mem, cur + 56, bxor(T[15], l1))
  writeu32(mem, cur + 60, bxor(T[16], h1))
  writeu32(mem, cur + 176, bxor(T[45], l2))
  writeu32(mem, cur + 180, bxor(T[46], h2))
  writeu32(mem, cur + 184, bxor(T[47], l3))
  writeu32(mem, cur + 188, bxor(T[48], h3))
  writeu32(mem, cur + 304, bxor(T[77], l4))
  writeu32(mem, cur + 308, bxor(T[78], h4))
  writeu32(mem, cur + 312, bxor(T[79], l5))
  writeu32(mem, cur + 316, bxor(T[80], h5))
  writeu32(mem, cur + 432, bxor(T[109], l6))
  writeu32(mem, cur + 436, bxor(T[110], h6))
  writeu32(mem, cur + 440, bxor(T[111], l7))
  writeu32(mem, cur + 444, bxor(T[112], h7))
  writeu32(mem, cur + 560, bxor(T[141], l8))
  writeu32(mem, cur + 564, bxor(T[142], h8))
  writeu32(mem, cur + 568, bxor(T[143], l9))
  writeu32(mem, cur + 572, bxor(T[144], h9))
  writeu32(mem, cur + 688, bxor(T[173], l10))
  writeu32(mem, cur + 692, bxor(T[174], h10))
  writeu32(mem, cur + 696, bxor(T[175], l11))
  writeu32(mem, cur + 700, bxor(T[176], h11))
  writeu32(mem, cur + 816, bxor(T[205], l12))
  writeu32(mem, cur + 820, bxor(T[206], h12))
  writeu32(mem, cur + 824, bxor(T[207], l13))
  writeu32(mem, cur + 828, bxor(T[208], h13))
  writeu32(mem, cur + 944, bxor(T[237], l14))
  writeu32(mem, cur + 948, bxor(T[238], h14))
  writeu32(mem, cur + 952, bxor(T[239], l15))
  writeu32(mem, cur + 956, bxor(T[240], h15))
end
do
  local l0, h0 = R[17], R[18]
  local l1, h1 = R[19], R[20]
  local l2, h2 = R[49], R[50]
  local l3, h3 = R[51], R[52]
  local l4, h4 = R[81], R[82]
  local l5, h5 = R[83], R[84]
  local l6, h6 = R[113], R[114]
  local l7, h7 = R[115], R[116]
  local l8, h8 = R[145], R[146]
  local l9, h9 = R[147], R[148]
  local l10, h10 = R[177], R[178]
  local l11, h11 = R[179], R[180]
  local l12, h12 = R[209], R[210]
  local l13, h13 = R[211], R[212]
  local l14, h14 = R[241], R[242]
  local l15, h15 = R[243], R[244]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 64, bxor(T[17], l0))
  writeu32(mem, cur + 68, bxor(T[18], h0))
  writeu32(mem, cur + 72, bxor(T[19], l1))
  writeu32(mem, cur + 76, bxor(T[20], h1))
  writeu32(mem, cur + 192, bxor(T[49], l2))
  writeu32(mem, cur + 196, bxor(T[50], h2))
  writeu32(mem, cur + 200, bxor(T[51], l3))
  writeu32(mem, cur + 204, bxor(T[52], h3))
  writeu32(mem, cur + 320, bxor(T[81], l4))
  writeu32(mem, cur + 324, bxor(T[82], h4))
  writeu32(mem, cur + 328, bxor(T[83], l5))
  writeu32(mem, cur + 332, bxor(T[84], h5))
  writeu32(mem, cur + 448, bxor(T[113], l6))
  writeu32(mem, cur + 452, bxor(T[114], h6))
  writeu32(mem, cur + 456, bxor(T[115], l7))
  writeu32(mem, cur + 460, bxor(T[116], h7))
  writeu32(mem, cur + 576, bxor(T[145], l8))
  writeu32(mem, cur + 580, bxor(T[146], h8))
  writeu32(mem, cur + 584, bxor(T[147], l9))
  writeu32(mem, cur + 588, bxor(T[148], h9))
  writeu32(mem, cur + 704, bxor(T[177], l10))
  writeu32(mem, cur + 708, bxor(T[178], h10))
  writeu32(mem, cur + 712, bxor(T[179], l11))
  writeu32(mem, cur + 716, bxor(T[180], h11))
  writeu32(mem, cur + 832, bxor(T[209], l12))
  writeu32(mem, cur + 836, bxor(T[210], h12))
  writeu32(mem, cur + 840, bxor(T[211], l13))
  writeu32(mem, cur + 844, bxor(T[212], h13))
  writeu32(mem, cur + 960, bxor(T[241], l14))
  writeu32(mem, cur + 964, bxor(T[242], h14))
  writeu32(mem, cur + 968, bxor(T[243], l15))
  writeu32(mem, cur + 972, bxor(T[244], h15))
end
do
  local l0, h0 = R[21], R[22]
  local l1, h1 = R[23], R[24]
  local l2, h2 = R[53], R[54]
  local l3, h3 = R[55], R[56]
  local l4, h4 = R[85], R[86]
  local l5, h5 = R[87], R[88]
  local l6, h6 = R[117], R[118]
  local l7, h7 = R[119], R[120]
  local l8, h8 = R[149], R[150]
  local l9, h9 = R[151], R[152]
  local l10, h10 = R[181], R[182]
  local l11, h11 = R[183], R[184]
  local l12, h12 = R[213], R[214]
  local l13, h13 = R[215], R[216]
  local l14, h14 = R[245], R[246]
  local l15, h15 = R[247], R[248]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 80, bxor(T[21], l0))
  writeu32(mem, cur + 84, bxor(T[22], h0))
  writeu32(mem, cur + 88, bxor(T[23], l1))
  writeu32(mem, cur + 92, bxor(T[24], h1))
  writeu32(mem, cur + 208, bxor(T[53], l2))
  writeu32(mem, cur + 212, bxor(T[54], h2))
  writeu32(mem, cur + 216, bxor(T[55], l3))
  writeu32(mem, cur + 220, bxor(T[56], h3))
  writeu32(mem, cur + 336, bxor(T[85], l4))
  writeu32(mem, cur + 340, bxor(T[86], h4))
  writeu32(mem, cur + 344, bxor(T[87], l5))
  writeu32(mem, cur + 348, bxor(T[88], h5))
  writeu32(mem, cur + 464, bxor(T[117], l6))
  writeu32(mem, cur + 468, bxor(T[118], h6))
  writeu32(mem, cur + 472, bxor(T[119], l7))
  writeu32(mem, cur + 476, bxor(T[120], h7))
  writeu32(mem, cur + 592, bxor(T[149], l8))
  writeu32(mem, cur + 596, bxor(T[150], h8))
  writeu32(mem, cur + 600, bxor(T[151], l9))
  writeu32(mem, cur + 604, bxor(T[152], h9))
  writeu32(mem, cur + 720, bxor(T[181], l10))
  writeu32(mem, cur + 724, bxor(T[182], h10))
  writeu32(mem, cur + 728, bxor(T[183], l11))
  writeu32(mem, cur + 732, bxor(T[184], h11))
  writeu32(mem, cur + 848, bxor(T[213], l12))
  writeu32(mem, cur + 852, bxor(T[214], h12))
  writeu32(mem, cur + 856, bxor(T[215], l13))
  writeu32(mem, cur + 860, bxor(T[216], h13))
  writeu32(mem, cur + 976, bxor(T[245], l14))
  writeu32(mem, cur + 980, bxor(T[246], h14))
  writeu32(mem, cur + 984, bxor(T[247], l15))
  writeu32(mem, cur + 988, bxor(T[248], h15))
end
do
  local l0, h0 = R[25], R[26]
  local l1, h1 = R[27], R[28]
  local l2, h2 = R[57], R[58]
  local l3, h3 = R[59], R[60]
  local l4, h4 = R[89], R[90]
  local l5, h5 = R[91], R[92]
  local l6, h6 = R[121], R[122]
  local l7, h7 = R[123], R[124]
  local l8, h8 = R[153], R[154]
  local l9, h9 = R[155], R[156]
  local l10, h10 = R[185], R[186]
  local l11, h11 = R[187], R[188]
  local l12, h12 = R[217], R[218]
  local l13, h13 = R[219], R[220]
  local l14, h14 = R[249], R[250]
  local l15, h15 = R[251], R[252]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 96, bxor(T[25], l0))
  writeu32(mem, cur + 100, bxor(T[26], h0))
  writeu32(mem, cur + 104, bxor(T[27], l1))
  writeu32(mem, cur + 108, bxor(T[28], h1))
  writeu32(mem, cur + 224, bxor(T[57], l2))
  writeu32(mem, cur + 228, bxor(T[58], h2))
  writeu32(mem, cur + 232, bxor(T[59], l3))
  writeu32(mem, cur + 236, bxor(T[60], h3))
  writeu32(mem, cur + 352, bxor(T[89], l4))
  writeu32(mem, cur + 356, bxor(T[90], h4))
  writeu32(mem, cur + 360, bxor(T[91], l5))
  writeu32(mem, cur + 364, bxor(T[92], h5))
  writeu32(mem, cur + 480, bxor(T[121], l6))
  writeu32(mem, cur + 484, bxor(T[122], h6))
  writeu32(mem, cur + 488, bxor(T[123], l7))
  writeu32(mem, cur + 492, bxor(T[124], h7))
  writeu32(mem, cur + 608, bxor(T[153], l8))
  writeu32(mem, cur + 612, bxor(T[154], h8))
  writeu32(mem, cur + 616, bxor(T[155], l9))
  writeu32(mem, cur + 620, bxor(T[156], h9))
  writeu32(mem, cur + 736, bxor(T[185], l10))
  writeu32(mem, cur + 740, bxor(T[186], h10))
  writeu32(mem, cur + 744, bxor(T[187], l11))
  writeu32(mem, cur + 748, bxor(T[188], h11))
  writeu32(mem, cur + 864, bxor(T[217], l12))
  writeu32(mem, cur + 868, bxor(T[218], h12))
  writeu32(mem, cur + 872, bxor(T[219], l13))
  writeu32(mem, cur + 876, bxor(T[220], h13))
  writeu32(mem, cur + 992, bxor(T[249], l14))
  writeu32(mem, cur + 996, bxor(T[250], h14))
  writeu32(mem, cur + 1000, bxor(T[251], l15))
  writeu32(mem, cur + 1004, bxor(T[252], h15))
end
do
  local l0, h0 = R[29], R[30]
  local l1, h1 = R[31], R[32]
  local l2, h2 = R[61], R[62]
  local l3, h3 = R[63], R[64]
  local l4, h4 = R[93], R[94]
  local l5, h5 = R[95], R[96]
  local l6, h6 = R[125], R[126]
  local l7, h7 = R[127], R[128]
  local l8, h8 = R[157], R[158]
  local l9, h9 = R[159], R[160]
  local l10, h10 = R[189], R[190]
  local l11, h11 = R[191], R[192]
  local l12, h12 = R[221], R[222]
  local l13, h13 = R[223], R[224]
  local l14, h14 = R[253], R[254]
  local l15, h15 = R[255], R[256]
  do
    local x0_0_ = l0 % 65536
    local x1_0_ = (l0 - x0_0_) / 65536
    local y0_0_ = l4 % 65536
    local y1_0_ = (l4 - y0_0_) / 65536
    local p_0_ = x0_0_ * y0_0_
    local q_0_ = x0_0_ * y1_0_ + x1_0_ * y0_0_
    local lo_0_ = (p_0_ % W) + (q_0_ % 65536) * 65536
    local hi_0_ = ((q_0_ - q_0_ % 65536) / 65536 + x1_0_ * y1_0_) % W
    local s_0_ = l0 + l4 + 2 * lo_0_
    local sl_0_ = s_0_ % W
    l0 = sl_0_
    h0 = (h0 + h4 + 2 * hi_0_ + (s_0_ - sl_0_) / W) % W
    local u_0 = l12; local v_0 = h12
    l12 = bxor(v_0, h0); h12 = bxor(u_0, l0)
    local x0_c0_ = l8 % 65536
    local x1_c0_ = (l8 - x0_c0_) / 65536
    local y0_c0_ = l12 % 65536
    local y1_c0_ = (l12 - y0_c0_) / 65536
    local p_c0_ = x0_c0_ * y0_c0_
    local q_c0_ = x0_c0_ * y1_c0_ + x1_c0_ * y0_c0_
    local lo_c0_ = (p_c0_ % W) + (q_c0_ % 65536) * 65536
    local hi_c0_ = ((q_c0_ - q_c0_ % 65536) / 65536 + x1_c0_ * y1_c0_) % W
    local s_c0_ = l8 + l12 + 2 * lo_c0_
    local sl_c0_ = s_c0_ % W
    l8 = sl_c0_
    h8 = (h8 + h12 + 2 * hi_c0_ + (s_c0_ - sl_c0_) / W) % W
    local w_0 = bxor(l4, l8); local z_0 = bxor(h4, h8)
    l4 = bor(rshift(w_0, 24), lshift(z_0, 8))
    h4 = bor(rshift(z_0, 24), lshift(w_0, 8))
    local x0_a0_ = l0 % 65536
    local x1_a0_ = (l0 - x0_a0_) / 65536
    local y0_a0_ = l4 % 65536
    local y1_a0_ = (l4 - y0_a0_) / 65536
    local p_a0_ = x0_a0_ * y0_a0_
    local q_a0_ = x0_a0_ * y1_a0_ + x1_a0_ * y0_a0_
    local lo_a0_ = (p_a0_ % W) + (q_a0_ % 65536) * 65536
    local hi_a0_ = ((q_a0_ - q_a0_ % 65536) / 65536 + x1_a0_ * y1_a0_) % W
    local s_a0_ = l0 + l4 + 2 * lo_a0_
    local sl_a0_ = s_a0_ % W
    l0 = sl_a0_
    h0 = (h0 + h4 + 2 * hi_a0_ + (s_a0_ - sl_a0_) / W) % W
    local e_0 = bxor(l12, l0); local f_0 = bxor(h12, h0)
    l12 = bor(rshift(e_0, 16), lshift(f_0, 16))
    h12 = bor(rshift(f_0, 16), lshift(e_0, 16))
    local x0_b0_ = l8 % 65536
    local x1_b0_ = (l8 - x0_b0_) / 65536
    local y0_b0_ = l12 % 65536
    local y1_b0_ = (l12 - y0_b0_) / 65536
    local p_b0_ = x0_b0_ * y0_b0_
    local q_b0_ = x0_b0_ * y1_b0_ + x1_b0_ * y0_b0_
    local lo_b0_ = (p_b0_ % W) + (q_b0_ % 65536) * 65536
    local hi_b0_ = ((q_b0_ - q_b0_ % 65536) / 65536 + x1_b0_ * y1_b0_) % W
    local s_b0_ = l8 + l12 + 2 * lo_b0_
    local sl_b0_ = s_b0_ % W
    l8 = sl_b0_
    h8 = (h8 + h12 + 2 * hi_b0_ + (s_b0_ - sl_b0_) / W) % W
    local g_0 = bxor(l4, l8); local k_0 = bxor(h4, h8)
    l4 = bor(lshift(g_0, 1), rshift(k_0, 31))
    h4 = bor(lshift(k_0, 1), rshift(g_0, 31))
  end
  do
    local x0_1_ = l1 % 65536
    local x1_1_ = (l1 - x0_1_) / 65536
    local y0_1_ = l5 % 65536
    local y1_1_ = (l5 - y0_1_) / 65536
    local p_1_ = x0_1_ * y0_1_
    local q_1_ = x0_1_ * y1_1_ + x1_1_ * y0_1_
    local lo_1_ = (p_1_ % W) + (q_1_ % 65536) * 65536
    local hi_1_ = ((q_1_ - q_1_ % 65536) / 65536 + x1_1_ * y1_1_) % W
    local s_1_ = l1 + l5 + 2 * lo_1_
    local sl_1_ = s_1_ % W
    l1 = sl_1_
    h1 = (h1 + h5 + 2 * hi_1_ + (s_1_ - sl_1_) / W) % W
    local u_1 = l13; local v_1 = h13
    l13 = bxor(v_1, h1); h13 = bxor(u_1, l1)
    local x0_c1_ = l9 % 65536
    local x1_c1_ = (l9 - x0_c1_) / 65536
    local y0_c1_ = l13 % 65536
    local y1_c1_ = (l13 - y0_c1_) / 65536
    local p_c1_ = x0_c1_ * y0_c1_
    local q_c1_ = x0_c1_ * y1_c1_ + x1_c1_ * y0_c1_
    local lo_c1_ = (p_c1_ % W) + (q_c1_ % 65536) * 65536
    local hi_c1_ = ((q_c1_ - q_c1_ % 65536) / 65536 + x1_c1_ * y1_c1_) % W
    local s_c1_ = l9 + l13 + 2 * lo_c1_
    local sl_c1_ = s_c1_ % W
    l9 = sl_c1_
    h9 = (h9 + h13 + 2 * hi_c1_ + (s_c1_ - sl_c1_) / W) % W
    local w_1 = bxor(l5, l9); local z_1 = bxor(h5, h9)
    l5 = bor(rshift(w_1, 24), lshift(z_1, 8))
    h5 = bor(rshift(z_1, 24), lshift(w_1, 8))
    local x0_a1_ = l1 % 65536
    local x1_a1_ = (l1 - x0_a1_) / 65536
    local y0_a1_ = l5 % 65536
    local y1_a1_ = (l5 - y0_a1_) / 65536
    local p_a1_ = x0_a1_ * y0_a1_
    local q_a1_ = x0_a1_ * y1_a1_ + x1_a1_ * y0_a1_
    local lo_a1_ = (p_a1_ % W) + (q_a1_ % 65536) * 65536
    local hi_a1_ = ((q_a1_ - q_a1_ % 65536) / 65536 + x1_a1_ * y1_a1_) % W
    local s_a1_ = l1 + l5 + 2 * lo_a1_
    local sl_a1_ = s_a1_ % W
    l1 = sl_a1_
    h1 = (h1 + h5 + 2 * hi_a1_ + (s_a1_ - sl_a1_) / W) % W
    local e_1 = bxor(l13, l1); local f_1 = bxor(h13, h1)
    l13 = bor(rshift(e_1, 16), lshift(f_1, 16))
    h13 = bor(rshift(f_1, 16), lshift(e_1, 16))
    local x0_b1_ = l9 % 65536
    local x1_b1_ = (l9 - x0_b1_) / 65536
    local y0_b1_ = l13 % 65536
    local y1_b1_ = (l13 - y0_b1_) / 65536
    local p_b1_ = x0_b1_ * y0_b1_
    local q_b1_ = x0_b1_ * y1_b1_ + x1_b1_ * y0_b1_
    local lo_b1_ = (p_b1_ % W) + (q_b1_ % 65536) * 65536
    local hi_b1_ = ((q_b1_ - q_b1_ % 65536) / 65536 + x1_b1_ * y1_b1_) % W
    local s_b1_ = l9 + l13 + 2 * lo_b1_
    local sl_b1_ = s_b1_ % W
    l9 = sl_b1_
    h9 = (h9 + h13 + 2 * hi_b1_ + (s_b1_ - sl_b1_) / W) % W
    local g_1 = bxor(l5, l9); local k_1 = bxor(h5, h9)
    l5 = bor(lshift(g_1, 1), rshift(k_1, 31))
    h5 = bor(lshift(k_1, 1), rshift(g_1, 31))
  end
  do
    local x0_2_ = l2 % 65536
    local x1_2_ = (l2 - x0_2_) / 65536
    local y0_2_ = l6 % 65536
    local y1_2_ = (l6 - y0_2_) / 65536
    local p_2_ = x0_2_ * y0_2_
    local q_2_ = x0_2_ * y1_2_ + x1_2_ * y0_2_
    local lo_2_ = (p_2_ % W) + (q_2_ % 65536) * 65536
    local hi_2_ = ((q_2_ - q_2_ % 65536) / 65536 + x1_2_ * y1_2_) % W
    local s_2_ = l2 + l6 + 2 * lo_2_
    local sl_2_ = s_2_ % W
    l2 = sl_2_
    h2 = (h2 + h6 + 2 * hi_2_ + (s_2_ - sl_2_) / W) % W
    local u_2 = l14; local v_2 = h14
    l14 = bxor(v_2, h2); h14 = bxor(u_2, l2)
    local x0_c2_ = l10 % 65536
    local x1_c2_ = (l10 - x0_c2_) / 65536
    local y0_c2_ = l14 % 65536
    local y1_c2_ = (l14 - y0_c2_) / 65536
    local p_c2_ = x0_c2_ * y0_c2_
    local q_c2_ = x0_c2_ * y1_c2_ + x1_c2_ * y0_c2_
    local lo_c2_ = (p_c2_ % W) + (q_c2_ % 65536) * 65536
    local hi_c2_ = ((q_c2_ - q_c2_ % 65536) / 65536 + x1_c2_ * y1_c2_) % W
    local s_c2_ = l10 + l14 + 2 * lo_c2_
    local sl_c2_ = s_c2_ % W
    l10 = sl_c2_
    h10 = (h10 + h14 + 2 * hi_c2_ + (s_c2_ - sl_c2_) / W) % W
    local w_2 = bxor(l6, l10); local z_2 = bxor(h6, h10)
    l6 = bor(rshift(w_2, 24), lshift(z_2, 8))
    h6 = bor(rshift(z_2, 24), lshift(w_2, 8))
    local x0_a2_ = l2 % 65536
    local x1_a2_ = (l2 - x0_a2_) / 65536
    local y0_a2_ = l6 % 65536
    local y1_a2_ = (l6 - y0_a2_) / 65536
    local p_a2_ = x0_a2_ * y0_a2_
    local q_a2_ = x0_a2_ * y1_a2_ + x1_a2_ * y0_a2_
    local lo_a2_ = (p_a2_ % W) + (q_a2_ % 65536) * 65536
    local hi_a2_ = ((q_a2_ - q_a2_ % 65536) / 65536 + x1_a2_ * y1_a2_) % W
    local s_a2_ = l2 + l6 + 2 * lo_a2_
    local sl_a2_ = s_a2_ % W
    l2 = sl_a2_
    h2 = (h2 + h6 + 2 * hi_a2_ + (s_a2_ - sl_a2_) / W) % W
    local e_2 = bxor(l14, l2); local f_2 = bxor(h14, h2)
    l14 = bor(rshift(e_2, 16), lshift(f_2, 16))
    h14 = bor(rshift(f_2, 16), lshift(e_2, 16))
    local x0_b2_ = l10 % 65536
    local x1_b2_ = (l10 - x0_b2_) / 65536
    local y0_b2_ = l14 % 65536
    local y1_b2_ = (l14 - y0_b2_) / 65536
    local p_b2_ = x0_b2_ * y0_b2_
    local q_b2_ = x0_b2_ * y1_b2_ + x1_b2_ * y0_b2_
    local lo_b2_ = (p_b2_ % W) + (q_b2_ % 65536) * 65536
    local hi_b2_ = ((q_b2_ - q_b2_ % 65536) / 65536 + x1_b2_ * y1_b2_) % W
    local s_b2_ = l10 + l14 + 2 * lo_b2_
    local sl_b2_ = s_b2_ % W
    l10 = sl_b2_
    h10 = (h10 + h14 + 2 * hi_b2_ + (s_b2_ - sl_b2_) / W) % W
    local g_2 = bxor(l6, l10); local k_2 = bxor(h6, h10)
    l6 = bor(lshift(g_2, 1), rshift(k_2, 31))
    h6 = bor(lshift(k_2, 1), rshift(g_2, 31))
  end
  do
    local x0_3_ = l3 % 65536
    local x1_3_ = (l3 - x0_3_) / 65536
    local y0_3_ = l7 % 65536
    local y1_3_ = (l7 - y0_3_) / 65536
    local p_3_ = x0_3_ * y0_3_
    local q_3_ = x0_3_ * y1_3_ + x1_3_ * y0_3_
    local lo_3_ = (p_3_ % W) + (q_3_ % 65536) * 65536
    local hi_3_ = ((q_3_ - q_3_ % 65536) / 65536 + x1_3_ * y1_3_) % W
    local s_3_ = l3 + l7 + 2 * lo_3_
    local sl_3_ = s_3_ % W
    l3 = sl_3_
    h3 = (h3 + h7 + 2 * hi_3_ + (s_3_ - sl_3_) / W) % W
    local u_3 = l15; local v_3 = h15
    l15 = bxor(v_3, h3); h15 = bxor(u_3, l3)
    local x0_c3_ = l11 % 65536
    local x1_c3_ = (l11 - x0_c3_) / 65536
    local y0_c3_ = l15 % 65536
    local y1_c3_ = (l15 - y0_c3_) / 65536
    local p_c3_ = x0_c3_ * y0_c3_
    local q_c3_ = x0_c3_ * y1_c3_ + x1_c3_ * y0_c3_
    local lo_c3_ = (p_c3_ % W) + (q_c3_ % 65536) * 65536
    local hi_c3_ = ((q_c3_ - q_c3_ % 65536) / 65536 + x1_c3_ * y1_c3_) % W
    local s_c3_ = l11 + l15 + 2 * lo_c3_
    local sl_c3_ = s_c3_ % W
    l11 = sl_c3_
    h11 = (h11 + h15 + 2 * hi_c3_ + (s_c3_ - sl_c3_) / W) % W
    local w_3 = bxor(l7, l11); local z_3 = bxor(h7, h11)
    l7 = bor(rshift(w_3, 24), lshift(z_3, 8))
    h7 = bor(rshift(z_3, 24), lshift(w_3, 8))
    local x0_a3_ = l3 % 65536
    local x1_a3_ = (l3 - x0_a3_) / 65536
    local y0_a3_ = l7 % 65536
    local y1_a3_ = (l7 - y0_a3_) / 65536
    local p_a3_ = x0_a3_ * y0_a3_
    local q_a3_ = x0_a3_ * y1_a3_ + x1_a3_ * y0_a3_
    local lo_a3_ = (p_a3_ % W) + (q_a3_ % 65536) * 65536
    local hi_a3_ = ((q_a3_ - q_a3_ % 65536) / 65536 + x1_a3_ * y1_a3_) % W
    local s_a3_ = l3 + l7 + 2 * lo_a3_
    local sl_a3_ = s_a3_ % W
    l3 = sl_a3_
    h3 = (h3 + h7 + 2 * hi_a3_ + (s_a3_ - sl_a3_) / W) % W
    local e_3 = bxor(l15, l3); local f_3 = bxor(h15, h3)
    l15 = bor(rshift(e_3, 16), lshift(f_3, 16))
    h15 = bor(rshift(f_3, 16), lshift(e_3, 16))
    local x0_b3_ = l11 % 65536
    local x1_b3_ = (l11 - x0_b3_) / 65536
    local y0_b3_ = l15 % 65536
    local y1_b3_ = (l15 - y0_b3_) / 65536
    local p_b3_ = x0_b3_ * y0_b3_
    local q_b3_ = x0_b3_ * y1_b3_ + x1_b3_ * y0_b3_
    local lo_b3_ = (p_b3_ % W) + (q_b3_ % 65536) * 65536
    local hi_b3_ = ((q_b3_ - q_b3_ % 65536) / 65536 + x1_b3_ * y1_b3_) % W
    local s_b3_ = l11 + l15 + 2 * lo_b3_
    local sl_b3_ = s_b3_ % W
    l11 = sl_b3_
    h11 = (h11 + h15 + 2 * hi_b3_ + (s_b3_ - sl_b3_) / W) % W
    local g_3 = bxor(l7, l11); local k_3 = bxor(h7, h11)
    l7 = bor(lshift(g_3, 1), rshift(k_3, 31))
    h7 = bor(lshift(k_3, 1), rshift(g_3, 31))
  end
  do
    local x0_4_ = l0 % 65536
    local x1_4_ = (l0 - x0_4_) / 65536
    local y0_4_ = l5 % 65536
    local y1_4_ = (l5 - y0_4_) / 65536
    local p_4_ = x0_4_ * y0_4_
    local q_4_ = x0_4_ * y1_4_ + x1_4_ * y0_4_
    local lo_4_ = (p_4_ % W) + (q_4_ % 65536) * 65536
    local hi_4_ = ((q_4_ - q_4_ % 65536) / 65536 + x1_4_ * y1_4_) % W
    local s_4_ = l0 + l5 + 2 * lo_4_
    local sl_4_ = s_4_ % W
    l0 = sl_4_
    h0 = (h0 + h5 + 2 * hi_4_ + (s_4_ - sl_4_) / W) % W
    local u_4 = l15; local v_4 = h15
    l15 = bxor(v_4, h0); h15 = bxor(u_4, l0)
    local x0_c4_ = l10 % 65536
    local x1_c4_ = (l10 - x0_c4_) / 65536
    local y0_c4_ = l15 % 65536
    local y1_c4_ = (l15 - y0_c4_) / 65536
    local p_c4_ = x0_c4_ * y0_c4_
    local q_c4_ = x0_c4_ * y1_c4_ + x1_c4_ * y0_c4_
    local lo_c4_ = (p_c4_ % W) + (q_c4_ % 65536) * 65536
    local hi_c4_ = ((q_c4_ - q_c4_ % 65536) / 65536 + x1_c4_ * y1_c4_) % W
    local s_c4_ = l10 + l15 + 2 * lo_c4_
    local sl_c4_ = s_c4_ % W
    l10 = sl_c4_
    h10 = (h10 + h15 + 2 * hi_c4_ + (s_c4_ - sl_c4_) / W) % W
    local w_4 = bxor(l5, l10); local z_4 = bxor(h5, h10)
    l5 = bor(rshift(w_4, 24), lshift(z_4, 8))
    h5 = bor(rshift(z_4, 24), lshift(w_4, 8))
    local x0_a4_ = l0 % 65536
    local x1_a4_ = (l0 - x0_a4_) / 65536
    local y0_a4_ = l5 % 65536
    local y1_a4_ = (l5 - y0_a4_) / 65536
    local p_a4_ = x0_a4_ * y0_a4_
    local q_a4_ = x0_a4_ * y1_a4_ + x1_a4_ * y0_a4_
    local lo_a4_ = (p_a4_ % W) + (q_a4_ % 65536) * 65536
    local hi_a4_ = ((q_a4_ - q_a4_ % 65536) / 65536 + x1_a4_ * y1_a4_) % W
    local s_a4_ = l0 + l5 + 2 * lo_a4_
    local sl_a4_ = s_a4_ % W
    l0 = sl_a4_
    h0 = (h0 + h5 + 2 * hi_a4_ + (s_a4_ - sl_a4_) / W) % W
    local e_4 = bxor(l15, l0); local f_4 = bxor(h15, h0)
    l15 = bor(rshift(e_4, 16), lshift(f_4, 16))
    h15 = bor(rshift(f_4, 16), lshift(e_4, 16))
    local x0_b4_ = l10 % 65536
    local x1_b4_ = (l10 - x0_b4_) / 65536
    local y0_b4_ = l15 % 65536
    local y1_b4_ = (l15 - y0_b4_) / 65536
    local p_b4_ = x0_b4_ * y0_b4_
    local q_b4_ = x0_b4_ * y1_b4_ + x1_b4_ * y0_b4_
    local lo_b4_ = (p_b4_ % W) + (q_b4_ % 65536) * 65536
    local hi_b4_ = ((q_b4_ - q_b4_ % 65536) / 65536 + x1_b4_ * y1_b4_) % W
    local s_b4_ = l10 + l15 + 2 * lo_b4_
    local sl_b4_ = s_b4_ % W
    l10 = sl_b4_
    h10 = (h10 + h15 + 2 * hi_b4_ + (s_b4_ - sl_b4_) / W) % W
    local g_4 = bxor(l5, l10); local k_4 = bxor(h5, h10)
    l5 = bor(lshift(g_4, 1), rshift(k_4, 31))
    h5 = bor(lshift(k_4, 1), rshift(g_4, 31))
  end
  do
    local x0_5_ = l1 % 65536
    local x1_5_ = (l1 - x0_5_) / 65536
    local y0_5_ = l6 % 65536
    local y1_5_ = (l6 - y0_5_) / 65536
    local p_5_ = x0_5_ * y0_5_
    local q_5_ = x0_5_ * y1_5_ + x1_5_ * y0_5_
    local lo_5_ = (p_5_ % W) + (q_5_ % 65536) * 65536
    local hi_5_ = ((q_5_ - q_5_ % 65536) / 65536 + x1_5_ * y1_5_) % W
    local s_5_ = l1 + l6 + 2 * lo_5_
    local sl_5_ = s_5_ % W
    l1 = sl_5_
    h1 = (h1 + h6 + 2 * hi_5_ + (s_5_ - sl_5_) / W) % W
    local u_5 = l12; local v_5 = h12
    l12 = bxor(v_5, h1); h12 = bxor(u_5, l1)
    local x0_c5_ = l11 % 65536
    local x1_c5_ = (l11 - x0_c5_) / 65536
    local y0_c5_ = l12 % 65536
    local y1_c5_ = (l12 - y0_c5_) / 65536
    local p_c5_ = x0_c5_ * y0_c5_
    local q_c5_ = x0_c5_ * y1_c5_ + x1_c5_ * y0_c5_
    local lo_c5_ = (p_c5_ % W) + (q_c5_ % 65536) * 65536
    local hi_c5_ = ((q_c5_ - q_c5_ % 65536) / 65536 + x1_c5_ * y1_c5_) % W
    local s_c5_ = l11 + l12 + 2 * lo_c5_
    local sl_c5_ = s_c5_ % W
    l11 = sl_c5_
    h11 = (h11 + h12 + 2 * hi_c5_ + (s_c5_ - sl_c5_) / W) % W
    local w_5 = bxor(l6, l11); local z_5 = bxor(h6, h11)
    l6 = bor(rshift(w_5, 24), lshift(z_5, 8))
    h6 = bor(rshift(z_5, 24), lshift(w_5, 8))
    local x0_a5_ = l1 % 65536
    local x1_a5_ = (l1 - x0_a5_) / 65536
    local y0_a5_ = l6 % 65536
    local y1_a5_ = (l6 - y0_a5_) / 65536
    local p_a5_ = x0_a5_ * y0_a5_
    local q_a5_ = x0_a5_ * y1_a5_ + x1_a5_ * y0_a5_
    local lo_a5_ = (p_a5_ % W) + (q_a5_ % 65536) * 65536
    local hi_a5_ = ((q_a5_ - q_a5_ % 65536) / 65536 + x1_a5_ * y1_a5_) % W
    local s_a5_ = l1 + l6 + 2 * lo_a5_
    local sl_a5_ = s_a5_ % W
    l1 = sl_a5_
    h1 = (h1 + h6 + 2 * hi_a5_ + (s_a5_ - sl_a5_) / W) % W
    local e_5 = bxor(l12, l1); local f_5 = bxor(h12, h1)
    l12 = bor(rshift(e_5, 16), lshift(f_5, 16))
    h12 = bor(rshift(f_5, 16), lshift(e_5, 16))
    local x0_b5_ = l11 % 65536
    local x1_b5_ = (l11 - x0_b5_) / 65536
    local y0_b5_ = l12 % 65536
    local y1_b5_ = (l12 - y0_b5_) / 65536
    local p_b5_ = x0_b5_ * y0_b5_
    local q_b5_ = x0_b5_ * y1_b5_ + x1_b5_ * y0_b5_
    local lo_b5_ = (p_b5_ % W) + (q_b5_ % 65536) * 65536
    local hi_b5_ = ((q_b5_ - q_b5_ % 65536) / 65536 + x1_b5_ * y1_b5_) % W
    local s_b5_ = l11 + l12 + 2 * lo_b5_
    local sl_b5_ = s_b5_ % W
    l11 = sl_b5_
    h11 = (h11 + h12 + 2 * hi_b5_ + (s_b5_ - sl_b5_) / W) % W
    local g_5 = bxor(l6, l11); local k_5 = bxor(h6, h11)
    l6 = bor(lshift(g_5, 1), rshift(k_5, 31))
    h6 = bor(lshift(k_5, 1), rshift(g_5, 31))
  end
  do
    local x0_6_ = l2 % 65536
    local x1_6_ = (l2 - x0_6_) / 65536
    local y0_6_ = l7 % 65536
    local y1_6_ = (l7 - y0_6_) / 65536
    local p_6_ = x0_6_ * y0_6_
    local q_6_ = x0_6_ * y1_6_ + x1_6_ * y0_6_
    local lo_6_ = (p_6_ % W) + (q_6_ % 65536) * 65536
    local hi_6_ = ((q_6_ - q_6_ % 65536) / 65536 + x1_6_ * y1_6_) % W
    local s_6_ = l2 + l7 + 2 * lo_6_
    local sl_6_ = s_6_ % W
    l2 = sl_6_
    h2 = (h2 + h7 + 2 * hi_6_ + (s_6_ - sl_6_) / W) % W
    local u_6 = l13; local v_6 = h13
    l13 = bxor(v_6, h2); h13 = bxor(u_6, l2)
    local x0_c6_ = l8 % 65536
    local x1_c6_ = (l8 - x0_c6_) / 65536
    local y0_c6_ = l13 % 65536
    local y1_c6_ = (l13 - y0_c6_) / 65536
    local p_c6_ = x0_c6_ * y0_c6_
    local q_c6_ = x0_c6_ * y1_c6_ + x1_c6_ * y0_c6_
    local lo_c6_ = (p_c6_ % W) + (q_c6_ % 65536) * 65536
    local hi_c6_ = ((q_c6_ - q_c6_ % 65536) / 65536 + x1_c6_ * y1_c6_) % W
    local s_c6_ = l8 + l13 + 2 * lo_c6_
    local sl_c6_ = s_c6_ % W
    l8 = sl_c6_
    h8 = (h8 + h13 + 2 * hi_c6_ + (s_c6_ - sl_c6_) / W) % W
    local w_6 = bxor(l7, l8); local z_6 = bxor(h7, h8)
    l7 = bor(rshift(w_6, 24), lshift(z_6, 8))
    h7 = bor(rshift(z_6, 24), lshift(w_6, 8))
    local x0_a6_ = l2 % 65536
    local x1_a6_ = (l2 - x0_a6_) / 65536
    local y0_a6_ = l7 % 65536
    local y1_a6_ = (l7 - y0_a6_) / 65536
    local p_a6_ = x0_a6_ * y0_a6_
    local q_a6_ = x0_a6_ * y1_a6_ + x1_a6_ * y0_a6_
    local lo_a6_ = (p_a6_ % W) + (q_a6_ % 65536) * 65536
    local hi_a6_ = ((q_a6_ - q_a6_ % 65536) / 65536 + x1_a6_ * y1_a6_) % W
    local s_a6_ = l2 + l7 + 2 * lo_a6_
    local sl_a6_ = s_a6_ % W
    l2 = sl_a6_
    h2 = (h2 + h7 + 2 * hi_a6_ + (s_a6_ - sl_a6_) / W) % W
    local e_6 = bxor(l13, l2); local f_6 = bxor(h13, h2)
    l13 = bor(rshift(e_6, 16), lshift(f_6, 16))
    h13 = bor(rshift(f_6, 16), lshift(e_6, 16))
    local x0_b6_ = l8 % 65536
    local x1_b6_ = (l8 - x0_b6_) / 65536
    local y0_b6_ = l13 % 65536
    local y1_b6_ = (l13 - y0_b6_) / 65536
    local p_b6_ = x0_b6_ * y0_b6_
    local q_b6_ = x0_b6_ * y1_b6_ + x1_b6_ * y0_b6_
    local lo_b6_ = (p_b6_ % W) + (q_b6_ % 65536) * 65536
    local hi_b6_ = ((q_b6_ - q_b6_ % 65536) / 65536 + x1_b6_ * y1_b6_) % W
    local s_b6_ = l8 + l13 + 2 * lo_b6_
    local sl_b6_ = s_b6_ % W
    l8 = sl_b6_
    h8 = (h8 + h13 + 2 * hi_b6_ + (s_b6_ - sl_b6_) / W) % W
    local g_6 = bxor(l7, l8); local k_6 = bxor(h7, h8)
    l7 = bor(lshift(g_6, 1), rshift(k_6, 31))
    h7 = bor(lshift(k_6, 1), rshift(g_6, 31))
  end
  do
    local x0_7_ = l3 % 65536
    local x1_7_ = (l3 - x0_7_) / 65536
    local y0_7_ = l4 % 65536
    local y1_7_ = (l4 - y0_7_) / 65536
    local p_7_ = x0_7_ * y0_7_
    local q_7_ = x0_7_ * y1_7_ + x1_7_ * y0_7_
    local lo_7_ = (p_7_ % W) + (q_7_ % 65536) * 65536
    local hi_7_ = ((q_7_ - q_7_ % 65536) / 65536 + x1_7_ * y1_7_) % W
    local s_7_ = l3 + l4 + 2 * lo_7_
    local sl_7_ = s_7_ % W
    l3 = sl_7_
    h3 = (h3 + h4 + 2 * hi_7_ + (s_7_ - sl_7_) / W) % W
    local u_7 = l14; local v_7 = h14
    l14 = bxor(v_7, h3); h14 = bxor(u_7, l3)
    local x0_c7_ = l9 % 65536
    local x1_c7_ = (l9 - x0_c7_) / 65536
    local y0_c7_ = l14 % 65536
    local y1_c7_ = (l14 - y0_c7_) / 65536
    local p_c7_ = x0_c7_ * y0_c7_
    local q_c7_ = x0_c7_ * y1_c7_ + x1_c7_ * y0_c7_
    local lo_c7_ = (p_c7_ % W) + (q_c7_ % 65536) * 65536
    local hi_c7_ = ((q_c7_ - q_c7_ % 65536) / 65536 + x1_c7_ * y1_c7_) % W
    local s_c7_ = l9 + l14 + 2 * lo_c7_
    local sl_c7_ = s_c7_ % W
    l9 = sl_c7_
    h9 = (h9 + h14 + 2 * hi_c7_ + (s_c7_ - sl_c7_) / W) % W
    local w_7 = bxor(l4, l9); local z_7 = bxor(h4, h9)
    l4 = bor(rshift(w_7, 24), lshift(z_7, 8))
    h4 = bor(rshift(z_7, 24), lshift(w_7, 8))
    local x0_a7_ = l3 % 65536
    local x1_a7_ = (l3 - x0_a7_) / 65536
    local y0_a7_ = l4 % 65536
    local y1_a7_ = (l4 - y0_a7_) / 65536
    local p_a7_ = x0_a7_ * y0_a7_
    local q_a7_ = x0_a7_ * y1_a7_ + x1_a7_ * y0_a7_
    local lo_a7_ = (p_a7_ % W) + (q_a7_ % 65536) * 65536
    local hi_a7_ = ((q_a7_ - q_a7_ % 65536) / 65536 + x1_a7_ * y1_a7_) % W
    local s_a7_ = l3 + l4 + 2 * lo_a7_
    local sl_a7_ = s_a7_ % W
    l3 = sl_a7_
    h3 = (h3 + h4 + 2 * hi_a7_ + (s_a7_ - sl_a7_) / W) % W
    local e_7 = bxor(l14, l3); local f_7 = bxor(h14, h3)
    l14 = bor(rshift(e_7, 16), lshift(f_7, 16))
    h14 = bor(rshift(f_7, 16), lshift(e_7, 16))
    local x0_b7_ = l9 % 65536
    local x1_b7_ = (l9 - x0_b7_) / 65536
    local y0_b7_ = l14 % 65536
    local y1_b7_ = (l14 - y0_b7_) / 65536
    local p_b7_ = x0_b7_ * y0_b7_
    local q_b7_ = x0_b7_ * y1_b7_ + x1_b7_ * y0_b7_
    local lo_b7_ = (p_b7_ % W) + (q_b7_ % 65536) * 65536
    local hi_b7_ = ((q_b7_ - q_b7_ % 65536) / 65536 + x1_b7_ * y1_b7_) % W
    local s_b7_ = l9 + l14 + 2 * lo_b7_
    local sl_b7_ = s_b7_ % W
    l9 = sl_b7_
    h9 = (h9 + h14 + 2 * hi_b7_ + (s_b7_ - sl_b7_) / W) % W
    local g_7 = bxor(l4, l9); local k_7 = bxor(h4, h9)
    l4 = bor(lshift(g_7, 1), rshift(k_7, 31))
    h4 = bor(lshift(k_7, 1), rshift(g_7, 31))
  end
  writeu32(mem, cur + 112, bxor(T[29], l0))
  writeu32(mem, cur + 116, bxor(T[30], h0))
  writeu32(mem, cur + 120, bxor(T[31], l1))
  writeu32(mem, cur + 124, bxor(T[32], h1))
  writeu32(mem, cur + 240, bxor(T[61], l2))
  writeu32(mem, cur + 244, bxor(T[62], h2))
  writeu32(mem, cur + 248, bxor(T[63], l3))
  writeu32(mem, cur + 252, bxor(T[64], h3))
  writeu32(mem, cur + 368, bxor(T[93], l4))
  writeu32(mem, cur + 372, bxor(T[94], h4))
  writeu32(mem, cur + 376, bxor(T[95], l5))
  writeu32(mem, cur + 380, bxor(T[96], h5))
  writeu32(mem, cur + 496, bxor(T[125], l6))
  writeu32(mem, cur + 500, bxor(T[126], h6))
  writeu32(mem, cur + 504, bxor(T[127], l7))
  writeu32(mem, cur + 508, bxor(T[128], h7))
  writeu32(mem, cur + 624, bxor(T[157], l8))
  writeu32(mem, cur + 628, bxor(T[158], h8))
  writeu32(mem, cur + 632, bxor(T[159], l9))
  writeu32(mem, cur + 636, bxor(T[160], h9))
  writeu32(mem, cur + 752, bxor(T[189], l10))
  writeu32(mem, cur + 756, bxor(T[190], h10))
  writeu32(mem, cur + 760, bxor(T[191], l11))
  writeu32(mem, cur + 764, bxor(T[192], h11))
  writeu32(mem, cur + 880, bxor(T[221], l12))
  writeu32(mem, cur + 884, bxor(T[222], h12))
  writeu32(mem, cur + 888, bxor(T[223], l13))
  writeu32(mem, cur + 892, bxor(T[224], h13))
  writeu32(mem, cur + 1008, bxor(T[253], l14))
  writeu32(mem, cur + 1012, bxor(T[254], h14))
  writeu32(mem, cur + 1016, bxor(T[255], l15))
  writeu32(mem, cur + 1020, bxor(T[256], h15))
end
end

local function le32(n)
	local b = {}
	for i = 1, 4 do
		b[i] = string.char(n % 256)
		n = (n - n % 256) / 256
	end
	return table.concat(b)
end

-- reference_area_size base for a segment (index-1 is added per block)
local M = {}

function M.initCache(blake, key, m_cost, t_cost)
	assert(type(key) == "string", "key must be a string")
	m_cost = m_cost or M_COST
	t_cost = t_cost or T_COST
	local seg_len = m_cost // 4
	local lane_len = seg_len * 4
	local mem = buffer.create(m_cost * BLOCK)

	-- H0 = Blake2b-512(lanes, outlen, m_cost, t_cost, version, type,
	--                     pwdlen, pwd, saltlen, salt, secretlen, adlen)
	local h0 = blake.blake2b(
		le32(LANES) .. le32(0) .. le32(m_cost) .. le32(t_cost) .. le32(VERSION) ..
		le32(ARGON2_D) .. le32(#key) .. key .. le32(SALT_LEN) .. SALT ..
		le32(0) .. le32(0),
		64)
	local blockhash = h0 .. le32(0) .. le32(0)

	local tmp = buffer.fromstring(blake.blakeLong(BLOCK, blockhash))
	buffer.copy(mem, 0, tmp, 0, BLOCK)
	blockhash = h0 .. le32(1) .. le32(0)
	tmp = buffer.fromstring(blake.blakeLong(BLOCK, blockhash))
	buffer.copy(mem, BLOCK, tmp, 0, BLOCK)

	for pass = 0, t_cost - 1 do
		for slice = 0, 3 do
			local starting_index = (pass == 0 and slice == 0) and 2 or 0
			-- index_alpha: same_lane is always true, pass/slice only pick a base
			local ras_base = (pass == 0) and slice * seg_len or (lane_len - seg_len)
			local start_pos = (pass ~= 0 and slice ~= 3) and (slice + 1) * seg_len or 0
			local with_xor = pass > 0
			local fill = with_xor and fillBlockX or fillBlock

			local curr = slice * seg_len + starting_index
			local prev
			if curr % lane_len == 0 then
				prev = curr + lane_len - 1
			else
				prev = curr - 1
			end

			for i = starting_index, seg_len - 1 do
				if curr % lane_len == 1 then
					prev = curr - 1
				end
				local prevOff = prev * BLOCK
				-- pseudo_rand = first qword of the previous block
				local pr = readu32(mem, prevOff)
				-- relative_position = (u64)pr * pr >> 32  (high 32 bits)
				local p0 = pr % 65536
				local p1 = (pr - p0) / 65536
				local cross = p0 * p1 * 2
				local q = cross % 65536
				local lo = q * 65536 + p0 * p0
				local rp = ((cross - q) / 65536 + p1 * p1 + (lo - lo % W) / W) % W
				-- 1.2.4 map to 0..<reference_area_size-1>
				local ras = ras_base + i - 1
				local m = ras * rp
				rp = ras - 1 - (m - m % W) / W
				-- 1.2.6 absolute position, always lane 0
				local ref = (start_pos + rp) % lane_len
				fill(mem, prevOff, ref * BLOCK, curr * BLOCK)
				curr += 1
				prev += 1
			end
		end
	end
	return mem
end

return M
