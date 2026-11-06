#include <cstdio>

#include <cstring>
#include <cstdlib>
#include <vector>
#include "blake2/blake2.h"
#include "vm_interpreted_light.hpp"
#include "aes_hash.hpp"

using namespace randomx;
typedef InterpretedLightVmDefault TVm;

struct Tracer : TVm {
	using TVm::TVm;
	using TVm::initialize; using TVm::program; using TVm::config; using TVm::mem; using TVm::scratchpad; using TVm::datasetOffset;

	void trace(int iters) {
		NativeRegisterFile nreg;
		for (unsigned i = 0; i < RegisterCountFlt; ++i) nreg.a[i] = rx_load_vec_f128(&reg.a[i].lo);
		InstructionByteCode bc[RANDOMX_PROGRAM_MAX_SIZE];
		compileProgram(program, bc, nreg, getFlags());
		for (int i = 0; i < 256; i++) printf("bc%d type=%d imm=%016llx mask=%08x tgt=%d\n", i, (int)bc[i].type, (unsigned long long)bc[i].imm, bc[i].memMask, (int)bc[i].target);
		uint32_t sp0 = mem.mx, sp1 = mem.ma;
		printf("ma=%08x mx=%08x eMask=%016llx %016llx rr=%u,%u,%u,%u off=%llu\n",
			mem.ma, mem.mx, (unsigned long long)config.eMask[0], (unsigned long long)config.eMask[1],
			config.readReg0, config.readReg1, config.readReg2, config.readReg3, (unsigned long long)datasetOffset);
		printf("a:");
		for (int i = 0; i < 4; i++) { double bb[2]; unsigned char* b = (unsigned char*)bb; rx_store_vec_f128(bb, nreg.a[i]); printf(" "); for (int j=0;j<16;j++) printf("%02x", b[j]); }
		printf("\n");
		for (int ic = 0; ic < iters; ic++) {
			uint64_t spMix = nreg.r[config.readReg0] ^ nreg.r[config.readReg1];
			sp0 ^= (uint32_t)spMix; sp0 &= ScratchpadL3Mask64;
			sp1 ^= (uint32_t)(spMix >> 32); sp1 &= ScratchpadL3Mask64;
			auto sp0Pre = sp0; auto sp1Pre = sp1;
			for (unsigned i = 0; i < RegistersCount; ++i) nreg.r[i] ^= load64(scratchpad + sp0 + 8 * i);
			if (ic == 1) { printf("DBG sp0=%llx sp1=%llx r=", (unsigned long long)sp0, (unsigned long long)sp1); for (int i=0;i<8;i++) printf(" %016llx", (unsigned long long)nreg.r[i]); printf("\n"); }
			for (unsigned i = 0; i < RegisterCountFlt; ++i) nreg.f[i] = rx_cvt_packed_int_vec_f128(scratchpad + sp1 + 8 * i);
			for (unsigned i = 0; i < RegisterCountFlt; ++i) nreg.e[i] = maskRegisterExponentMantissa(config, rx_cvt_packed_int_vec_f128(scratchpad + sp1 + 8 * (RegisterCountFlt + i)));
			if (ic == 1) { printf("DBGFE f:"); for (int i=0;i<4;i++){unsigned char b[16]; rx_store_vec_f128((double*)b, nreg.f[i]); for(int j=0;j<16;j++) printf("%02x",b[j]);} printf(" e:"); for (int i=0;i<4;i++){unsigned char b[16]; rx_store_vec_f128((double*)b, nreg.e[i]); for(int j=0;j<16;j++) printf("%02x",b[j]);} printf("\n"); }
for (int k=0;k<96;k++) printf("%02x", (unsigned char)scratchpad[sp1+k]); printf("\n");
			printf("sp %08x %08x\nit%d r:", sp0, sp1, ic);
			for (int i = 0; i < 8; i++) printf(" %016llx", (unsigned long long)nreg.r[i]);
			printf("\nf:");
			for (int i = 0; i < 4; i++) { double bb[2]; unsigned char* b = (unsigned char*)bb; rx_store_vec_f128(bb, nreg.f[i]); printf(" "); for (int j=0;j<16;j++) printf("%02x", b[j]); }
			printf("\ne:");
			for (int i = 0; i < 4; i++) { double bb[2]; unsigned char* b = (unsigned char*)bb; rx_store_vec_f128(bb, nreg.e[i]); printf(" "); for (int j=0;j<16;j++) printf("%02x", b[j]); }
			printf("\n");
			for (int pc = 0; pc < 256; pc++) {
				if (pc == 6) { { double bb[2]; rx_store_vec_f128(bb, nreg.f[0]); printf("PRE0 %016llx %016llx\n", (unsigned long long)*(unsigned long long*)&bb[0], (unsigned long long)*(unsigned long long*)&bb[1]); } unsigned long long a = (nreg.r[6] + (unsigned long long)bc[pc].imm) & bc[pc].memMask; printf("ADDR %llx bytes:", a); for (int j=0;j<12;j++) printf("%02x", scratchpad[a+j]); { rx_vec_f128 fv = rx_cvt_packed_int_vec_f128(scratchpad+a); double bb[2]; rx_store_vec_f128(bb, fv); printf(" fsrc=%02x%02x%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x%02x%02x", *((unsigned char*)&bb[0]+7),*((unsigned char*)&bb[0]+6),*((unsigned char*)&bb[0]+5),*((unsigned char*)&bb[0]+4),*((unsigned char*)&bb[0]+3),*((unsigned char*)&bb[0]+2),*((unsigned char*)&bb[0]+1),*((unsigned char*)&bb[0]), *((unsigned char*)&bb[1]+7),*((unsigned char*)&bb[1]+6),*((unsigned char*)&bb[1]+5),*((unsigned char*)&bb[1]+4),*((unsigned char*)&bb[1]+3),*((unsigned char*)&bb[1]+2),*((unsigned char*)&bb[1]+1),*((unsigned char*)&bb[1])); } printf("\n"); }
				if (pc == 15) { double bb[2]; unsigned char* b=(unsigned char*)bb; rx_store_vec_f128(bb, nreg.f[2]); printf("PRE f2:"); for(int j=0;j<16;j++) printf("%02x", b[j]); printf(" dst=%p f2=%p\n", (void*)bc[pc].fdst, (void*)&nreg.f[2]); }
				executeInstruction(bc[pc], pc, scratchpad, config, getFlags());
				if (pc == 15) { double bb[2]; unsigned char* b=(unsigned char*)bb; rx_store_vec_f128(bb, nreg.f[2]); printf("POST f2:"); for(int j=0;j<16;j++) printf("%02x", b[j]); printf("\n"); }
				printf("pc%d r:", pc);
				for (int i = 0; i < 8; i++) printf(" %016llx", (unsigned long long)nreg.r[i]);
				printf(" f:");
				for (int i = 0; i < 4; i++) { double bb[2]; unsigned char* b=(unsigned char*)bb; rx_store_vec_f128(bb, nreg.f[i]); for (int j=0;j<16;j++) printf("%02x", b[j]); }
				printf(" e:");
				for (int i = 0; i < 4; i++) { double bb[2]; unsigned char* b=(unsigned char*)bb; rx_store_vec_f128(bb, nreg.e[i]); for (int j=0;j<16;j++) printf("%02x", b[j]); }
				printf("\n");
			}
			{ unsigned char rb[256]; for (int i=0;i<8;i++) store64(rb+8*i, nreg.r[i]); for (int i=0;i<4;i++){ unsigned char tb[16]; rx_store_vec_f128((double*)tb, nreg.f[i]); memcpy(rb+64+8*i, tb, 8); memcpy(rb+96+8*i, tb+8, 8); rx_store_vec_f128((double*)tb, nreg.e[i]); memcpy(rb+128+8*i, tb, 8); memcpy(rb+160+8*i, tb+8, 8);} unsigned char h[4]; blake2b(h,4,rb,256,nullptr,0); printf("rg:"); for (int j=0;j<256;j++) printf("%02x", rb[j]); printf("\n"); }
			printf("after r:");
			for (int i = 0; i < 8; i++) printf(" %016llx", (unsigned long long)nreg.r[i]);
			printf("FILL0:"); for (int j=0;j<64;j++) printf("%02x", scratchpad[j]); printf("\n");
			printf("\nCHK sp0=%x sp1=%x mem_sp0=%x stored0=%016llx r0=%016llx\n", sp0Pre, sp1Pre, sp0Pre, (unsigned long long)load64(scratchpad+sp1Pre), (unsigned long long)nreg.r[0]);
			printf("SPB:"); for (int j=0;j<64;j++) printf("%02x", scratchpad[sp0Pre+j]); printf(":"); for (int j=0;j<64;j++) printf("%02x", scratchpad[sp1Pre+j]); printf("\n");
			printf("f2:");
			for (int i = 0; i < 4; i++) { double bb[2]; unsigned char* b = (unsigned char*)bb; rx_store_vec_f128(bb, nreg.f[i]); printf(" "); for (int j=0;j<16;j++) printf("%02x", b[j]); }
			printf("\ne2:");
			for (int i = 0; i < 4; i++) { double bb[2]; unsigned char* b = (unsigned char*)bb; rx_store_vec_f128(bb, nreg.e[i]); printf(" "); for (int j=0;j<16;j++) printf("%02x", b[j]); }
			printf("\n");
			unsigned char sp[32]; blake2b(sp, 32, scratchpad, ScratchpadSize, nullptr, 0);
			printf("sp:%02x%02x%02x%02x\n", sp[0], sp[1], sp[2], sp[3]);
			for (int c=0;c<32;c++){ unsigned char h[4]; blake2b(h,4,scratchpad+c*65536,65536,nullptr,0); printf("CH%d %02x%02x%02x%02x\n", c,h[0],h[1],h[2],h[3]); }
			uint64_t readPtr = datasetOffset + (mem.ma & CacheLineAlignMask);
			auto& mp = mem.mx; mp ^= (uint32_t)(nreg.r[config.readReg2] ^ nreg.r[config.readReg3]);
			datasetRead(readPtr, nreg.r);
			std::swap(mem.mx, mem.ma);
			printf("STORING at %p sp1=%x sp0=%x\n", (void*)(scratchpad+sp1), sp1, sp0);
			for (unsigned i = 0; i < RegistersCount; ++i) store64(scratchpad + sp1 + 8 * i, nreg.r[i]);
			printf("AFTERSTORE %016llx\n", (unsigned long long)load64(scratchpad+sp1));
			for (unsigned i = 0; i < RegisterCountFlt; ++i) nreg.f[i] = rx_xor_vec_f128(nreg.f[i], nreg.e[i]);
			printf("FSTORE sp0=%x sp1=%x\n", sp0, sp1);
			for (unsigned i = 0; i < RegisterCountFlt; ++i) rx_store_vec_f128((double*)(scratchpad + sp0 + 16 * i), nreg.f[i]);
			printf("POSTIT:"); for (int j=0;j<96;j++) printf("%02x", scratchpad[0x12ecc0+j]); printf("\n"); printf("POSTIT2:"); for (int j=0;j<96;j++) printf("%02x", scratchpad[0x14b940+j]); printf("\n");
			sp0 = 0; sp1 = 0;
			printf("r3:");
			for (int i = 0; i < 8; i++) printf(" %016llx", (unsigned long long)nreg.r[i]);
			printf("\n");
			for (unsigned i = 0; i < RegistersCount; ++i) store64(&reg.r[i], nreg.r[i]);
			for (unsigned i = 0; i < RegisterCountFlt; ++i) rx_store_vec_f128(&reg.f[i].lo, nreg.f[i]);
			for (unsigned i = 0; i < RegisterCountFlt; ++i) rx_store_vec_f128(&reg.e[i].lo, nreg.e[i]);
		}
	}
};

int main(int argc, char** argv) {
	const char* keyhex = argv[1];
	const char* inhex = argv[2];
	int chains = argc > 3 ? atoi(argv[3]) : 1;
	int iters = argc > 4 ? atoi(argv[4]) : 3;
	size_t kl = strlen(keyhex)/2; std::vector<unsigned char> key(kl);
	for (size_t i=0;i<kl;i++){unsigned v;sscanf(keyhex+2*i,"%2x",&v);key[i]=(unsigned char)v;}
	randomx_cache* cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
	randomx_init_cache(cache, key.data(), key.size());
	Tracer* vm = new Tracer((randomx_flags)(RANDOMX_FLAG_DEFAULT));
	vm->setCache(cache);
	vm->allocate();
	size_t il = strlen(inhex)/2; std::vector<unsigned char> input(il);
	for (size_t i=0;i<il;i++){unsigned v;sscanf(inhex+2*i,"%2x",&v);input[i]=(unsigned char)v;}
	uint64_t tempHash[8];
	blake2b(tempHash, sizeof(tempHash), input.data(), input.size(), nullptr, 0);
	vm->initScratchpad(&tempHash);
	printf("FILLCHK:"); for (int j=0;j<64;j++) printf("%02x", ((unsigned char*)vm->getScratchpad())[0x12ecc0+j]); printf("\n");
	for (int c = 0; c < chains; c++) {
		unsigned char* p = (unsigned char*)&vm->getProgram();
		printf("chain %d\n", c);
		memcpy(p, tempHash, 64);
		fillAes4Rx4<true>(p, 2176, p);
		for (int i = 0; i < 2176; i++) printf("%02x", p[i]);
		printf("\n");
		vm->initialize();
		((Tracer*)vm)->trace(iters);
		{ unsigned char* rg = (unsigned char*)vm->getRegisterFile(); printf("RF:"); for (int j=0;j<256;j++) printf("%02x", rg[j]); printf("\n"); }
		blake2b(tempHash, 64, vm->getRegisterFile(), sizeof(randomx::RegisterFile), nullptr, 0);
	}
	return 0;
}
