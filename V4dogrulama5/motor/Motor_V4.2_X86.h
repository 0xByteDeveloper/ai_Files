// ============================================================================
//  Motor_V4.2_X86.h - V4.2 STREAM x86 (PE32) emitter'i
//  Tasarim farklari (x64'e gore):
//   - PEB/blobBase YOK: veri adreslemesi ABSOLUTE disp32/imm32 + RELOC
//     (IMAGE_REL_BASED_HIGHLOW). Load-aninda loader yamar; arena kopyasi
//     yamali degerleri tasir. Blok-ofsetleri (blockTblOff vb.) build sabitidir,
//     reloc ISTEMEZ.
//   - conv = esi (yalniz stage-ICI; her giriste [abs ARENA_PTR]'den yuklenir)
//   - pid = edx (thunk: mov edx,pid; jmp [abs ARENA_PTR])
//   - x86'da rip-relative YOK: original kodun abs data referanslari reloc'dur,
//     slot kopyasi load-sonrasi degerleri tasir -> site fixup yalniz rel32 dal.
//   - VirtualAlloc/VirtualFree stdcall: argumanlar stack'ten, callee temizler.
//   - Header 0x50 (0x40 ARENA_PTR dword, 0x48 jmpSlot dword) - x64 ile ayni.
//   - P_ARENA_IMM 'which' uzayi (x86):
//       0 imgSize  2 sitesOff  3 arenaSize  4 mazeRva  5 firstSpanAbs(RE)
//       7 templateAbs(RE)  8 templateLen  9 slotImmPos  16 slotBase
//       17 slotMask  30 decoyTblOff  32 blockTblOff  34 crcTblOff
//       35 crcFarewellAbs(RE)  36 crcDispPos  37 crcJmpEnd  31 fbStageAbs(RE)
//       40 hintAbs(RE)  41 ARENA_PTR abs(RE)  42 blkTableAbs(RE)
//       43 blobBaseImm(RE)  44 nBlocksAbs(RE)  48 jmpSlot abs(RE)
//       10..: farewell trio (clDispPos/clJmpEnd/farewellAbs(RE))
//     (RE = reloc gerektiren VA)
// ============================================================================
#ifndef MOTOR_V42_X86_H
#define MOTOR_V42_X86_H

// ---- x86 FAREWELL (cleanup kuyrugu; stdcall VirtualFree + ret) ----
// Giris stack'i: [esp]=freeBase, [esp+4]=freeFlag
static u32 EmitArenaFarewellX86(std::vector<u8>& blob, std::vector<Patch>& patches,
                                u32 iatVfRva) {
    u32 S = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    put({0x83, 0x7C, 0x24, 0x04, 0x00});                            // cmp dword [esp+4],0
    put({0x74}); u32 jeSite = (u32)blob.size(); blob.push_back(0);  // je nofree
    put({0x68, 0x00, 0x80, 0x00, 0x00});                            // push 0x8000
    put({0x6A, 0x00});                                              // push 0
    put({0xFF, 0x74, 0x24, 0x08});                                  // push dword [esp+8]
    put({0xFF, 0x15});                                              // call [abs IAT_VF]
    { Patch p; p.kind = Patch::P_ARENA_VF; p.siteOff = (u32)blob.size(); p.immValue = iatVfRva;
      patches.push_back(p); }
    blob.resize(blob.size() + 4, 0);
    u32 nofree = (u32)blob.size();
    blob[jeSite] = (u8)(nofree - (jeSite + 1));
    put({0x83, 0xC4, 0x20});                                        // add esp,0x20
    put({0x58});                                                    // pop eax
    put({0xC3});                                                    // ret
    return S;
}

// ---- x86 GIRIS STUB ----
static u32 EmitStreamStubX86(std::vector<u8>& blob, std::vector<Patch>& patches,
                             u32 iatVaRva, u32 nCleanup, bool hardened) {
    u32 S = (u32)blob.size();                                       // 0x50
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    auto put4 = [&](u32 v) { for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); };
    auto imm = [&](u32 which) {
        Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = which;
        patches.push_back(p); put4(0);
    };

    put({0x9C});                                                    // pushfd
    put({0x50, 0x51, 0x52, 0x53, 0x56, 0x57});                      // push eax,ecx,edx,ebx,esi,edi
    put({0xA1}); imm(20);                                           // mov eax,[abs fbFlag]
    put({0x85, 0xC0});                                              // test eax,eax
    put({0x0F, 0x85}); u32 jneFb = (u32)blob.size(); put4(0);       // jne fb
    put({0xBE}); imm(40);                                           // mov esi,hint (VA, reloc)
    put({0xBF, 0x08, 0x00, 0x00, 0x00});                            // mov edi,8
  u32 tryOff = (u32)blob.size();
    put({0x6A, 0x40});                                              // push 0x40
    put({0x68, 0x00, 0x30, 0x00, 0x00});                            // push 0x3000
    put({0x68, 0x00, 0x10, 0x00, 0x00});                            // push 0x1000
    put({0x56});                                                    // push esi
    put({0xFF, 0x15}); imm(45);                                     // call [abs IAT_VA] (V4.2-X86: w=45; w=2 = sitesOff)
    put({0x85, 0xC0});                                              // test eax,eax
    put({0x0F, 0x85}); u32 jneGot = (u32)blob.size(); put4(0);      // jne got
    put({0x81, 0xC6, 0x00, 0x00, 0x40, 0x00});                      // add esi,0x400000
    put({0x4F});                                                    // dec edi
    put({0x75}); blob.push_back((u8)(tryOff - (blob.size() + 1)));  // jne try
    put({0xE9}); u32 jmpFb = (u32)blob.size(); put4(0);             // jmp fb
  u32 gotOff = (u32)blob.size();
    Poke32(blob, jneGot, (i32)((i64)gotOff - ((i64)jneGot + 4)));
    put({0xA3}); imm(41);                                           // mov [abs ARENA_PTR],eax
    put({0x89, 0xC3});                                              // mov ebx,eax (arena)
    put({0x89, 0xC7});                                              // mov edi,eax (dst)
    put({0xBE}); imm(7);                                            // mov esi,templateAbs
    put({0xB9}); imm(8);                                            // mov ecx,templateLen
    put({0xFC});                                                    // cld
    put({0xF3, 0xA4});                                              // rep movsb
    put({0x0F, 0x31});                                              // rdtsc
    put({0x31, 0xD0});                                              // xor eax,edx
    put({0xC1, 0xE8, 0x0C});                                        // shr eax,12
    put({0x25}); imm(17);                                           // and eax,slotMask
    put({0xC1, 0xE0, 0x05});                                        // shl eax,5
    put({0x05}); imm(16);                                           // add eax,slotBase
    put({0x89, 0x83}); imm(9);                                      // mov [ebx+slotImmPos],eax (ebx=arena)
    for (u32 i = 0; i < nCleanup; i++) {
        put({0x8D, 0x8B}); imm(11 + 3 * i);                         // lea ecx,[ebx+clJmpEnd_i] (ADRES)
        put({0xB8}); imm(12 + 3 * i);                               // mov eax,farewellAbs_i
        // V4.2-X86 DUZELTME: disp = farewell - (arena+clJmpEnd) OLMALI (x64 ile ayni);
        // eski 'sub ecx,eax' TERSINI yaziyordu -> cleanup wild-jmp (arena+~0x593 crash)
        put({0x29, 0xC8});                                          // sub eax,ecx (eax = farewell - (arena+clJmpEnd))
        put({0x89, 0x86}); imm(10 + 3 * i);                         // mov [ebx+clDispPos_i],eax
    }
    if (hardened) {
        put({0x8D, 0x8B}); imm(37);                                 // lea ecx,[ebx+crcJmpEnd] (ADRES)
        put({0xB8}); imm(35);                                       // mov eax,crcFarewellAbs
        put({0x29, 0xC8});                                          // sub eax,ecx
        put({0x89, 0x86}); imm(36);                                 // mov [ebx+crcDispPos],eax
    }
    put({0x31, 0xD2});                                              // xor edx,edx
    put({0xE9}); u32 jmpAT = (u32)blob.size(); put4(0);             // jmp arenaTail
    // ---- fb: yerinde decrypt-once ----
  u32 fbOff = (u32)blob.size();
    Poke32(blob, jneFb, (i32)((i64)fbOff - ((i64)jneFb + 4)));
    Poke32(blob, jmpFb, (i32)((i64)fbOff - ((i64)jmpFb + 4)));
    put({0xC7, 0x05}); imm(20); put4(1);                            // mov dword [abs fbFlag],1
    put({0xBB}); imm(43);                                           // mov ebx,blobBase (reloc)
    put({0xBE}); imm(42);                                           // mov esi,blkTableAbs (reloc)
    put({0x8B, 0x1D}); imm(44);                                     // mov ebx2?? HAYIR - edx=nBlocks:
    blob.resize(blob.size() - 6);                                   // yanlis emit geri al
    put({0x8B, 0x15}); imm(44);                                     // mov edx,[abs nBlocks=blob+0]
  u32 freg = (u32)blob.size();
    put({0x85, 0xD2});                                              // test edx,edx
    put({0x0F, 0x84}); u32 jeFbFlag = (u32)blob.size(); put4(0);    // je fbFlagSet
    put({0x8B, 0x06});                                              // mov eax,[esi] (encOff)
    put({0x8B, 0x4E, 0x04});                                        // mov ecx,[esi+4] (len)
    put({0x83, 0xC6, 0x10});                                        // add esi,16
    put({0x01, 0xD8});                                              // add eax,ebx (dst = blob+encOff)
    put({0x89, 0xC7});                                              // mov edi,eax
  u32 fin = (u32)blob.size();
    put({0x85, 0xC9});                                              // test ecx,ecx
    put({0x0F, 0x84}); u32 jeFbNext = (u32)blob.size(); put4(0);    // je fbNext
    put({0x8B, 0x07});                                              // mov eax,[edi]
    put({0x33, 0x43, 0x08});                                        // xor eax,[ebx+8] (K lo)
    put({0x89, 0x07});                                              // mov [edi],eax
    put({0x8B, 0x47, 0x04});                                        // mov eax,[edi+4]
    put({0x33, 0x43, 0x0C});                                        // xor eax,[ebx+12] (K hi)
    put({0x89, 0x47, 0x04});                                        // mov [edi+4],eax
    put({0x83, 0xC7, 0x08});                                        // add edi,8
    put({0x83, 0xE9, 0x08});                                        // sub ecx,8
    put({0x0F, 0x85}); { u32 h = (u32)blob.size(); put4(0); Poke32(blob, h, (i32)((i64)fin - (h + 4))); }
  u32 fbNext = (u32)blob.size();
    Poke32(blob, jeFbNext, (i32)((i64)fbNext - ((i64)jeFbNext + 4)));
    put({0x4A});                                                    // dec edx
    put({0xE9}); { u32 h = (u32)blob.size(); put4(0); Poke32(blob, h, (i32)((i64)freg - (h + 4))); }
  u32 fbFlagSet = (u32)blob.size();
    Poke32(blob, jeFbFlag, (i32)((i64)fbFlagSet - ((i64)jeFbFlag + 4)));
    put({0xB8}); imm(31);                                           // mov eax,fbStageAbs
    put({0xA3}); imm(41);                                           // mov [abs ARENA_PTR],eax
    put({0xB8}); imm(5);                                            // mov eax,firstSpanAbs
    put({0xA3}); imm(48);                                           // mov [abs jmpSlot],eax
    // ---- kuyruklar ----
    u32 arenaTail = (u32)blob.size();
    Poke32(blob, jmpAT, (i32)((i64)arenaTail - ((i64)jmpAT + 4)));
    put({0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58});                      // pop edi,esi,ebx,edx,ecx,eax
    put({0x9D});                                                    // popfd
    put({0x31, 0xD2});                                              // xor edx,edx
    put({0xFF, 0x25}); imm(41);                                     // jmp [abs ARENA_PTR] -> stage
    put({0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58});                      // pop edi,esi,ebx,edx,ecx,eax
    put({0x9D});                                                    // popfd
    put({0xFF, 0x25}); imm(48);                                     // jmp [abs jmpSlot] -> ilk parca
    return (u32)blob.size();   // V4.2-X86 DUZELTME: STUB SONU donmeli (S=baslangic -> templateAbs=stub olur!)
}

// ---- x86 FALLBACK STAGE (blob icinde statik; eax = hedef parca) ----
static u32 EmitStreamFbStageX86(std::vector<u8>& blob, std::vector<Patch>& patches,
                                u32 nCleanup, const std::vector<u32>& farewellOffs) {
    u32 S0 = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    auto put4 = [&](u32 v) { for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); };
    auto imm = [&](u32 which) {
        Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = which;
        patches.push_back(p); put4(0);
    };
    put({0x9C});                                                    // pushfd
    put({0x50, 0x51, 0x52});                                        // push eax,ecx,edx
    put({0x81, 0xFA, 0xF0, 0x00, 0x00, 0x00});                      // cmp edx,0xF0
    put({0x0F, 0x83}); u32 jaBye = (u32)blob.size(); put4(0);       // jae byeD
    // hedef = blobBase + blk[edx].encOff
    put({0x89, 0xD0});                                              // mov eax,edx
    put({0xC1, 0xE0, 0x04});                                        // shl eax,4
    put({0x05}); imm(32);                                           // add eax,blockTblOff
    put({0x05}); imm(43);                                           // add eax,blobBase (reloc'd imm)
    put({0x8B, 0x00});                                              // mov eax,[eax] (encOff)
    put({0x05}); imm(43);                                           // add eax,blobBase
    put({0x5A});                                                    // pop edx (caller edx GERI)
    put({0x59});                                                    // pop ecx
    put({0x58});                                                    // pop eax
    put({0x9D});                                                    // popfd
    put({0xFF, 0xE0});                                              // jmp eax (parcaya)
    u32 byeD = (u32)blob.size();
    Poke32(blob, jaBye, (i32)((i64)byeD - ((i64)jaBye + 4)));
    put({0x5A});                                                    // pop edx
    put({0x59});                                                    // pop ecx
    put({0x58});                                                    // pop eax
    put({0x9D});                                                    // popfd
    std::vector<u32> jeBye(nCleanup);
    for (u32 i = 0; i < nCleanup; i++) {
        put({0x81, 0xFA}); put4(0xFE - (u32)i);                     // cmp edx,0xFE-i
        put({0x0F, 0x84});
        jeBye[i] = (u32)blob.size(); put4(0);                       // je bye_i
    }
    put({0xE9}); u32 defBye = (u32)blob.size(); put4(0);            // jmp bye0
    for (u32 i = 0; i < nCleanup; i++) {
        u32 bye = (u32)blob.size();
        Poke32(blob, jeBye[i], (i32)((i64)bye - ((i64)jeBye[i] + 4)));
        if (i == 0) Poke32(blob, defBye, (i32)((i64)bye - ((i64)defBye + 4)));
        put({0x50});                                                // push eax (farewell pop eder)
        put({0x83, 0xEC, 0x20});                                    // sub esp,0x20
        put({0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00});            // mov dword [esp],0
        put({0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00});      // mov dword [esp+4],0 (free YOK)
        u32 jmpPos = (u32)blob.size();
        put({0xE9}); put4(0);                                       // jmp farewell_i
        Poke32(blob, jmpPos + 1, (i32)((i64)farewellOffs[i] - ((i64)jmpPos + 5)));
    }
    return S0;
}

// ---- x86 STAGE TEMPLATE (arena'ya kopyalanir; disp yer tutuculari) ----
//  Konvansiyon: edx=pid, esi=conv(arena), edi=slot, ebx=blobBase, ecx/eax scratch.
//  Frame: pushfd + 6 push + sub esp,0x30
//   [esp+0x00]=pid [esp+0x04]=slot [esp+0x08]=encOff [esp+0x0C]=len
//   [esp+0x10]=siteFirst [esp+0x14]=packed [esp+0x18]=delta [esp+0x1C]=crcAcc
//   [esp+0x20]=crcCnt [esp+0x24]=fixCnt [esp+0x28]=fixPtr [esp+0x2C]=(hiza)
static void EmitStreamStageX86(std::vector<u8>& blob, std::vector<Patch>& patches,
                               bool hardened, u32 nPieces, u32 nCleanup,
                               StreamStageInfo& out) {
    u32 S = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    auto put4 = [&](u32 v) { for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); };
    auto imm = [&](u32 which) {
        Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = which;
        patches.push_back(p); put4(0);
    };
    out.stageOff = 0;
    put({0x9C});                                                    // pushfd
    put({0x50, 0x51, 0x52, 0x53, 0x56, 0x57});                      // push eax,ecx,edx,ebx,esi,edi
    put({0x83, 0xEC, 0x30});                                        // sub esp,0x30
    put({0x89, 0x14, 0x24});                                        // mov [esp],edx (pid)
    put({0x81, 0xFA}); put4(nPieces);                               // cmp edx,nPieces
    put({0x0F, 0x83}); u32 jaCl = (u32)blob.size(); put4(0);        // jae clDispatch
    // conv = [abs ARENA_PTR]
    put({0x8B, 0x35}); imm(41);                                     // mov esi,[abs ARENA_PTR]
    put({0x89, 0x74, 0x24, 0x2C});                                  // mov [esp+0x2C],esi (conv YEDEK - decoy oncesi!)
    // slot = conv + slotOff (imm per-call yamali)
    put({0xB8}); out.slotImmPos = (u32)blob.size() - S; imm(16);    // mov eax,slotBase
    put({0x01, 0xF0});                                              // add eax,esi
    put({0x89, 0x44, 0x24, 0x04});                                  // mov [esp+4],eax (slot)
    // blobBase -> ebx
    put({0xBB}); imm(43);                                           // mov ebx,blobBase (reloc)
    // blk girdisi: eax = edx*16 + blockTblOff
    put({0x89, 0xD0});                                              // mov eax,edx
    put({0xC1, 0xE0, 0x04});                                        // shl eax,4
    put({0x05}); imm(32);                                           // add eax,blockTblOff
    put({0x8B, 0x0C, 0x03});                                        // mov ecx,[ebx+eax] (encOff)
    put({0x89, 0x4C, 0x24, 0x08});                                  // mov [esp+8],ecx
    put({0x8B, 0x4C, 0x03, 0x04});                                  // mov ecx,[ebx+eax+4] (len)
    put({0x89, 0x4C, 0x24, 0x0C});                                  // mov [esp+0xC],ecx
    put({0x8B, 0x4C, 0x03, 0x08});                                  // mov ecx,[ebx+eax+8] (siteFirst)
    put({0x89, 0x4C, 0x24, 0x10});                                  // mov [esp+0x10],ecx
    put({0x8B, 0x4C, 0x03, 0x0C});                                  // mov ecx,[ebx+eax+12] (packed)
    put({0x89, 0x4C, 0x24, 0x14});                                  // mov [esp+0x14],ecx
    // slot 32B sifirla (edi = slot)
    put({0x8B, 0x7C, 0x24, 0x04});                                  // mov edi,[esp+4]
    put({0x31, 0xC0});                                              // xor eax,eax
    put({0x89, 0x07}); put({0x89, 0x47, 0x04}); put({0x89, 0x47, 0x08}); put({0x89, 0x47, 0x0C});
    put({0x89, 0x47, 0x10}); put({0x89, 0x47, 0x14}); put({0x89, 0x47, 0x18}); put({0x89, 0x47, 0x1C});
    // G3 decoy (hardened)
    if (hardened) {
        put({0x0F, 0x31});                                          // rdtsc
        put({0x31, 0xD0});                                          // xor eax,edx
        put({0xA8, 0x03});                                          // test al,3
        put({0x75}); u32 jneNd = (u32)blob.size(); blob.push_back(0); // jne nodec
        put({0xC1, 0xE8, 0x0C});                                    // shr eax,12
        put({0x25, 0x03, 0x00, 0x00, 0x00});                        // and eax,3
        // decoy kaydi ONCE dlen (eax=idx korunur), SONRA doff:
        put({0x8B, 0x8C, 0x03}); imm(47);                           // mov ecx,[ebx+eax*8+decoyTblOff+4] (dlen; V4.2-X86: w=47, 34=crcTbl ile CAKISIYORDU!)
        put({0x8B, 0x84, 0x03}); imm(46);                           // mov eax,[ebx+eax*8+decoyTblOff] (doff; w=46)
        put({0x8D, 0x34, 0x03});                                    // lea esi,[ebx+eax] (decoy src; esi KIRILIR - yedek [esp+0x2C])
      u32 dlp = (u32)blob.size();
        put({0x8B, 0x06});                                          // mov eax,[esi]
        put({0x33, 0x43, 0x08});                                    // xor eax,[ebx+8]
        put({0x89, 0x07});                                          // mov [edi],eax
        put({0x8B, 0x46, 0x04});                                    // mov eax,[esi+4]
        put({0x33, 0x43, 0x0C});                                    // xor eax,[ebx+12]
        put({0x89, 0x47, 0x04});                                    // mov [edi+4],eax
        put({0x83, 0xC6, 0x08});                                    // add esi,8
        put({0x83, 0xC7, 0x08});                                    // add edi,8
        put({0x83, 0xE9, 0x08});                                    // sub ecx,8
        put({0x75}); blob.push_back((u8)(dlp - (blob.size() + 1))); // jne dloop
        // slot geri al + yeniden sil; esi=conv geri
        put({0x8B, 0x7C, 0x24, 0x04});                              // mov edi,[esp+4]
        put({0x8B, 0x74, 0x24, 0x2C});                              // mov esi,[esp+0x2C] (conv geri)
        put({0x31, 0xC0});                                          // xor eax,eax
        put({0x89, 0x07}); put({0x89, 0x47, 0x04}); put({0x89, 0x47, 0x08}); put({0x89, 0x47, 0x0C});
        put({0x89, 0x47, 0x10}); put({0x89, 0x47, 0x14}); put({0x89, 0x47, 0x18}); put({0x89, 0x47, 0x1C});
        blob[jneNd + 1] = (u8)((u32)blob.size() - (jneNd + 2));     // nodec:
    }
    // gercek parca decrypt: esi=src (kirilir), edi=slot; sonrasinda esi=conv geri
    // gercek parca decrypt: esi=src (kirilir), edi=slot
    put({0x8B, 0x74, 0x24, 0x08});                                  // mov esi,[esp+8] (encOff)
    put({0x01, 0xDE});                                              // add esi,ebx (src = blob+encOff)
    put({0x8B, 0x7C, 0x24, 0x04});                                  // mov edi,[esp+4] (slot)
  u32 clp = (u32)blob.size();
    put({0x8B, 0x06});                                              // mov eax,[esi]
    put({0x33, 0x43, 0x08});                                        // xor eax,[ebx+8]
    put({0x89, 0x07});                                              // mov [edi],eax
    put({0x8B, 0x46, 0x04});                                        // mov eax,[esi+4]
    put({0x33, 0x43, 0x0C});                                        // xor eax,[ebx+12]
    put({0x89, 0x47, 0x04});                                        // mov [edi+4],eax
    put({0x83, 0xC6, 0x08});                                        // add esi,8
    put({0x83, 0xC7, 0x08});                                        // add edi,8
    put({0x83, 0x6C, 0x24, 0x0C, 0x08});                            // sub dword [esp+0xC],8
    put({0x75}); blob.push_back((u8)(clp - (blob.size() + 1)));     // jne cpy
    // delta = slot - srcVA = slot - encOff - blobBase(ebx)
    put({0x8B, 0x44, 0x24, 0x04});                                  // mov eax,[esp+4] (slot)
    put({0x2B, 0x44, 0x24, 0x08});                                  // sub eax,[esp+8] (encOff)
    put({0x2B, 0xC3});                                              // sub eax,ebx (blobBase)
    put({0x89, 0x44, 0x24, 0x18});                                  // mov [esp+0x18],eax (delta)
    u32 crcFailJne = 0;   // crcFail jne disp konumu (crcFail blogunda Poke)
    // G2 CRC-8 (hardened): acc spill [esp+0x1C], cnt [esp+0x20], ptr edi
    if (hardened) {
        put({0x8B, 0x4C, 0x24, 0x14});                              // mov ecx,[esp+0x14] (packed)
        put({0xC1, 0xE9, 0x08});                                    // shr ecx,8 (beklenen crc)
        put({0x88, 0x4C, 0x24, 0x30});                              // mov [esp+0x30],cl  (beklenen - frame genis! 0x30 kullanim: sub 0x30 yaptik, 0x30 = alt sinir ASAGIDA)
        // DIKKAT: [esp+0x30] frame DISI - bunun yerine dl'de tutalim:
        blob.resize(blob.size() - 4);                               // mov [esp+0x30],cl geri al
        put({0x88, 0xD2});                                          // mov dl,cl?? edx PID tutuyordu!
        blob.resize(blob.size() - 2);
        // edx=pid [esp]'te yedekli -> edx serbest: mov edx,ecx (beklenen)
        put({0x89, 0xCA});                                          // mov edx,ecx (beklenen crc)
        put({0x8B, 0x4C, 0x24, 0x0C});                              // mov ecx,[esp+0xC] (len)
        put({0x8B, 0x7C, 0x24, 0x04});                              // mov edi,[esp+4] (slot)
        put({0xC7, 0x44, 0x24, 0x1C, 0x00, 0x00, 0x00, 0x00});      // mov dword [esp+0x1C],0 (acc)
      u32 cl2 = (u32)blob.size();
        put({0x0F, 0xB6, 0x07});                                    // movzx eax,byte [edi]
        put({0x47});                                                // inc edi
        put({0x33, 0x44, 0x24, 0x1C});                              // xor eax,[esp+0x1C] (acc)
        put({0x25, 0xFF, 0x00, 0x00, 0x00});                        // and eax,0xFF
        put({0x0F, 0xB6, 0x84, 0x03}); imm(34);                     // movzx eax,byte [ebx+eax+crcTblOff]
        put({0x89, 0x44, 0x24, 0x1C});                              // mov [esp+0x1C],eax
        put({0x49});                                                // dec ecx
        put({0x0F, 0x85}); u32 crcJne = (u32)blob.size(); put4(0);  // jne crcloop
        put({0x8B, 0x44, 0x24, 0x1C});                              // mov eax,[esp+0x1C]
        put({0x38, 0xD0});                                          // cmp al,dl (beklenen)
        put({0x0F, 0x85}); crcFailJne = (u32)blob.size(); put4(0); // jne crcFail (tail sonrasi yamali)
        (void)crcJne; Poke32(blob, crcJne, (i32)((i64)cl2 - (crcJne + 4)));
    }
    // site fixup: edi = slot; fixPtr = ebx+siteFirst*12+sitesOff; fixCnt = packed&0xFF
    put({0x8B, 0x7C, 0x24, 0x04});                                  // mov edi,[esp+4] (slot)
    put({0x8B, 0x44, 0x24, 0x10});                                  // mov eax,[esp+0x10] (siteFirst)
    put({0x69, 0xC0, 0x0C, 0x00, 0x00, 0x00});                      // imul eax,eax,12
    put({0x05}); imm(2);                                            // add eax,sitesOff (build sabiti)
    put({0x01, 0xD8});                                              // add eax,ebx (VA)
    put({0x89, 0x44, 0x24, 0x28});                                  // mov [esp+0x28],eax (fixPtr)
    put({0x8B, 0x44, 0x24, 0x14});                                  // mov eax,[esp+0x14] (packed)
    put({0x25, 0xFF, 0x00, 0x00, 0x00});                            // and eax,0xFF (nSites)
    put({0x89, 0x44, 0x24, 0x24});                                  // mov [esp+0x24],eax (fixCnt)
  u32 fxl = (u32)blob.size();
    put({0x83, 0x7C, 0x24, 0x24, 0x00});                            // cmp dword [esp+0x24],0
    put({0x0F, 0x84}); u32 jeFxd = (u32)blob.size(); put4(0);       // je fxDone
    put({0x8B, 0x44, 0x24, 0x28});                                  // mov eax,[esp+0x28] (fixPtr)
    put({0x8B, 0x08});                                              // mov ecx,[eax] (fieldOff)
    put({0x83, 0xC0, 0x0C});                                        // add eax,12
    put({0x89, 0x44, 0x24, 0x28});                                  // mov [esp+0x28],eax
    put({0x8B, 0x14, 0x39});                                        // mov edx,[edi+ecx] (disp)
    put({0x2B, 0x54, 0x24, 0x18});                                  // sub edx,[esp+0x18] (delta)
    put({0x89, 0x14, 0x39});                                        // mov [edi+ecx],edx
    put({0xFF, 0x4C, 0x24, 0x24});                                  // dec dword [esp+0x24]
    put({0xE9}); { u32 h = (u32)blob.size(); put4(0); Poke32(blob, h, (i32)((i64)fxl - (h + 4))); }
  u32 fxDone = (u32)blob.size();
    Poke32(blob, jeFxd, (i32)((i64)fxDone - ((i64)jeFxd + 4)));
    // tail: jmpSlot(abs 0x48) = slot; poplar; jmp [abs 0x48]
    put({0x8B, 0x44, 0x24, 0x04});                                  // mov eax,[esp+4] (slot)
    put({0xA3}); imm(48);                                           // mov [abs jmpSlot],eax
    put({0x83, 0xC4, 0x30});                                        // add esp,0x30
    put({0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58});                      // pop edi,esi,ebx,edx,ecx,eax
    put({0x9D});                                                    // popfd
    put({0xFF, 0x25}); imm(48);                                     // jmp [abs jmpSlot] -> slot
    // ---- crcFail (hardened): tail sonrasi; jmp crcFarewell (disp runtime yamali) ----
    if (hardened) {
        u32 crcFail = (u32)blob.size();
        Poke32(blob, crcFailJne, (i32)((i64)crcFail - ((i64)crcFailJne + 4)));
        put({0x83, 0xC4, 0x30});                                    // add esp,0x30
        put({0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58});                  // pop edi,esi,ebx,edx,ecx,eax
        put({0x9D});                                                // popfd
        out.crcDispPos = (u32)blob.size() - S + 1;                  // E9 disp
        put({0xE9}); put4(0);                                       // jmp crcFarewell (runtime)
        out.crcJmpEnd = (u32)blob.size() - S;
    }
    // ---- clDispatch ----
    u32 clD = (u32)blob.size();
    Poke32(blob, jaCl, (i32)((i64)clD - ((i64)jaCl + 4)));
    put({0x8B, 0x14, 0x24});                                        // mov edx,[esp] (pid)
    put({0x83, 0xC4, 0x30});                                        // add esp,0x30
    put({0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58});                      // pop edi,esi,ebx,edx,ecx,eax
    put({0x9D});                                                    // popfd
    std::vector<u32> jeSite(nCleanup);
    for (u32 i = 0; i < nCleanup; i++) {
        put({0x81, 0xFA}); put4(0xFE - (u32)i);                     // cmp edx,0xFE-i
        put({0x0F, 0x84});
        jeSite[i] = (u32)blob.size(); put4(0);                      // je c_i
    }
    put({0xE9}); u32 defJmp = (u32)blob.size(); put4(0);            // jmp c0
    for (u32 i = 0; i < nCleanup; i++) {
        u32 ci = (u32)blob.size();
        Poke32(blob, jeSite[i], (i32)((i64)ci - ((i64)jeSite[i] + 4)));
        if (i == 0) Poke32(blob, defJmp, (i32)((i64)ci - ((i64)defJmp + 4)));
        put({0x50});                                                // push eax
        put({0x83, 0xEC, 0x20});                                    // sub esp,0x20
        put({0x8B, 0x05}); imm(41);                                 // mov eax,[abs ARENA_PTR]
        put({0x89, 0x04, 0x24});                                    // mov [esp],eax (free base)
        put({0xC7, 0x44, 0x24, 0x04, 0x01, 0x00, 0x00, 0x00});      // mov dword [esp+4],1 (free VAR)
        out.clDispPos.push_back((u32)blob.size() - S + 1);
        out.clJmpEnd.push_back((u32)blob.size() - S + 5);
        put({0xE9}); put4(0);                                       // jmp farewell (runtime)
    }
    out.templateLen = (u32)blob.size() - S;
}

// ============================================================================
//  V4.2-X86 STREAM ANA KURULUM - BuildStream'in PE32 karsiligi
// ============================================================================
inline bool BuildStreamX86(Core& c, const Options& optIn, Report& rep) {
    Options opt = optIn;
    auto& pe  = c.pe;
    auto& mem = c.mem;
    rep.fnRva = opt.fnRva; rep.fnSize = opt.fnSize;
    bool hardened = opt.streamHardened;

    if (!pe.valid || mem.data.empty())          { rep.err = "PE yuklu degil"; return false; }
    if (opt.fnSize < 5)                         { rep.err = "Fonksiyon cok kucuk"; return false; }
    if (opt.fnRva == 0 || opt.fnRva >= pe.imgSz){ rep.err = "RVA goruntu disinda"; return false; }
    if (opt.fnRva + opt.fnSize > pe.imgSz)      { rep.err = "Fonksiyon araligi SizeOfImage'i asiyor"; return false; }
    {
        u32 prVa = 0, prVf = 0;
        bool hasVA = FindIatRva(c, "VirtualAlloc", prVa), hasVF = FindIatRva(c, "VirtualFree", prVf);
        if (!hasVA || !hasVF) {
            if (!EnsureIatImports(c, rep.warnings)) { rep.err = "IAT'ye import eklenemedi"; return false; }
        }
    }
    if (opt.chunkMax < 8)  opt.chunkMax = 8;
    if (opt.chunkMax > 64) opt.chunkMax = 64;
    bool inExec = false;
    for (auto& s : pe.secs)
        if (opt.fnRva >= s.va && opt.fnRva + opt.fnSize <= s.va + (std::max)(s.vSz, s.rawSz))
            { inExec = (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0; break; }
    if (!inExec) { rep.err = "Fonksiyon X section'da degil"; return false; }
    bool relocBody = false; u32 relocBodyRva = 0;
    for (auto& r : pe.relocs) {
        if (r.rva + 8 > opt.fnRva && r.rva < opt.fnRva + opt.fnSize) { relocBody = true; relocBodyRva = r.rva; break; }
    }
    if (relocBody) {
        if (!opt.allowRelocBody) {
            char eb[192]; snprintf(eb, sizeof(eb),
                "Fonksiyon govdesinde mutlak adres (reloc RVA 0x%X) - x86 stream reddetti (V4.5: encoder ASLR kapali cikista izin verir)", relocBodyRva);
            rep.err = eb;
            return false;
        }
        char wb[160]; snprintf(wb, sizeof(wb),
            "Govdede mutlak adres (reloc RVA 0x%X): cikista ASLR KAPALI (DYNAMICBASE temizlendi), mutlak adresler tercih-edilen base'de gecerli", relocBodyRva);
        rep.warnings.push_back(wb);
    }
    u32 iatVaRva = 0, iatVfRva = 0;
    {
        bool va = FindIatRva(c, "VirtualAlloc", iatVaRva);
        bool vf = FindIatRva(c, "VirtualFree", iatVfRva);
        if (!va || !vf) { rep.err = "STREAM x86: VirtualAlloc/VirtualFree yok"; return false; }
        bool hasEp = false; { u32 t; hasEp = FindIatRva(c, "ExitProcess", t); }
        if (opt.streamHardened && !hasEp) { opt.streamHardened = false; hardened = false; }
    }
    if (!c.refs.built) c.BuildRefs();

    // ---- komut komut coz ----
    u64 startVA = mem.base + opt.fnRva;
    u64 endVA   = startVA + opt.fnSize;
    std::vector<MInsn> insns;
    {
        u64 a = startVA;
        while (a < endVA) {
            const u8* p = &mem.data[(size_t)(a - mem.base)];
            size_t rm = (size_t)(mem.data.size() - (a - mem.base));
            cs_insn* i0 = nullptr;
            size_t n = cs_disasm(c.dis.handle, p, (std::min)(rm, (size_t)16), a, 1, &i0);
            if (!n) { char eb[96]; snprintf(eb, sizeof(eb), "Cozulamayan bayt: RVA 0x%X", (u32)(a - mem.base)); rep.err = eb; return false; }
            MInsn m;
            m.rva = (u32)(a - mem.base); m.size = (u8)i0[0].size;
            memcpy(m.bytes, i0[0].bytes, (m.size <= 16) ? m.size : 16);
            m.mn = i0[0].mnemonic;
            cs_detail* d = i0[0].detail;
            u8 op0 = m.bytes[0];
            bool grpJmp = false, grpCall = false, grpRet = false;
            if (d) for (u8 g = 0; g < d->groups_count; g++) {
                if (d->groups[g] == CS_GRP_JUMP) grpJmp = true;
                if (d->groups[g] == CS_GRP_CALL) grpCall = true;
                if (d->groups[g] == CS_GRP_RET)  grpRet  = true;
            }
            m.isRet = grpRet;
            if (op0 >= 0xE0 && op0 <= 0xE3) { cs_free(i0, 1);
                rep.err = "loop/jcxz desteklenmiyor"; return false; }
            u64 immTarget = 0; bool hasImm = false;
            if (d) for (int i = 0; i < d->x86.op_count; i++)
                if (d->x86.operands[i].type == X86_OP_IMM) { hasImm = true; immTarget = (u64)d->x86.operands[i].imm; break; }
            if (grpCall && op0 == 0xE8) {
                m.kind = K_BR; m.targetRva = (u32)(immTarget - mem.base);
            } else if (grpJmp && m.mn == "jmp") {
                if (op0 == 0xE9)      { m.kind = K_BR; m.targetRva = (u32)(immTarget - mem.base); }
                else if (op0 == 0xEB) { m.kind = K_EXPJMP; m.targetRva = (u32)(immTarget - mem.base); }
                else if (hasImm)      { cs_free(i0, 1); rep.err = "Far jmp desteklenmiyor"; return false; }
            } else if (grpJmp) {
                if (op0 >= 0x70 && op0 <= 0x7F)                     { m.kind = K_EXPJCC; m.targetRva = (u32)(immTarget - mem.base); }
                else if (op0 == 0x0F && m.size >= 2 && m.bytes[1] >= 0x80 && m.bytes[1] <= 0x8F) { m.kind = K_JCC; m.targetRva = (u32)(immTarget - mem.base); }
                else { char eb[96]; snprintf(eb, sizeof(eb), "Bilinmeyen dal formu (RVA 0x%X)", m.rva); cs_free(i0, 1); rep.err = eb; return false; }
            }
            if ((m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC) &&
                m.targetRva >= pe.imgSz) { cs_free(i0, 1); rep.err = "Dal goruntu disinda"; return false; }
            cs_free(i0, 1);
            insns.push_back(m);
            a += m.size;
        }
    }
    if (insns.empty()) { rep.err = "Hic komut cozulamadi"; return false; }
    while (insns.size() >= 2) {
        MInsn& last = insns.back();
        if (last.size == 1 && (last.bytes[0] == 0xCC || last.bytes[0] == 0x90)) {
            MInsn& prev = insns[insns.size() - 2];
            if (prev.isRet || (prev.kind == K_BR && prev.mn == "jmp")) {
                insns.pop_back(); opt.fnSize -= 1;
                rep.warnings.push_back("Sondaki dolgu temizlendi");
                continue;
            }
        }
        break;
    }
    rep.fnSize = opt.fnSize;
    {
        MInsn& last = insns.back();
        bool lastJoinJmp = (!last.isRet && (last.kind == K_BR || last.kind == K_EXPJMP) && last.mn == "jmp" &&
                            last.targetRva >= opt.fnRva && last.targetRva < opt.fnRva + opt.fnSize);
        if (!last.isRet && !lastJoinJmp) { rep.err = "x86 STREAM son komut ret/join-jmp olmali ('" + last.mn + "')"; return false; }
    }
    rep.insnCount = (u32)insns.size();

    // ---- kesim ----
    std::vector<char> isTarget(insns.size(), 0);
    for (auto& m : insns)
        if (m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC)
            for (size_t j = 0; j < insns.size(); j++)
                if (insns[j].rva == m.targetRva) { isTarget[j] = 1; break; }
    std::vector<StreamPiece> pcs;
    {
        size_t i = 0;
        while (i < insns.size()) {
            StreamPiece ch; ch.i0 = i; u32 len = 0;
            while (i < insns.size()) {
                if (i > ch.i0 && isTarget[i]) break;
                u32 isz = NewSizeOf(insns[i]);
                if (len > 0 && len + isz > opt.chunkMax) break;
                len += isz; i++;
            }
            ch.n = i - ch.i0;
            pcs.push_back(ch);
        }
    }
    u32 nPieces = (u32)pcs.size();
    if (nPieces >= 0xF0) { rep.err = "parca sayisi 0xF0'u asiyor"; return false; }
    std::vector<u32> insnPiece(insns.size(), 0xFFFFFFFFu);
    for (u32 ci = 0; ci < nPieces; ci++)
        for (size_t k = 0; k < pcs[ci].n; k++) insnPiece[pcs[ci].i0 + k] = ci;
    for (auto& m : insns) {
        if (m.kind == K_BR && m.mn == "call") {
            for (size_t j = 0; j < insns.size(); j++)
                if (insns[j].rva == m.targetRva) {
                    if (insnPiece[j] != insnPiece[&m - &insns[0]]) {
                        char eb[96]; snprintf(eb, sizeof(eb), "parcalar-arasi CALL (RVA 0x%X)", m.rva);
                        rep.err = eb; return false;
                    }
                    break;
                }
        }
    }

    // ---- ret encoding ----
    std::vector<u32> encKeys;
    std::map<u32, u32> encIdx;
    for (auto& m : insns) {
        if (!m.isRet) continue;
        u32 key = (u32)m.bytes[0] | ((u32)((m.size >= 3) ? (m.bytes[1] | ((u32)m.bytes[2] << 8)) : 0) << 8);
        if (!encIdx.count(key)) { encIdx[key] = (u32)encKeys.size(); encKeys.push_back(key); }
    }
    u32 nCleanup = (u32)encKeys.size();

    // ---- blob: header + stub + template ----
    Rng rng(opt.seed ? opt.seed : (opt.fnRva ^ 0x5A17A5A5u ^ 0x57545245u));
    if (!opt.key) {
        u64 t = (u64)GetTickCount64();
        t ^= (u64)(uintptr_t)&c << 32;
        t ^= (u64)opt.fnRva * 0x9E3779B97F4A7C15ull;
        t ^= t >> 29; t *= 0xBF58476D1CE4E5B9ull; t ^= t >> 32;
        opt.key = t ? t : 0x0123456789ABCDEFull;
    }
    rep.keyUsed = opt.key;
    std::vector<u8> blob;
    std::vector<Patch> patches;
    auto putv = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    std::vector<V4Site> v4sites;
    std::vector<V4Local> v4locals;
    blob.resize(0x50, 0);
    u32 stubEnd = EmitStreamStubX86(blob, patches, iatVaRva, nCleanup, opt.streamHardened);
    StreamStageInfo ssi;
    EmitStreamStageX86(blob, patches, hardened, nPieces, nCleanup, ssi);
    u32 templateOff = stubEnd;
    u32 templateLen = ssi.templateLen;
    u32 slotBase = (templateOff + templateLen + 15u) & ~15u;

    // ---- span'ler ----
    std::vector<u32> order(nPieces);
    for (u32 i = 0; i < nPieces; i++) order[i] = i;
    for (size_t i = nPieces - 1; i > 0; i--) std::swap(order[i], order[rng.Next((u32)i + 1)]);
    for (u32 oi = 0; oi < nPieces; oi++) {
        u32 ci = order[oi];
        StreamPiece& ch = pcs[ci];
        ch.encOff = (u32)blob.size();
        ch.siteFirst = (u32)v4sites.size();
        bool endsWithRetSwap = false;
        for (size_t k = 0; k < ch.n; k++) {
            size_t ii = ch.i0 + k;
            MInsn& m = insns[ii];
            m.blobOff = (u32)blob.size();
            if (m.isRet) {
                blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
                m.newSize = 5;
                u32 key = (u32)m.bytes[0] | ((u32)((m.size >= 3) ? (m.bytes[1] | ((u32)m.bytes[2] << 8)) : 0) << 8);
                V4Site s;
                s.fieldAbs = (u32)blob.size() - 4; s.insnAbs = m.blobOff; s.insnLen = 5;
                s.kind = 1; s.value = 0xFE - encIdx[key]; s.piece = ci;
                v4sites.push_back(s);
                if (k + 1 == ch.n) endsWithRetSwap = true;
                continue;
            }
            switch (m.kind) {
            case K_BR: case K_JCC: {
                for (int b = 0; b < m.size; b++) blob.push_back(m.bytes[b]);
                m.newSize = (u32)m.size;
                break;
            }
            case K_EXPJMP: {
                blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
                m.newSize = 5;
                break;
            }
            case K_EXPJCC: {
                blob.push_back(0x0F); blob.push_back((u8)(0x80 | (m.bytes[0] - 0x70)));
                blob.resize(blob.size() + 4, 0);
                m.newSize = 6;
                break;
            }
            default: {
                for (int b = 0; b < m.size; b++) blob.push_back(m.bytes[b]);
                m.newSize = (u32)m.size;
                break;
            }
            }
            if (m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC) {
                bool foundT = false;
                for (size_t j = 0; j < insns.size(); j++)
                    if (insns[j].rva == m.targetRva) {
                        foundT = true;
                        if (insnPiece[j] == ci)
                            v4locals.push_back({ m.blobOff + ((m.kind == K_JCC || m.kind == K_EXPJCC) ? 2u : 1u), m.blobOff, m.newSize, (u32)j });
                        else {
                            V4Site s; s.fieldAbs = m.blobOff + ((m.kind == K_JCC || m.kind == K_EXPJCC) ? 2u : 1u);
                            s.insnAbs = m.blobOff; s.insnLen = m.newSize;
                            s.kind = 1; s.value = insnPiece[j]; s.piece = ci;
                            v4sites.push_back(s);
                        }
                        break;
                    }
                if (!foundT) {
                    if (m.targetRva >= opt.fnRva && m.targetRva < opt.fnRva + opt.fnSize) {
                        char eb[120]; snprintf(eb, sizeof(eb), "Ic dal hedefi komut sinirinda degil (RVA 0x%X)", m.targetRva);
                        rep.err = eb; return false;
                    }
                    V4Site s; s.fieldAbs = m.blobOff + ((m.kind == K_JCC || m.kind == K_EXPJCC) ? 2u : 1u);
                    s.insnAbs = m.blobOff; s.insnLen = m.newSize;
                    s.kind = 0; s.value = m.targetRva; s.piece = ci;
                    v4sites.push_back(s);
                }
            }
        }
        if (!endsWithRetSwap) {
            blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
            V4Site s; s.fieldAbs = (u32)blob.size() - 4;
            s.insnAbs = (u32)blob.size() - 5; s.insnLen = 5;
            s.kind = 1; s.value = (ci + 1 < nPieces) ? (ci + 1) : 0xFE; s.piece = ci;
            v4sites.push_back(s);
        }
        while ((blob.size() - ch.encOff) % 8) blob.push_back(0x90);
        ch.len = (u32)blob.size() - ch.encOff;
    }

    // ---- decoy + CRC tablosu ----
    u32 decoyTblOff = 0;
    if (hardened) {
        while (blob.size() % 8) blob.push_back(0x90);
        decoyTblOff = (u32)blob.size();
        blob.resize(blob.size() + 32, 0x90);
        std::vector<std::pair<u32,u32>> dts;
        for (int di = 0; di < 4; di++) {
            while (blob.size() % 8) blob.push_back(0x90);
            u32 off = (u32)blob.size();
            u32 len = 8 * (2 + rng.Next(2));
            for (u32 i = 0; i < len; i++) blob.push_back((u8)rng.Next(256));
            dts.push_back({ off, len });
        }
        for (int di = 0; di < 4; di++) {
            for (int i = 0; i < 4; i++) blob[decoyTblOff + di * 8 + i] = (u8)(dts[di].first >> (8 * i));
            for (int i = 0; i < 4; i++) blob[decoyTblOff + di * 8 + 4 + i] = (u8)(dts[di].second >> (8 * i));
        }
    }
    u32 crcTblOff = 0;
    if (hardened) {
        while (blob.size() % 16) blob.push_back(0x90);
        crcTblOff = (u32)blob.size();
        for (int i = 0; i < 256; i++) {
            u8 cc = (u8)i;
            for (int b = 0; b < 8; b++)
                cc = (u8)((cc & 0x80) ? ((cc << 1) ^ 0x07) : (cc << 1));
            blob.push_back(cc);
        }
    }

    // ---- THUNK TABLOSU (x86: 11B mov edx,pid; jmp [abs blob+0x40]) ----
    u32 edgeTblOff = (u32)blob.size();
    {
        for (u32 pid = 0; pid < nPieces + nCleanup; pid++) {
            u32 effPid = (pid < nPieces) ? pid : 0xFE - (pid - nPieces);
            blob.push_back(0xBA);                                    // mov edx,imm32
            for (int i = 0; i < 4; i++) blob.push_back((u8)(effPid >> (8 * i)));
            blob.push_back(0xFF); blob.push_back(0x25);              // jmp [ABS disp32]  (x86: disp32 = mutlak adres, rip-rel DEGIL!)
            // V4.2-X86 DUZELTME: disp32 = blobVA+0x40 (mazeRva bilinmedigi icin patch
            // sistemiyle yazilir; w=41 ayni hem deger hem RELOC kaydi uretir)
            { Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = 41;
              patches.push_back(p); }
            blob.resize(blob.size() + 4, 0);
            (void)edgeTblOff;
        }
    }

    // ---- site + blk tablolari ----
    u32 sitesOff = (u32)blob.size();
    for (auto& s : v4sites) {
        u32 fieldRel = s.fieldAbs - pcs[s.piece].encOff;
        for (int i = 0; i < 4; i++) blob.push_back((u8)(fieldRel >> (8 * i)));
        blob.push_back(s.kind); blob.push_back(0); blob.push_back(0); blob.push_back(0);
        for (int i = 0; i < 4; i++) blob.push_back((u8)(s.value >> (8 * i)));
    }
    u32 blockTblOff = (u32)blob.size();
    for (auto& ch : pcs) {
        for (int i = 0; i < 4; i++) blob.push_back((u8)(ch.encOff >> (8 * i)));
        for (int i = 0; i < 4; i++) blob.push_back((u8)(ch.len >> (8 * i)));
        for (int i = 0; i < 4; i++) blob.push_back((u8)(ch.siteFirst >> (8 * i)));
        for (int i = 0; i < 4; i++) blob.push_back(0);
    }
    for (u32 ci = 0; ci < nPieces; ci++) pcs[ci].nSites = 0;
    for (auto& s : v4sites) pcs[s.piece].nSites++;

    // ---- farewell + fbStage + crcFarewell ----
    std::vector<u32> farewellOffs;
    for (u32 i = 0; i < nCleanup; i++) {
        u32 off = EmitArenaFarewellX86(blob, patches, iatVfRva);
        while ((blob.size() - off) % 8) blob.push_back(0x90);
        farewellOffs.push_back(off);
    }
    u32 fbStageOff = EmitStreamFbStageX86(blob, patches, nCleanup, farewellOffs);
    u32 crcFarewellOff = 0;
    if (hardened) {
        crcFarewellOff = (u32)blob.size();
        putv({0xFF, 0x74, 0x24, 0x04});                       // push dword [esp+4] (base)
        putv({0x6A, 0x00});                                   // push 0
        putv({0x68, 0x00, 0x80, 0x00, 0x00});                 // push 0x8000
        putv({0xFF, 0x15});                                   // call [abs IAT_VF]
        { Patch p; p.kind = Patch::P_ARENA_VF; p.siteOff = (u32)blob.size(); p.immValue = iatVfRva; patches.push_back(p); }
        blob.resize(blob.size() + 4, 0);
        putv({0x6A, 0xDE});                                   // push 0xDE
        putv({0xFF, 0x15});                                   // call [abs ExitProcess]
        { u32 t = 0; FindIatRva(c, "ExitProcess", t);
          Patch p; p.kind = Patch::P_ARENA_VF; p.siteOff = (u32)blob.size(); p.immValue = t; patches.push_back(p); }
        blob.resize(blob.size() + 4, 0);
        putv({0xCC});
    }

    // ---- .maze section ----
    u32 chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    u32 mazeRva = 0;
    {
        SecInfo* exist = nullptr;
        for (auto& s : pe.secs) if (!strncmp(s.name, ".maze", 8)) { exist = &s; break; }
        bool reuse = (exist != nullptr);
        if (exist) {
            u32 offInSec = ((std::max)(exist->vSz, exist->rawSz) + 15u) & ~15u;
            u32 needVSz  = offInSec + (u32)blob.size();
            u32 newFileEnd = (size_t)exist->raw + ((needVSz + 0xFFFF) & ~0xFFFFu);
            u32 newImgSz  = exist->va + ((needVSz + 0xFFF) & ~0xFFFu);
            if (newFileEnd > pe.raw.size()) pe.raw.resize(newFileEnd, 0xCC);
            auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
            auto nt = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew);
            u32 secAlign = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SectionAlignment;
            u32 fileAlign = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.FileAlignment;
            auto sh = IMAGE_FIRST_SECTION(nt);
            IMAGE_SECTION_HEADER* hh = nullptr;
            for (u16 i = 0; i < nt->FileHeader.NumberOfSections; i++)
                if (!strncmp((const char*)sh[i].Name, ".maze", 8)) { hh = &sh[i]; break; }
            if (hh) {
                u32 newVSz   = ((needVSz + secAlign - 1) / secAlign) * secAlign;
                u32 newRawSz = ((needVSz + fileAlign - 1) / fileAlign) * fileAlign;
                hh->Misc.VirtualSize = newVSz; hh->SizeOfRawData = newRawSz;
                exist->vSz = newVSz; exist->rawSz = newRawSz;
                ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = newImgSz;
                pe.imgSz = newImgSz;
                if (mem.data.size() < pe.imgSz) mem.data.resize(pe.imgSz, 0);
                mazeRva = exist->va + offInSec;
            } else reuse = false;
        }
        if (!reuse) {
            u32 addSz = (u32)blob.size() + 8;
            u32 mrva2 = 0;
            if (!GrowAppendSection(pe, mem, ".maze", addSz, chars, mrva2)) {
                rep.err = ".maze section eklenemedi"; return false;
            }
            mazeRva = mrva2;
        }
    }
    rep.mazeRva = mazeRva;
    rep.entryRva = mazeRva + pcs[0].encOff;
    for (auto& m : insns) m.newRva = mazeRva + m.blobOff;

    // ---- yama fazlari ----
    auto applyRel32X86 = [&](u64 fieldAbs, u64 insnEndAbs, i64 targetRva, const char* what) -> bool {
        i64 disp = targetRva - ((i64)mazeRva + insnEndAbs);
        if (disp < -2147483648LL || disp > 2147483647LL) { rep.err = std::string("rel32 tasmasi: ") + what; return false; }
        Poke32(blob, (size_t)fieldAbs, (i32)disp);
        rep.fixupCount++;
        return true;
    };
    for (auto& lc : v4locals)
        if (!applyRel32X86(lc.fieldAbs, lc.insnAbs + lc.insnLen, (i64)insns[lc.targetInsn].newRva, "ayni-parca dal")) return false;
    for (auto& s : v4sites) {
        i64 target;
        if (s.kind == 1) {
            u32 thunkIdx = (s.value < 0xF0) ? s.value : (nPieces + (0xFE - s.value));
            target = (i64)mazeRva + edgeTblOff + (i64)thunkIdx * 11;
        } else target = (i64)s.value;
        if (!applyRel32X86(s.fieldAbs, s.insnAbs + s.insnLen, target, "v4 site")) return false;
    }
    // P_ARENA_IMM degerleri + RELOC toplama
    std::vector<u32> relocRvas;
    u32 hintRva = ((pe.imgSz + 0xFFFFu) & ~0xFFFFu);              // image-top (RVA; VA=imgBase+..)
    for (auto& p : patches) {
        if (p.kind == Patch::P_ARENA_VF) {
            Poke32(blob, (size_t)p.siteOff, (i32)(pe.imgBase + p.immValue));
            relocRvas.push_back(mazeRva + p.siteOff);
            continue;
        }
        if (p.kind != Patch::P_ARENA_IMM) continue;
        u32 w = p.immWhich; u32 v = 0; bool isVA = false;
        if (w == 2)        { v = sitesOff; }                            // V4.2-X86: w=2 = sitesOff (offset, VA degil)
        else if (w == 45)  { v = pe.imgBase + iatVaRva; isVA = true; }
        else if (w == 5)   { v = pe.imgBase + mazeRva + pcs[0].encOff; isVA = true; }
        else if (w == 7)   { v = pe.imgBase + mazeRva + templateOff; isVA = true; }
        else if (w == 8)   { v = templateLen; }
        else if (w == 9)   { v = ssi.slotImmPos; }
        else if (w == 16)  { v = slotBase; }
        else if (w == 17)  { v = hardened ? 0x1Fu : 0u; }
        else if (w == 20)  { v = pe.imgBase + mazeRva + 0x20; isVA = true; }
        else if (w == 30)  { v = decoyTblOff; }
        else if (w == 46)  { v = decoyTblOff; }
        else if (w == 47)  { v = decoyTblOff + 4; }
        else if (w == 31)  { v = pe.imgBase + mazeRva + fbStageOff; isVA = true; }
        else if (w == 32)  { v = blockTblOff; }
        else if (w == 34)  { v = crcTblOff; }
        else if (w == 35)  { v = pe.imgBase + mazeRva + crcFarewellOff; isVA = true; }
        else if (w == 36)  { v = ssi.crcDispPos; }
        else if (w == 37)  { v = ssi.crcJmpEnd; }
        else if (w == 40)  { v = pe.imgBase + hintRva; isVA = true; }
        else if (w == 41)  { v = pe.imgBase + mazeRva + 0x40; isVA = true; }
        else if (w == 42)  { v = pe.imgBase + mazeRva + blockTblOff; isVA = true; }
        else if (w == 43)  { v = pe.imgBase + mazeRva; isVA = true; }
        else if (w == 44)  { v = pe.imgBase + mazeRva; isVA = true; }
        else if (w == 48)  { v = pe.imgBase + mazeRva + 0x48; isVA = true; }
        else if (w >= 10 && w < 30) {
            u32 rem = w - 10, i = rem / 3, sub = rem % 3;
            if (i < farewellOffs.size()) {
                if (sub == 0) v = ssi.clDispPos[i];
                else if (sub == 1) v = ssi.clJmpEnd[i];
                else { v = pe.imgBase + mazeRva + farewellOffs[i]; isVA = true; }
            }
        }
        Poke32(blob, (size_t)p.siteOff, (i32)v);
        if (isVA) relocRvas.push_back(mazeRva + p.siteOff);
    }

    // ---- CRC paketleme (FINAL plaintext; disp yamalari dahil) + sifreleme ----
    //  V4.2-X86 DUZELTME: CRC, sifrelemeden ONCE, yamali plaintext uzerinden
    //  hesaplanmali (x64 ile ayni sira) - tersi CRC-fail 0xDE surekli tetikler.
    {
        for (u32 ci = 0; ci < nPieces; ci++) {
            u8 crc = 0;
            for (u32 q = 0; q < pcs[ci].len; q++) {
                crc ^= blob[pcs[ci].encOff + q];
                for (int b = 0; b < 8; b++)
                    crc = (u8)((crc & 0x80) ? ((crc << 1) ^ 0x07) : (crc << 1));
            }
            u32 packed = pcs[ci].nSites | ((u32)crc << 8);
            for (int i = 0; i < 4; i++) blob[blockTblOff + ci * 16 + 12 + i] = (u8)(packed >> (8 * i));
        }
        u64 K = opt.key;
        for (auto& ch : pcs) {
            for (u32 q = 0; q < ch.len; q += 8) {
                u64 v = 0;
                for (int b = 7; b >= 0; b--) v = (v << 8) | blob[ch.encOff + q + b];
                v ^= K;
                for (int b = 0; b < 8; b++) blob[ch.encOff + q + b] = (u8)(v >> (8 * b));
            }
        }
    }
    // MZE3 header
    {
        auto wr32 = [&](u32 off, u32 v) { for (int i = 0; i < 4; i++) blob[off + i] = (u8)(v >> (8 * i)); };
        wr32(0x00, nPieces);
        wr32(0x04, 0x33455A4D);
        for (int i = 0; i < 8; i++) blob[0x08 + i] = (u8)(opt.key >> (8 * i));
        wr32(0x10, rep.entryRva);
        wr32(0x14, opt.fnRva);
        wr32(0x18, opt.fnSize);
        wr32(0x1C, blockTblOff);
        wr32(0x20, getenv("MP_FORCE_FB") ? 1u : 0u);   // V4.2-X86: dogrudan fallback testi
        wr32(0x24, 0u);
        wr32(0x28, 0x1000);
        wr32(0x2C, (u32)v4sites.size());
        wr32(0x30, sitesOff);
        wr32(0x34, pe.imgSz);
        wr32(0x3C, edgeTblOff);
    }

    // ---- bellege yaz + trambolin ----
    memcpy(mem.data.data() + mazeRva, blob.data(), blob.size());
    {
        u32 jmpTargetRva = mazeRva + 0x50;
        i64 rel = (i64)jmpTargetRva - ((i64)opt.fnRva + 5);
        if (rel < -2147483648LL || rel > 2147483647LL) { rep.err = "Trambolin rel32 tasmadi"; return false; }
        u32 bodyEnd = insns.back().rva + insns.back().size - opt.fnRva;
        if (bodyEnd < opt.fnSize) bodyEnd = opt.fnSize;
        u8* body = mem.data.data() + opt.fnRva;
        body[0] = 0xE9;
        for (int i = 0; i < 4; i++) body[1 + i] = (u8)(((u64)rel >> (8 * i)) & 0xFF);
        for (u32 i = 5; i < bodyEnd; i++) body[i] = 0xCC;
    }

    // ---- RELOC (V4.2: TEK .reloc - Core.mpX86Relocs'ta BIRIKIR, her fonksiyonda
    //  tum blok yeniden yazilir; ayni run'da 2. .reloc section OLMAZ) ----
    if (!relocRvas.empty()) {
        if (pe.hasRelocs) {
            for (u32 r : relocRvas) pe.AddRelocation(r, 3);
            rep.warnings.push_back("x86: reloc kayitlari mevcut .reloc'a eklendi");
        } else {
            for (u32 r : relocRvas)
                if (std::find(c.mpX86Relocs.begin(), c.mpX86Relocs.end(), r) == c.mpX86Relocs.end())
                    c.mpX86Relocs.push_back(r);
            std::sort(c.mpX86Relocs.begin(), c.mpX86Relocs.end());
            std::vector<u8> rblk;
            {
                std::map<u32, std::vector<u32>> pages;
                for (u32 r : c.mpX86Relocs) pages[r & ~0xFFFu].push_back(r);
                for (auto& kv : pages) {
                    u32 page = kv.first; auto& offs = kv.second;
                    u32 body = (u32)offs.size() * 2;
                    if (body % 4) body += 2;
                    u32 blockSize = 8 + body;
                    for (int i = 0; i < 4; i++) rblk.push_back((u8)(page >> (8 * i)));
                    for (int i = 0; i < 4; i++) rblk.push_back((u8)(blockSize >> (8 * i)));
                    for (u32 o : offs) {
                        u16 ent = (u16)((10u << 12) | (o - page));
                        rblk.push_back((u8)(ent & 0xFF)); rblk.push_back((u8)(ent >> 8));
                    }
                    if (offs.size() & 1) { rblk.push_back(0); rblk.push_back(0); }
                }
            }
            SecInfo* relSec = nullptr;
            for (auto& s : pe.secs) if (!strncmp(s.name, ".reloc", 8)) { relSec = &s; break; }
            u32 relRva = 0;
            u32 relChars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | 0x02000000u;
            if (!relSec) {
                if (!GrowAppendSection(pe, mem, ".reloc", (u32)rblk.size() + 64, relChars, relRva)) {
                    rep.err = ".reloc section eklenemedi"; return false;
                }
            } else {
                u32 offInSec = ((std::max)(relSec->vSz, relSec->rawSz) + 15u) & ~15u;
                u32 needVSz  = offInSec + (u32)rblk.size();
                u32 newFileEnd = (size_t)relSec->raw + ((needVSz + 0xFFFF) & ~0xFFFFu);
                u32 newImgSz  = relSec->va + ((needVSz + 0xFFF) & ~0xFFFu);
                if (newFileEnd > pe.raw.size()) pe.raw.resize(newFileEnd, 0);
                auto dosg = (PIMAGE_DOS_HEADER)pe.raw.data();
                auto ntg = (PIMAGE_NT_HEADERS32)(pe.raw.data() + dosg->e_lfanew);
                u32 secAlign = ntg->OptionalHeader.SectionAlignment, fileAlign = ntg->OptionalHeader.FileAlignment;
                auto shg = IMAGE_FIRST_SECTION(ntg);
                IMAGE_SECTION_HEADER* hh = nullptr;
                for (u16 i = 0; i < ntg->FileHeader.NumberOfSections; i++)
                    if (!strncmp((const char*)shg[i].Name, ".reloc", 8)) { hh = &shg[i]; break; }
                if (!hh) { rep.err = ".reloc header bulunamadi"; return false; }
                u32 newVSz   = ((needVSz + secAlign - 1) / secAlign) * secAlign;
                u32 newRawSz = ((needVSz + fileAlign - 1) / fileAlign) * fileAlign;
                hh->Misc.VirtualSize = newVSz; hh->SizeOfRawData = newRawSz;
                relSec->vSz = newVSz; relSec->rawSz = newRawSz;
                ntg->OptionalHeader.SizeOfImage = newImgSz;
                pe.imgSz = newImgSz;
                if (mem.data.size() < pe.imgSz) mem.data.resize(pe.imgSz, 0);
                relRva = relSec->va + offInSec;
            }
            memcpy(mem.data.data() + relRva, rblk.data(), rblk.size());
            auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
            auto nt32 = (PIMAGE_NT_HEADERS32)(pe.raw.data() + dos->e_lfanew);
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relSec ? relSec->va : relRva;
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = (u32)rblk.size();
            auto dos2 = (PIMAGE_DOS_HEADER)mem.data.data();
            auto nt32b = (PIMAGE_NT_HEADERS32)(mem.data.data() + dos2->e_lfanew);
            nt32b->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relSec ? relSec->va : relRva;
            nt32b->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = (u32)rblk.size();
            rep.warnings.push_back("x86: .reloc guncellendi (HIGHLOW toplam)");
        }
    }

    // ---- rapor ----
    rep.fnRva = opt.fnRva; rep.fnSize = opt.fnSize;
    rep.chunkCount = nPieces;
    rep.streamActive = true;
    rep.streamBlocks = nPieces;
    rep.streamSites = (u32)v4sites.size();
    rep.streamThunks = nPieces + nCleanup;
    rep.slotSize = 32; rep.maxPieceLen = 0;
    for (auto& ch : pcs) rep.maxPieceLen = (std::max)(rep.maxPieceLen, ch.len);
    rep.arenaSize = 0x1000;
    rep.edgeTblOff = edgeTblOff;
    for (u32 pid = 0; pid < nPieces + nCleanup; pid++) rep.jmpSites.push_back(mazeRva + edgeTblOff + pid * 11);
    {
        char b[256];
        for (u32 ci = 0; ci < nPieces; ci++) {
            u32 eff = ci;
            snprintf(b, sizeof(b), "BLK %02u enc=0x%04X len=%3u ops=%2u rva=0x%04X..0x%04X sites=%u crc=0x%02X",
                     eff, 0, pcs[ci].len, pcs[ci].nSites, (u32)(opt.fnRva + (u32)insns[pcs[ci].i0].rva - (u32)insns[pcs[ci].i0].rva), 0u, pcs[ci].nSites, 0);
            // BLK rva araligi: insns tabanindan
            u32 rvaA = insns[pcs[ci].i0].rva;
            u32 rvaB = (pcs[ci].i0 + pcs[ci].n < insns.size()) ? insns[pcs[ci].i0 + pcs[ci].n].rva : (opt.fnRva + opt.fnSize);
            snprintf(b, sizeof(b), "BLK %02u enc=0x%04X len=%3u ops=%2u rva=0x%04X..0x%04X sites=%u crc=0x%02X",
                     eff, 0, pcs[ci].len, pcs[ci].nSites, rvaA, rvaB, pcs[ci].nSites, 0);
            rep.streamMap.push_back(b);
        }
        for (auto& s : v4sites) {
            const char* kn = (s.kind == 0) ? "MODUL" : (s.kind == 1) ? "THUNK" : "RIP";
            snprintf(b, sizeof(b), "SITE blk=%u +0x%02X kind=%s val=0x%X", s.piece, s.fieldAbs - pcs[s.piece].encOff, kn, s.value);
            rep.streamMap.push_back(b);
        }
        for (u32 pid = 0; pid < nPieces + nCleanup; pid++) {
            u32 effPid = (pid < nPieces) ? pid : 0xFE - (pid - nPieces);
            if (pid < nPieces) snprintf(b, sizeof(b), "EDGE thunk=0x%X mov edx,%u -> parca%u", mazeRva + edgeTblOff + pid * 11, effPid, effPid);
            else               snprintf(b, sizeof(b), "EDGE thunk=0x%X mov edx,0x%X -> cleanup", mazeRva + edgeTblOff + pid * 11, effPid);
            rep.streamMap.push_back(b);
        }
    }
    rep.warnings.push_back("V4.2-X86 STREAM AKTIF: absolute+reloc adresleme, conv=esi (stage-ici), thunk [blob+0x40]");
    if (hardened)
        rep.warnings.push_back("G1 slot rastgele (32x32B) + G2 CRC-8 + G3 decoy");
    return true;
}

#endif // MOTOR_V42_X86_H
