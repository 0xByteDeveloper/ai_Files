#!/bin/bash
# STREAM build + unicorn test (Linux)
export MP_ONLY=MovePlayer MP_STREAM=1
./mp_driver MazeGame.exe cikis.exe harita.txt stream
python3 unicorn_run.py cikis.exe auto                       # score=30 WON=1 beklenir
MP_FAIL_ALLOC=8 python3 unicorn_run.py cikis.exe auto       # fallback: score=30 WON=1
python3 mp_antipatch_test.py                                 # G2: exit=222 (0xDE) beklenir
python3 mp_v4_proofs.py cikis.exe                            # G1 + cold-path kanitlari
