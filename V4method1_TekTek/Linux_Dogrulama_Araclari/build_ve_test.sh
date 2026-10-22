#!/bin/bash
# TekTek build + unicorn test (Linux)
# 1) motor kaynaklari bu klasorun iki ustu olarak konumlandirin:
#    download/i4MConsoleLoader/i4MConsoleLoader/MazeProtector.h
# 2) capstone 5.0.9 C kutuphanesi (obj/) ve shims derli olmali
# Kisa yol: hazir mp_driver binary'si ile:
export MP_ONLY=MovePlayer MP_TEKTEK=1
./mp_driver MazeGame.exe cikis.exe harita.txt tektek
python3 unicorn_run.py cikis.exe auto   # score=30 WON=1 beklenir
