@echo off
cd ..
call source\env\Scripts\activate
python source\setup.py py2exe
pause
