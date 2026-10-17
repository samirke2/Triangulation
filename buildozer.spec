[app]
title = Triangulation
package.name = triangulation
package.domain = org.samir
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,ttf
source.exclude_dirs = bin, .buildozer, venv, __pycache__, .git, .github
source.exclude_patterns = *.db, *.log, triangulation.py, triangulation_backup.py
version = 1.0

# Optional: uncomment after adding icon.png / splash.png next to main.py
# icon.filename = %(source.dir)s/icon.png
# presplash.filename = %(source.dir)s/splash.png
icon.filename = %(source.dir)s/icon.png
presplash.filename = %(source.dir)s/presplash.png
presplash.color = #020B1E

# Requirements (p4a does not install dependencies automatically, so list them all)
# - sqlite3 : needed for `import sqlite3` on the phone
# - kivy_garden.mapview + requests/urllib3/chardet/idna/certifi : map widget and its tile downloader
# - pyjnius : used to read the Android ID for the licence Device ID
# NumPy is NOT required: main.py computes the error ellipse in pure Python.
requirements = python3,hostpython3,kivy==2.3.0,sqlite3,pyjnius,kivy_garden.mapview,requests,urllib3,chardet,idna,certifi

orientation = portrait
fullscreen = 0

android.api = 33
android.minapi = 24
android.ndk = 25b
android.ndk_api = 24
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True

# INTERNET: map tiles and opening WhatsApp / Google Maps links
# READ/WRITE_EXTERNAL_STORAGE: choosing the .txt file in "Import File"

android.permissions = INTERNET, ACCESS_NETWORK_STATE, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE

# The licence/trial state lives in the app data folder; do not restore it from a cloud backup
android.allow_backup = False
android.logcat_filters = *:S python:D

# Stable p4a release matching kivy 2.3.0 / Python 3.11 / NDK 25b
p4a.branch = v2024.01.21

[buildozer]
log_level = 2
warn_on_root = 1
