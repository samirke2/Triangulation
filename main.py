"""Triangulation app - diagnostic build for Pydroid 3.
Errors and startup checkpoints are written to triangulation_debug.log beside this file.
"""
import os
import sys
import traceback
import faulthandler
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, 'triangulation_debug.log')

def _log_uncaught(exc_type, exc_value, exc_tb):
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as _f:
            _f.write('\n--- UNCAUGHT EXCEPTION %s ---\n' % datetime.now().isoformat())
            traceback.print_exception(exc_type, exc_value, exc_tb, file=_f)
    except Exception:
        pass
    sys.__excepthook__(exc_type, exc_value, exc_tb)

sys.excepthook = _log_uncaught
try:
    _fault_file = open(LOG_PATH, 'a', encoding='utf-8')
    _fault_file.write('\n\n=== APP START %s ===\n' % datetime.now().isoformat())
    _fault_file.flush()
    faulthandler.enable(_fault_file)
except Exception:
    _fault_file = None

def _checkpoint(message):
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as _f:
            _f.write('[%s] %s\n' % (datetime.now().isoformat(), message))
    except Exception:
        pass

_checkpoint('Python entry reached')
import csv
import math
import sqlite3
import webbrowser
from urllib.parse import quote
from contextlib import closing
_checkpoint('Standard-library imports completed')

import kivy
kivy.require('1.11.1')
_checkpoint('Kivy import completed: ' + str(kivy.__version__))

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivy.graphics import Color, Line, RoundedRectangle, Ellipse, Rectangle
from kivy.core.text import Label as CoreLabel
from kivy.metrics import dp
from kivy.lang import Builder
from kivy.properties import (ObjectProperty, StringProperty, ListProperty,
                             NumericProperty, BooleanProperty)
from kivy.uix.widget import Widget
from kivy.resources import resource_add_path
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy_garden.mapview import MapView, MapMarker
# Compatibility helpers: some Kivy Garden MapView releases do not expose
# lat_to_y/lon_to_x from kivy_garden.mapview.utils. Return normalized Web
# Mercator coordinates (0..1), matching the scale calculation below.
def lon_to_x(lon):
    return (float(lon) + 180.0) / 360.0

def lat_to_y(lat):
    # Web Mercator is undefined at the poles; clamp to its standard latitude.
    lat = max(-85.05112878, min(85.05112878, float(lat)))
    lat_rad = math.radians(lat)
    return (1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0

_checkpoint('Kivy and MapView imports completed; local Mercator helpers enabled')

resource_add_path(BASE_DIR)

def get_db_path():
    try:
        app = App.get_running_app()
        if app and hasattr(app, 'user_data_dir') and app.user_data_dir:
            os.makedirs(app.user_data_dir, exist_ok=True)
            return os.path.join(app.user_data_dir, 'emitters.db')
    except Exception:
        pass
    return os.path.join(BASE_DIR, 'emitters.db')


# ---- licensing ----------------------------------------------------------------
import base64
import hashlib
import json
import platform
import time
import uuid

LICENSE_PUBLIC_N = int("b217cd6f199ef0e51c99c82a6da88962cbb1b2393c62a3820959c46333403db2a2328173bd55fa0a2425b54a3aa0a7e9e06a46af5b876247d31722a9bbdf88295ddad1e25b50f5d9c62cb728155ad1e5844bc2dfd2f6a4b8d73da165228c7008208bf1fc477d221f349b361dff6101796189306e32403161bb3014d58881749ca32716536bdb436fe295464c5eb4c7ed3d742ab23e838bd413e8e35f0a15ce48b46b6088686cf4f44a6a46bc9373762dd46c88ae3b1173ba808139cb338bdba1cbe0f106da63f22991a729c41ab9a61401df0f1682d9628f63c9c20d8ccb8f01aab0c0affdbd306e557da6103c5ac62eabb2d4b3469ebe7232dbfcc32d95624b", 16)
LICENSE_PUBLIC_E = 65537
TRIAL_DAYS = 7
TRIAL_OPERATIONS = 10

def _b64url_decode(value):
    value = value.strip()
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def get_device_id():
    """Stable-enough device fingerprint; Android ID is preferred when available."""
    raw = ""
    try:
        from jnius import autoclass
        SettingsSecure = autoclass("android.provider.Settings$Secure")
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        raw = str(SettingsSecure.getString(
            PythonActivity.mActivity.getContentResolver(),
            SettingsSecure.ANDROID_ID))
    except Exception:
        raw = ""
    if not raw or raw == "None":
        raw = "%s|%s|%s" % (platform.system(), platform.machine(), uuid.getnode())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32].upper()

def _verify_rsa_sha256(message, signature):
    """Verify PKCS#1 v1.5 SHA-256 using only the Python standard library."""
    try:
        k = (LICENSE_PUBLIC_N.bit_length() + 7) // 8
        if len(signature) != k:
            return False
        decoded = pow(int.from_bytes(signature, "big"), LICENSE_PUBLIC_E, LICENSE_PUBLIC_N).to_bytes(k, "big")
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
        padding_len = k - len(digest_info) - 3
        expected = b"\x00\x01" + (b"\xff" * padding_len) + b"\x00" + digest_info
        return padding_len >= 8 and decoded == expected
    except Exception:
        return False

def verify_license_token(token, expected_device_id):
    """Token format: base64url(canonical JSON).base64url(RSA-SHA256 signature)."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 2:
            return False, "Invalid license format."
        payload_bytes = _b64url_decode(parts[0])
        signature = _b64url_decode(parts[1])
        if not _verify_rsa_sha256(payload_bytes, signature):
            return False, "License signature is invalid."
        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("product") != "Triangulation" or payload.get("license_type") != "full":
            return False, "This is not a Triangulation Full license."
        if payload.get("device_id") != expected_device_id:
            return False, "This license belongs to a different device."
        if payload.get("license_id") is None:
            return False, "License identifier is missing."
        return True, payload
    except Exception:
        return False, "Could not read the license code."

class LicenseManager:
    def __init__(self):
        self.state_path = os.path.join(get_db_dir(), "triangulation_license.json")
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        self.device_id = get_device_id()
        self.state = self._load()
        now = int(time.time())
        self.state.setdefault("trial_started", now)
        self.state.setdefault("operations", 0)
        self.state.setdefault("last_seen", now)
        self.state.setdefault("tampered", False)
        if now + 300 < int(self.state.get("last_seen", now)):
            self.state["tampered"] = True
        self.state["last_seen"] = max(now, int(self.state.get("last_seen", now)))
        self._save()

    def _load(self):
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
                return state if isinstance(state, dict) else {}
        except Exception:
            return {}

    def _save(self):
        temp = self.state_path + ".tmp"
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(self.state, f, ensure_ascii=False, indent=2)
        os.replace(temp, self.state_path)

    def is_full(self):
        token = self.state.get("license_token", "")
        ok, _ = verify_license_token(token, self.device_id) if token else (False, None)
        return ok

    def trial_status(self):
        if self.is_full():
            return "Full license activated."
        if self.state.get("tampered"):
            return "Trial disabled because the system clock moved backwards."
        elapsed = max(0, int(time.time()) - int(self.state["trial_started"]))
        remaining_seconds = max(0, TRIAL_DAYS * 86400 - elapsed)
        remaining_days = (remaining_seconds + 86399) // 86400
        remaining_ops = max(0, TRIAL_OPERATIONS - int(self.state["operations"]))
        if remaining_seconds <= 0 or remaining_ops <= 0:
            return "Trial expired. Activate a Full license to continue triangulating."
        return "Trial: %d day(s) or %d operation(s) remaining, whichever comes first." % (remaining_days, remaining_ops)

    def authorize_operation(self):
        if self.is_full():
            return True, ""
        now = int(time.time())
        if self.state.get("tampered"):
            return False, "Trial expired or clock rollback detected. Activate a Full license."
        if now + 300 < int(self.state.get("last_seen", now)):
            self.state["tampered"] = True
            self._save()
            return False, "System clock rollback detected. Activate a Full license."
        elapsed = now - int(self.state["trial_started"])
        if elapsed >= TRIAL_DAYS * 86400 or int(self.state["operations"]) >= TRIAL_OPERATIONS:
            return False, "Trial limit reached. Activate a Full license to continue."
        self.state["operations"] = int(self.state["operations"]) + 1
        self.state["last_seen"] = max(now, int(self.state.get("last_seen", now)))
        self._save()
        return True, ""

    def activate(self, token):
        ok, result = verify_license_token(token, self.device_id)
        if not ok:
            return False, result
        self.state["license_token"] = token.strip()
        self._save()
        return True, "Full license activated permanently on this device."

def get_db_dir():
    try:
        app = App.get_running_app()
        if app and getattr(app, "user_data_dir", None):
            return app.user_data_dir
    except Exception:
        pass
    return BASE_DIR
# ---- end licensing ------------------------------------------------------------


BLUE = (0.2, 0.6, 0.86, 1)
DARK_BLUE = (0.1, 0.4, 0.6, 1)
ACCENT_RED = (0.9, 0.3, 0.3, 1)

# Dark theme colours used by the buttons and dialogs
NAVY = (0.05, 0.15, 0.26, 1)
RED_BTN = (0.33, 0.07, 0.08, 1)
GREEN_BTN = (0.02, 0.36, 0.19, 1)
TEAL_BTN = (0.04, 0.33, 0.30, 1)

APP_NAME = 'Triangulation'
APP_VERSION = '1.0'
DEV_PHONE_DISPLAY = '+213 553 762 791'
DEV_PHONE_INTL = '213553762791'

# ---- geo-math ----------------------------------------------------------------
EARTH_RADIUS_KM = 6371.0

def destination_point(lat, lon, bearing, dist_km):
    try:
        d = dist_km / EARTH_RADIUS_KM
        brg = math.radians(bearing)
        phi1 = math.radians(lat)
        lam1 = math.radians(lon)
        sin_phi2 = (math.sin(phi1) * math.cos(d) + math.cos(phi1) * math.sin(d) * math.cos(brg))
        phi2 = math.asin(max(-1.0, min(1.0, sin_phi2)))
        y = math.sin(brg) * math.sin(d) * math.cos(phi1)
        x = math.cos(d) - math.sin(phi1) * sin_phi2
        lam2 = lam1 + math.atan2(y, x)
        return float(math.degrees(phi2)), float((math.degrees(lam2) + 540.0) % 360.0 - 180.0)
    except Exception:
        return lat, lon

def line_intersection(a1, a2, b1, b2):
    try:
        d1 = (a2[0] - a1[0], a2[1] - a1[1])
        d2 = (b2[0] - b1[0], b2[1] - b1[1])
        den = d1[0] * d2[1] - d1[1] * d2[0]
        if abs(den) <= 1e-2 * math.hypot(*d1) * math.hypot(*d2):
            return None
        t = ((b1[0] - a1[0]) * d2[1] - (b1[1] - a1[1]) * d2[0]) / den
        return float(a1[0] + t * d1[0]), float(a1[1] + t * d1[1])
    except Exception:
        return None

def triangulate(stations):
    """Draw one line per station and extend the original lines to forward intersections.

    Intersections are calculated from bearing direction vectors in a local
    east/north plane, independently of the entered range. This means a short
    range cannot prevent a valid forward intersection from being located.
    """
    segments = []
    points = []
    try:
        if not stations:
            return [], None, []

        mean_lat = sum(float(s[0]) for s in stations) / len(stations)
        km_per_lon = 111.32 * max(abs(math.cos(math.radians(mean_lat))), 1e-6)
        origins = []
        directions = []
        ranges = []

        for lat, lon, brg, rng in stations:
            lat, lon, brg, rng = float(lat), float(lon), float(brg) % 360.0, max(0.0, float(rng))
            # Store one segment for each station, initially using its entered range.
            end = destination_point(lat, lon, brg, rng)
            segments.append(((lat, lon), end))
            origins.append((lon * km_per_lon, lat * 111.0))
            angle = math.radians(brg)
            # Bearings are clockwise from north: east = sin, north = cos.
            directions.append((math.sin(angle), math.cos(angle)))
            ranges.append(rng)

        extensions = {}
        candidates = []
        max_pairs = min(len(stations), 100)
        for i in range(max_pairs):
            for j in range(i + 1, max_pairs):
                x1, y1 = origins[i]
                x2, y2 = origins[j]
                ux, uy = directions[i]
                vx, vy = directions[j]
                den = ux * vy - uy * vx
                if abs(den) < 1e-8:
                    continue

                dx, dy = x2 - x1, y2 - y1
                # Solve O_i + t*d_i = O_j + u*d_j.
                t = (dx * vy - dy * vx) / den
                u = (dx * uy - dy * ux) / den
                # Only forward rays count; backward infinite-line crossings do not.
                if t <= 0 or u <= 0:
                    continue

                px, py = x1 + t * ux, y1 + t * uy
                p = (py / 111.0, px / km_per_lon)
                points.append(p)
                candidates.append((t, u, i, j, p))

                # Extend only the two original lines if the crossing is beyond
                # their entered ranges. Never add a third connector line.
                if t > ranges[i]:
                    extensions[i] = p
                if u > ranges[j]:
                    extensions[j] = p

        for idx, endpoint in extensions.items():
            segments[idx] = (segments[idx][0], endpoint)

        if not points:
            return segments, None, []

        fix = (sum(p[0] for p in points) / len(points),
               sum(p[1] for p in points) / len(points))
        return segments, fix, points
    except Exception:
        return segments, None, []

def suggest_required_range(stations):
    """Estimate the range needed for forward bearing rays to meet (km).

    Uses a local tangent-plane approximation and only accepts intersections
    that lie forward of both stations. Returns a recommended common range,
    or None if no forward intersection can be found.
    """
    if len(stations) < 2:
        return None
    try:
        mean_lat = sum(float(s[0]) for s in stations) / len(stations)
        km_per_lon = 111.32 * max(abs(math.cos(math.radians(mean_lat))), 1e-6)
        origins = []
        for lat, lon, bearing, rng in stations:
            angle = math.radians(float(bearing) % 360.0)
            origins.append((float(lon) * km_per_lon, float(lat) * 111.0,
                            math.sin(angle), math.cos(angle), max(float(rng), 0.0)))
        required = []
        for i in range(len(origins)):
            x1, y1, ux, uy, r1 = origins[i]
            for j in range(i + 1, len(origins)):
                x2, y2, vx, vy, r2 = origins[j]
                den = ux * (-vy) - (-vx) * uy
                if abs(den) < 1e-8:
                    continue
                dx, dy = x2 - x1, y2 - y1
                t = (dx * (-vy) - (-vx) * dy) / den
                u = (ux * dy - dx * uy) / den
                if t >= 0 and u >= 0:
                    required.append(max(t, u, r1, r2))
        if not required:
            return None
        return max(required) * 1.10
    except Exception:
        return None


def _largest_nearby_intersection_cluster(points, max_distance_km=10.0):
    """Return the largest group of intersection points close to one another.

    A simple connected-neighbour clustering is used so that spurious,
    distant pairwise crossings do not stretch the error ellipse.
    """
    if not points:
        return []
    try:
        lat0 = sum(float(p[0]) for p in points) / len(points)
        lon_scale = 111.32 * max(abs(math.cos(math.radians(lat0))), 1e-6)
        xy = [(float(p[1]) * lon_scale, float(p[0]) * 111.0) for p in points]
        remaining = set(range(len(points)))
        clusters = []
        while remaining:
            seed = remaining.pop()
            cluster = {seed}
            stack = [seed]
            while stack:
                i = stack.pop()
                near = [j for j in list(remaining)
                        if math.hypot(xy[i][0] - xy[j][0],
                                      xy[i][1] - xy[j][1]) <= max_distance_km]
                for j in near:
                    remaining.remove(j)
                    cluster.add(j)
                    stack.append(j)
            clusters.append(cluster)
        # Prefer the cluster with the most points; break ties by compactness.
        def rank(cluster):
            ids = list(cluster)
            if len(ids) < 2:
                return (len(ids), 0)
            cx = sum(xy[i][0] for i in ids) / len(ids)
            cy = sum(xy[i][1] for i in ids) / len(ids)
            spread = sum((xy[i][0]-cx)**2 + (xy[i][1]-cy)**2 for i in ids) / len(ids)
            return (len(ids), -spread)
        best = max(clusters, key=rank)
        return [points[i] for i in sorted(best)]
    except Exception:
        return list(points)


def calculate_error_ellipse(points, fallback_center=None):
    """Build a red error ellipse from the largest compact cluster of crossings.

    The ellipse represents the spread of calculated pairwise intersections,
    not a guaranteed statistical confidence region unless bearing/range
    uncertainty is supplied by the user.
    """
    cluster = _largest_nearby_intersection_cluster(points)
    if len(cluster) < 2:
        # A single crossing has no measurable scatter; show a small visual
        # marker only, and do not pretend it is a statistically estimated error.
        if not cluster and fallback_center is None:
            return []
        try:
            center = cluster[0] if cluster else fallback_center
            mean_lat, mean_lon = float(center[0]), float(center[1])
            lat_radius = 0.25 / 111.0
            lon_radius = 0.25 / max(111.0 * abs(math.cos(math.radians(mean_lat))), 1e-6)
            return [(mean_lat + lat_radius * math.sin(2 * math.pi * i / 48),
                     mean_lon + lon_radius * math.cos(2 * math.pi * i / 48))
                    for i in range(48)]
        except Exception:
            return []
    try:
        # Pure-Python 2x2 covariance + eigen-decomposition (no NumPy needed).
        n = len(cluster)
        mean_lat = sum(float(p[0]) for p in cluster) / n
        mean_lon = sum(float(p[1]) for p in cluster) / n
        lat_scale = 111.0
        lon_scale = 111.0 * max(abs(math.cos(math.radians(mean_lat))), 1e-6)
        x_km = [(float(p[1]) - mean_lon) * lon_scale for p in cluster]
        y_km = [(float(p[0]) - mean_lat) * lat_scale for p in cluster]
        sxx = sum(x * x for x in x_km) / (n - 1)
        syy = sum(y * y for y in y_km) / (n - 1)
        sxy = sum(x * y for x, y in zip(x_km, y_km)) / (n - 1)
        half_tr = (sxx + syy) / 2.0
        root = math.sqrt(max(0.0, ((sxx - syy) / 2.0) ** 2 + sxy * sxy))
        val_major = half_tr + root
        val_minor = half_tr - root
        # 95% 2-D covariance ellipse scale; small floor keeps the outline visible.
        major = math.sqrt(5.991 * max(val_major, 1e-6))
        minor = math.sqrt(5.991 * max(val_minor, 1e-6))
        angle = 0.5 * math.atan2(2.0 * sxy, sxx - syy)
        ellipse_pts = []
        for i in range(64):
            t = 2 * math.pi * i / 64
            x_e, y_e = major * math.cos(t), minor * math.sin(t)
            x_rot = x_e * math.cos(angle) - y_e * math.sin(angle)
            y_rot = x_e * math.sin(angle) + y_e * math.cos(angle)
            ellipse_pts.append((mean_lat + y_rot / lat_scale,
                                mean_lon + x_rot / lon_scale))
        return ellipse_pts
    except Exception:
        return []

# ---- database ----------------------------------------------------------------
def init_db():
    try:
        with closing(sqlite3.connect(get_db_path())) as conn:
            conn.execute("create table if not exists emm (lat float, long float, bearing float, range float)")
            conn.commit()
    except Exception:
        pass

def load_stations():
    try:
        db_file = get_db_path()
        if not os.path.exists(db_file):
            return []
        with closing(sqlite3.connect(db_file)) as conn:
            rows = conn.execute("select lat, long, bearing, range from emm").fetchall()
        return [tuple(float(v) for v in r) for r in rows if None not in r]
    except Exception:
        return []

def save_stations(stations):
    try:
        with closing(sqlite3.connect(get_db_path())) as conn:
            conn.execute("delete from emm")
            conn.executemany("insert into emm (lat, long, bearing, range) values (?, ?, ?, ?)", stations)
            conn.commit()
    except Exception:
        pass

def add_station_db(station):
    try:
        with closing(sqlite3.connect(get_db_path())) as conn:
            conn.execute("insert into emm (lat, long, bearing, range) values (?, ?, ?, ?)", station)
            conn.commit()
    except Exception:
        pass

# ---- ui helpers --------------------------------------------------------------
def add_panel_bg(widget, color=(0.055, 0.105, 0.15, 1), radius=None):
    """Give a layout a rounded dark panel background."""
    radius = radius or dp(10)
    with widget.canvas.before:
        Color(*color)
        rect = RoundedRectangle(pos=widget.pos, size=widget.size, radius=[radius] * 4)
    widget.bind(pos=lambda w, v: setattr(rect, 'pos', v),
                size=lambda w, v: setattr(rect, 'size', v))
    return rect

def wrapped_label(text, font_size='14sp', color=(0.90, 0.93, 0.97, 1), halign='left', bold=False):
    """Label that wraps to its width and grows to fit its text."""
    lbl = Label(text=text, font_size=font_size, color=color, halign=halign,
                valign='top', bold=bold, size_hint_y=None)
    lbl.bind(width=lambda w, v: setattr(w, 'text_size', (v, None)))
    lbl.bind(texture_size=lambda w, v: setattr(w, 'height', v[1] + dp(2)))
    return lbl

def make_popup(title, content, size_hint=(0.9, 0.6), auto_dismiss=True):
    return Popup(title=title, content=content, size_hint=size_hint,
                 auto_dismiss=auto_dismiss, background='',
                 background_color=(0.03, 0.07, 0.11, 0.98),
                 separator_color=(0.20, 0.55, 0.85, 1),
                 title_size='17sp', title_color=(0.92, 0.96, 1, 1))

def open_url(url, fail_text):
    try:
        if not webbrowser.open(url):
            show_message(fail_text, title='Open')
    except Exception as exc:
        show_message(fail_text + '\n' + str(exc), title='Open')

def show_message(text, title='Info'):
    try:
        box = BoxLayout(orientation='vertical', padding=dp(14), spacing=dp(14))
        label = Label(text=text, halign='center', valign='middle', color=(1, 1, 1, 1))
        label.bind(size=lambda w, s: setattr(w, 'text_size', (max(0, s[0] - dp(4)), s[1])))
        ok = styled_button('OK', bg_color=NAVY, icon='check', size_hint_y=None, height=dp(48))
        box.add_widget(label)
        box.add_widget(ok)
        popup = make_popup(title, box, size_hint=(0.86, 0.42))
        ok.bind(on_press=popup.dismiss)
        popup.open()
    except Exception:
        pass

def styled_button(text, bg_color=NAVY, icon='', **kwargs):
    kwargs.setdefault('color', (0.95, 0.98, 1, 1))
    kwargs.setdefault('icon_color', (0.95, 0.98, 1, 1))
    kwargs.setdefault('font_size', '15sp')
    return IconButton(caption=text, icon=icon, background_color=bg_color, bold=True, **kwargs)

class NumInput(TextInput):
    def insert_text(self, substring, from_undo=False):
        try:
            substring = substring.replace(',', '.')
            clean = ''.join(c for c in substring if c in '0123456789.-+')
            return super().insert_text(clean, from_undo=from_undo)
        except Exception:
            return super().insert_text(substring, from_undo=from_undo)

# ---- vector icons (drawn with canvas, no font/emoji dependency) ----------------
def draw_icon(name, cx, cy, s, color):
    """Draw a simple line icon centred at (cx, cy) with overall size s.

    Must be called inside a `with canvas:` block.
    """
    h = s / 2.0
    w = max(dp(1.5), s * 0.09)
    Color(*color)
    if name == 'menu':
        for dy in (-h * 0.62, 0, h * 0.62):
            Line(points=[cx - h * 0.8, cy + dy, cx + h * 0.8, cy + dy], width=w, cap='round')
    elif name == 'folder':
        x0, y0 = cx - h * 0.85, cy - h * 0.55
        bw, bh = h * 1.7, h * 1.15
        Line(rounded_rectangle=(x0, y0, bw, bh, dp(2)), width=w)
        Line(points=[x0, y0 + bh, x0, y0 + bh + h * 0.22, x0 + h * 0.6, y0 + bh + h * 0.22,
                     x0 + h * 0.8, y0 + bh], width=w)
    elif name == 'exit':
        Line(points=[cx - h * 0.1, cy + h * 0.75, cx - h * 0.8, cy + h * 0.75,
                     cx - h * 0.8, cy - h * 0.75, cx - h * 0.1, cy - h * 0.75], width=w)
        Line(points=[cx - h * 0.3, cy, cx + h * 0.8, cy], width=w, cap='round')
        Line(points=[cx + h * 0.4, cy + h * 0.4, cx + h * 0.8, cy, cx + h * 0.4, cy - h * 0.4],
             width=w, cap='round')
    elif name == 'plus':
        Line(points=[cx - h * 0.75, cy, cx + h * 0.75, cy], width=w * 1.2, cap='round')
        Line(points=[cx, cy - h * 0.75, cx, cy + h * 0.75], width=w * 1.2, cap='round')
    elif name == 'minus':
        Line(points=[cx - h * 0.75, cy, cx + h * 0.75, cy], width=w * 1.2, cap='round')
    elif name == 'locate':
        Line(circle=(cx, cy, h * 0.5), width=w)
        Ellipse(pos=(cx - h * 0.16, cy - h * 0.16), size=(h * 0.32, h * 0.32))
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            Line(points=[cx + dx * h * 0.72, cy + dy * h * 0.72, cx + dx * h, cy + dy * h],
                 width=w, cap='round')
    elif name == 'pin':
        Line(circle=(cx, cy + h * 0.2, h * 0.45), width=w)
        Line(points=[cx - h * 0.38, cy - h * 0.12, cx, cy - h * 0.9, cx + h * 0.38, cy - h * 0.12],
             width=w, joint='round')
        Ellipse(pos=(cx - h * 0.12, cy + h * 0.08), size=(h * 0.24, h * 0.24))
    elif name == 'compass':
        Line(circle=(cx, cy, h * 0.8), width=w)
        Line(points=[cx - h * 0.3, cy - h * 0.3, cx + h * 0.3, cy + h * 0.3], width=w * 1.6, cap='round')
    elif name == 'ruler':
        Line(points=[cx - h * 0.8, cy - h * 0.8, cx + h * 0.8, cy + h * 0.8], width=w * 3.0)
        for k in (-0.4, 0.0, 0.4):
            Line(points=[cx + h * k, cy + h * k + h * 0.15, cx + h * k - h * 0.15, cy + h * k + h * 0.3],
                 width=max(dp(1), w * 0.6))
    elif name == 'map':
        x0, y0 = cx - h * 0.85, cy - h * 0.7
        bw, bh = h * 1.7, h * 1.4
        Line(rounded_rectangle=(x0, y0, bw, bh, dp(2)), width=w)
        Line(points=[x0 + bw / 3.0, y0, x0 + bw / 3.0, y0 + bh], width=w)
        Line(points=[x0 + 2 * bw / 3.0, y0, x0 + 2 * bw / 3.0, y0 + bh], width=w)
    elif name == 'key':
        Line(circle=(cx - h * 0.4, cy + h * 0.25, h * 0.38), width=w)
        Line(points=[cx - h * 0.12, cy, cx + h * 0.8, cy - h * 0.85], width=w, cap='round')
        Line(points=[cx + h * 0.45, cy - h * 0.5, cx + h * 0.75, cy - h * 0.25], width=w, cap='round')
    elif name == 'trash':
        Line(points=[cx - h * 0.8, cy + h * 0.55, cx + h * 0.8, cy + h * 0.55], width=w, cap='round')
        Line(points=[cx - h * 0.25, cy + h * 0.55, cx - h * 0.25, cy + h * 0.85,
                     cx + h * 0.25, cy + h * 0.85, cx + h * 0.25, cy + h * 0.55], width=w)
        Line(points=[cx - h * 0.6, cy + h * 0.55, cx - h * 0.5, cy - h * 0.85,
                     cx + h * 0.5, cy - h * 0.85, cx + h * 0.6, cy + h * 0.55], width=w)
    elif name == 'info':
        Line(circle=(cx, cy, h * 0.85), width=w)
        Ellipse(pos=(cx - h * 0.1, cy + h * 0.30), size=(h * 0.2, h * 0.2))
        Line(points=[cx, cy + h * 0.10, cx, cy - h * 0.48], width=w * 1.5, cap='round')
    elif name == 'close':
        Line(points=[cx - h * 0.6, cy - h * 0.6, cx + h * 0.6, cy + h * 0.6], width=w * 1.2, cap='round')
        Line(points=[cx - h * 0.6, cy + h * 0.6, cx + h * 0.6, cy - h * 0.6], width=w * 1.2, cap='round')
    elif name == 'check':
        Line(points=[cx - h * 0.7, cy, cx - h * 0.2, cy - h * 0.5, cx + h * 0.75, cy + h * 0.55],
             width=w * 1.3, cap='round', joint='round')
    elif name == 'chat':
        Line(rounded_rectangle=(cx - h * 0.85, cy - h * 0.40, h * 1.7, h * 1.2, dp(4)), width=w)
        Line(points=[cx - h * 0.40, cy - h * 0.40, cx - h * 0.62, cy - h * 0.85, cx - h * 0.05, cy - h * 0.40],
             width=w, joint='round')
    elif name == 'call':
        Line(points=[cx - h * 0.55, cy + h * 0.55, cx + h * 0.55, cy - h * 0.55], width=w * 2.6, cap='round')
        Ellipse(pos=(cx - h * 0.85, cy + h * 0.25), size=(h * 0.55, h * 0.55))
        Ellipse(pos=(cx + h * 0.30, cy - h * 0.80), size=(h * 0.55, h * 0.55))
    elif name == 'help':
        Line(circle=(cx, cy, h * 0.85), width=w)
        Line(circle=(cx, cy + h * 0.22, h * 0.30, -100, 170), width=w * 1.2)
        Ellipse(pos=(cx - h * 0.09, cy - h * 0.52), size=(h * 0.18, h * 0.18))
    elif name == 'copy':
        Line(rounded_rectangle=(cx - h * 0.35, cy - h * 0.85, h * 1.1, h * 1.3, dp(2)), width=w)
        Line(rounded_rectangle=(cx - h * 0.8, cy - h * 0.45, h * 1.1, h * 1.3, dp(2)), width=w)


class Icon(Widget):
    """Small drawn icon widget (see draw_icon)."""
    name = StringProperty('')
    color = ListProperty([1, 1, 1, 1])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, name=self._redraw, color=self._redraw)
        Clock.schedule_once(self._redraw, 0)

    def _redraw(self, *args):
        self.canvas.clear()
        if not self.name:
            return
        with self.canvas:
            draw_icon(self.name, self.center_x, self.center_y,
                      min(self.width, self.height), self.color)


class IconButton(Button):
    """Button whose icon and caption are drawn explicitly so they never overlap.

    Use `caption` (not `text`) for the label. The icon + caption group is
    centred; if it is too wide for the button the caption font shrinks to fit.
    Both are drawn on canvas.after, so nothing depends on child widgets.
    """
    caption = StringProperty('')
    icon = StringProperty('')
    icon_color = ListProperty([1, 1, 1, 1])
    icon_dp = NumericProperty(20)
    center_text = BooleanProperty(False)
    face_color = ListProperty([0.05, 0.15, 0.26, 1])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._capture_face(self, self.background_color)
        self.bind(background_color=self._capture_face)
        self.bind(texture_size=self._relayout, center_text=self._relayout, pos=self._relayout, size=self._relayout, caption=self._relayout,
                  icon=self._relayout, icon_color=self._relayout, icon_dp=self._relayout,
                  font_size=self._relayout, bold=self._relayout, color=self._relayout)
        Clock.schedule_once(self._relayout, 0)

    def _capture_face(self, instance, value):
        """Kivy paints a square background with `background_color`; move that
        colour to `face_color` (drawn as a rounded rectangle by the KV rule)
        and make the square one invisible so the corners can be rounded."""
        if tuple(value) != (0, 0, 0, 0):
            self.face_color = list(value)
            self.background_color = (0, 0, 0, 0)

    def _make_texture(self, size_px):
        try:
            core = CoreLabel(text=self.caption, font_size=size_px, bold=self.bold)
            core.refresh()
            return core.texture
        except Exception:
            return None

    def _relayout(self, *args):
        self.canvas.after.clear()
        if self.width <= 1 or self.height <= 1:
            return
        if self.center_text:
            # Caption is the Button's own text, so Kivy centres it exactly;
            # only the icon is drawn, immediately to the left of the text.
            if self.text != self.caption:
                self.text = self.caption
            if self.icon:
                s = dp(self.icon_dp)
                cx = self.center_x - self.texture_size[0] / 2.0 - dp(10) - s / 2.0
                with self.canvas.after:
                    draw_icon(self.icon, cx, self.center_y + dp(1), s, self.icon_color)
            return
        tex = self._make_texture(self.font_size) if self.caption else None
        s = dp(self.icon_dp) if self.icon else 0
        gap = dp(7) if (self.icon and tex) else 0
        avail = max(dp(10), self.width - dp(14))
        if tex is not None and s + gap + tex.width > avail:
            room = max(avail - s - gap, dp(10))
            tex = self._make_texture(max(dp(8), self.font_size * room / float(tex.width)))
        tw = tex.width if tex is not None else 0
        th = tex.height if tex is not None else 0
        total = s + gap + tw
        left = self.center_x - total / 2.0
        if self.center_text and tex is not None:
            # caption exactly centred; icon sits to its left
            left = self.center_x - tw / 2.0 - gap - s
        with self.canvas.after:
            if self.icon:
                draw_icon(self.icon, left + s / 2.0, self.center_y + dp(1), s, self.icon_color)
            if tex is not None:
                Color(*self.color)
                Rectangle(texture=tex, size=(tw, th),
                          pos=(int(left + s + gap), int(self.center_y - th / 2.0 + dp(1))))


class FieldCell(BoxLayout):
    """One labelled input cell; draws a thin divider on its right edge."""
    show_div = BooleanProperty(True)

# ---- الخريطة المحمية ---------------------------------------------------------
class MyMapView(MapView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.double_tap_zoom = True
        self.segments = []
        self.ellipse_latlons = []
        self.fix_marker = None
        
        self.line_instructions = []
        with self.canvas.after:
            # Keep the ellipse as one closed red polyline.
            Color(1.0, 0.0, 0.0, 1.0)
            self.ellipse_line = Line(points=[], width=2.5, closed=True)

        # Redraw geographic overlays whenever the map is moved, zoomed, or resized.
        self.bind(on_map_relocated=self._schedule_redraw)
        self.bind(zoom=self._schedule_redraw, pos=self._schedule_redraw,
                  size=self._schedule_redraw)
        # The tile layer must be rebuilt when the widget is moved/resized by the
        # layout; otherwise tiles stay at their old position (black gaps).
        self.bind(pos=self._on_geometry, size=self._on_geometry)

    def _on_geometry(self, *args):
        Clock.schedule_once(lambda dt: self.trigger_update(True), 0)
        Clock.schedule_once(lambda dt: self.trigger_update(True), 0.4)

    def _schedule_redraw(self, *args):
        Clock.schedule_once(self.update_drawings, 0)

    def set_data(self, segments, ellipse_pts):
        self.segments = segments
        self.ellipse_latlons = ellipse_pts
        Clock.schedule_once(lambda dt: self.update_drawings(), 0.05)

    def set_fix_position(self, lat, lon):
        try:
            lat_f, lon_f = float(lat), float(lon)
            if self.fix_marker is not None:
                try:
                    self.remove_marker(self.fix_marker)
                except Exception:
                    pass
                self.fix_marker = None
            
            self.fix_marker = MapMarker(lat=lat_f, lon=lon_f)
            self.add_marker(self.fix_marker)
        except Exception:
            pass

    def clear_fix(self):
        try:
            if self.fix_marker:
                self.remove_marker(self.fix_marker)
        except Exception:
            pass
        self.fix_marker = None
        self.ellipse_latlons = []
        self.ellipse_line.points = []
        for instruction in self.line_instructions:
            try:
                self.canvas.after.remove(instruction)
            except Exception:
                pass
        self.line_instructions = []

    def clear_all(self):
        self.clear_fix()
        self.segments = []
        self.line_instructions.clear()

    def get_screen_xy(self, lat, lon):
        """Convert a geographic coordinate using MapView's own projection.

        MapView handles the internal pan/zoom transform and tile-source
        projection. Reusing it keeps overlays attached to their real locations.
        """
        try:
            if self.width <= 1 or self.height <= 1:
                return None
            # Supported by current kivy-garden/mapview releases.
            if hasattr(self, 'get_window_xy_from'):
                x, y = self.get_window_xy_from(float(lat), float(lon), self.zoom)
                return float(x), float(y)
            # Compatibility fallback for older releases.
            scale = 2.0 ** self.zoom * 256
            c_x = lon_to_x(self.lon) * scale
            c_y = lat_to_y(self.lat) * scale
            pt_x = lon_to_x(lon) * scale
            pt_y = lat_to_y(lat) * scale
            x = self.x + self.width / 2.0 + (pt_x - c_x)
            y = self.y + self.height / 2.0 - (pt_y - c_y)
            return float(x), float(y)
        except Exception:
            return None

    def update_drawings(self, *args):
        try:
            if self.width <= 1 or self.height <= 1:
                return

            # IMPORTANT: each bearing is a separate Line instruction.
            # Putting all endpoints into one Line(points=[...]) creates
            # unwanted connector segments between independent bearings.
            for instruction in self.line_instructions:
                try:
                    self.canvas.after.remove(instruction)
                except Exception:
                    pass
            self.line_instructions = []
            for (a_lat, a_lon), (b_lat, b_lon) in self.segments:
                x1, y1 = self.get_screen_xy(a_lat, a_lon)
                x2, y2 = self.get_screen_xy(b_lat, b_lon)
                if None not in (x1, y1, x2, y2):
                    with self.canvas.after:
                        Color(0.0, 0.0, 0.0, 1.0)
                        instruction = Line(points=[x1, y1, x2, y2], width=2)
                    self.line_instructions.append(instruction)

            if self.ellipse_latlons:
                ellipse_pts = []
                for lat, lon in self.ellipse_latlons:
                    x, y = self.get_screen_xy(lat, lon)
                    if x is not None and y is not None:
                        ellipse_pts.extend([x, y])
                self.ellipse_line.points = ellipse_pts
            else:
                self.ellipse_line.points = []
        except Exception:
            pass

    def do_update(self, dt):
        super().do_update(dt)
        self.update_drawings()

# ---- main widget -------------------------------------------------------------
class MyWidget(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.map = self.ids.map
        self.fix = None
        init_db()
        self.license_manager = LicenseManager()
        self.stations = load_stations()
        Clock.schedule_once(self.init_map_data, 0.5)

    def init_map_data(self, dt):
        if self.stations and self.map:
            self.refresh_map()

    def add_line(self):
        try:
            lat = to_float(self.ids.input_lat.text)
            lon = to_float(self.ids.input_lon.text)
            brg = to_float(self.ids.input_brg.text)
            rng = to_float(self.ids.input_rng.text)
        except ValueError:
            show_message('Please enter valid numbers in all fields.')
            return

        if not (-90 <= lat <= 90 and -180 <= lon <= 180 and rng > 0):
            show_message('Invalid values check coordinate ranges and range > 0.')
            return

        current_count = len(load_stations())
        max_limit = 100
        if current_count >= max_limit:
            show_message(f'Maximum limit reached ({max_limit} lines).')
            return

        add_station_db((lat, lon, brg, rng))
        self.stations = load_stations()
        
        self.ids.input_lat.text = ''
        self.ids.input_lon.text = ''
        self.ids.input_brg.text = ''
        self.ids.input_rng.text = ''
        
        Clock.schedule_once(lambda dt: self.refresh_map(), 0.05)
        show_message(f'Line added successfully! Total: {len(self.stations)}', title='Success')

    def locate(self, *args):
        self.stations = load_stations()
        if not self.stations:
            show_message('No stations recorded. Add lines or import a file first.')
            return
        allowed, reason = self.license_manager.authorize_operation()
        if not allowed:
            show_message(reason, title='License required')
            self.show_license_popup()
            return
        self.refresh_map()
        if self.fix is None:
            suggested = suggest_required_range(self.stations)
            if suggested is not None:
                show_message(
                    'The bearing lines may intersect beyond the entered ranges.\n'
                    f'Try increasing the range to about {suggested:.1f} km for the relevant stations, '
                    'then press Locate again.',
                    title='Range may be too short')
            else:
                show_message('No forward intersection found. Check the bearings and station coordinates, '
                             'or increase the ranges and try again.')

    def refresh_map(self):
        try:
            m = self.map
            segments, self.fix, intersection_points = triangulate(self.stations)
            ellipse_pts = calculate_error_ellipse(intersection_points, self.fix)
            
            if m:
                m.set_data(segments, ellipse_pts)

            if self.fix:
                m.set_fix_position(float(self.fix[0]), float(self.fix[1]))
                self.ids.label_lat.text = f'{self.fix[0]:.4f}°'
                self.ids.label_lon.text = f'{self.fix[1]:.4f}°'
                m.center_on(float(self.fix[0]), float(self.fix[1]))
                m.zoom = 10
            else:
                if m:
                    m.clear_fix()
                self.ids.label_lat.text = '0.0000°'
                self.ids.label_lon.text = '0.0000°'
            if m:
                m.trigger_update(True)
        except Exception:
            pass

    def zoom_in(self, *args):
        try:
            self.map.zoom = min(int(self.map.zoom) + 1, 19)
        except Exception:
            pass

    def zoom_out(self, *args):
        try:
            self.map.zoom = max(int(self.map.zoom) - 1, 1)
        except Exception:
            pass

    def center_map(self, *args):
        try:
            if self.fix:
                self.map.center_on(float(self.fix[0]), float(self.fix[1]))
            else:
                self.map.center_on(36.5, 6.5)
        except Exception:
            pass

    def go_map(self, *args):
        if self.fix is None:
            show_message('No position yet. Press Locate first.')
            return
        lat, lon = self.fix
        webbrowser.open(f'https://www.google.com/maps/@?api=1&map_action=map&center={lat}%2C{lon}&zoom=18&basemap=satellite')

    def show_menu(self, *args):
        layout = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(14))
        popup = make_popup('Main Menu', layout, size_hint=(0.82, 0.66))
        items = (
            ('Help', 'help', self.show_help_popup, NAVY),
            ('License / Activate', 'key', self.show_license_popup, NAVY),
            ('About', 'info', self.show_about_popup, NAVY),
            ('Clear All Data', 'trash', self.clear_data, RED_BTN),
            ('Close Menu', 'close', None, NAVY),
        )
        for text, icon, action, color in items:
            btn = styled_button(text, bg_color=color, icon=icon)
            btn.bind(on_press=popup.dismiss)
            if action:
                btn.bind(on_press=lambda *a, f=action: f())
            layout.add_widget(btn)
        popup.open()

    def show_license_popup(self, *args):
        status = self.license_manager.trial_status()
        device_id = self.license_manager.device_id
        layout = BoxLayout(orientation='vertical', spacing=dp(8),
                           padding=[dp(12), dp(8), dp(12), dp(10)])
        popup = make_popup('Triangulation License', layout,
                           size_hint=(0.94, 0.92), auto_dismiss=False)

        # status
        status_box = BoxLayout(size_hint_y=None, height=dp(56), padding=[dp(10), dp(4)])
        add_panel_bg(status_box)
        status_label = Label(text=status, halign='center', valign='middle',
                             font_size='14sp', color=(0.95, 0.97, 1, 1))
        status_label.bind(size=lambda w, s: setattr(w, 'text_size', (max(0, s[0] - dp(4)), s[1])))
        status_box.add_widget(status_label)

        # device id + copy
        device_row = BoxLayout(size_hint_y=None, height=dp(86), spacing=dp(8),
                               padding=[dp(10), dp(6)])
        add_panel_bg(device_row)
        id_col = BoxLayout(orientation='vertical')
        id_caption = Label(text='Device ID - send it to the license issuer', font_size='11sp',
                           color=(0.62, 0.72, 0.84, 1), halign='left', valign='middle',
                           size_hint_y=None, height=dp(30))
        id_caption.bind(size=lambda w, s: setattr(w, 'text_size', (s[0], s[1])))
        id_label = Label(text=device_id[:16] + '\n' + device_id[16:], bold=True,
                         font_size='15sp', color=(1, 1, 1, 1), halign='left', valign='middle')
        id_label.bind(size=lambda w, s: setattr(w, 'text_size', (s[0], s[1])))
        id_col.add_widget(id_caption)
        id_col.add_widget(id_label)
        copy_btn = styled_button('Copy ID', bg_color=NAVY, icon='copy', icon_dp=16,
                                 font_size='14sp', size_hint=(None, 1), width=dp(104))

        def copy_device_id(*_):
            try:
                Clipboard.copy(device_id)
                copy_btn.caption = 'Copied!'
                Clock.schedule_once(lambda dt: setattr(copy_btn, 'caption', 'Copy ID'), 1.5)
            except Exception as exc:
                show_message('Could not copy Device ID. Please select and copy it manually.\n' + str(exc),
                             title='Clipboard')

        copy_btn.bind(on_press=copy_device_id)
        device_row.add_widget(id_col)
        device_row.add_widget(copy_btn)

        # price
        price_box = BoxLayout(size_hint_y=None, height=dp(46), padding=[dp(10), dp(4)])
        add_panel_bg(price_box)
        price_label = Label(text='Full License: 15,000 DZD  |  Permanent license for one device',
                            font_size='12sp', halign='center', valign='middle',
                            color=(0.95, 0.78, 0.30, 1))
        price_label.bind(size=lambda w, s: setattr(w, 'text_size', (max(0, s[0] - dp(4)), s[1])))
        price_box.add_widget(price_label)

        token_input = TextInput(
            hint_text='Paste Full license code here',
            multiline=True,
            size_hint_y=1,
            font_size='14sp',
            padding=[dp(10), dp(10)],
            background_normal='',
            background_active='',
            background_color=(0.96, 0.97, 0.98, 1),
            foreground_color=(0.08, 0.10, 0.13, 1),
            cursor_color=(0.05, 0.35, 0.65, 1),
        )

        # buttons: stacked so captions never collide
        buttons = BoxLayout(orientation='vertical', size_hint_y=None,
                            height=dp(3 * 46 + 2 * 8), spacing=dp(8))
        activate_btn = styled_button('Activate Full', bg_color=GREEN_BTN, icon='check')
        whatsapp_btn = styled_button('Request via WhatsApp', bg_color=TEAL_BTN, icon='chat')
        close_btn = styled_button('Close', bg_color=NAVY, icon='close')

        def request_via_whatsapp(*_):
            message = (
                'Hello, I would like to purchase a Triangulation Full License.\n'
                'Device ID: ' + device_id + '\n'
                'Price: 15,000 DZD\n'
                'License: Permanent, for one device.\n'
                'Please send me the activation code for this Device ID.'
            )
            open_url('https://wa.me/' + DEV_PHONE_INTL + '?text=' + quote(message),
                     'If WhatsApp did not open, copy your Device ID and contact ' + DEV_PHONE_DISPLAY + '.')

        def activate(*_):
            ok, message = self.license_manager.activate(token_input.text)
            show_message(message, title='License')
            if ok:
                popup.dismiss()

        activate_btn.bind(on_press=activate)
        whatsapp_btn.bind(on_press=request_via_whatsapp)
        close_btn.bind(on_press=popup.dismiss)
        buttons.add_widget(activate_btn)
        buttons.add_widget(whatsapp_btn)
        buttons.add_widget(close_btn)

        layout.add_widget(status_box)
        layout.add_widget(device_row)
        layout.add_widget(price_box)
        layout.add_widget(token_input)
        layout.add_widget(buttons)
        popup.open()

    def show_help_popup(self, *args):
        sections = (
            ('What the app does',
             'Triangulation finds the position of a transmitter from several direction-finding '
             'stations. Each station gives a bearing line; where the lines cross is the estimated '
             'position.'),
            ('Quick start',
             '1. Fill Lat, Lon, Bear and Rng for one station, then press Add.\n'
             '2. Repeat for every station (at least 2, with different bearings).\n'
             '3. Press Locate Intersection.\n'
             '4. Read the position under the map, or press Google Maps to open it.'),
            ('Lat - latitude',
             'Decimal degrees from -90 to 90.\n'
             '+ = North, - = South.\n'
             'Example: +36.7538 (north) or -33.8688 (south).'),
            ('Lon - longitude',
             'Decimal degrees from -180 to 180.\n'
             '+ = East, - = West.\n'
             'Example: +3.0422 (east) or -3.7038 (west).'),
            ('Bear - bearing',
             'The angle between true North and the line, measured clockwise from 0 to 360.\n'
             '0 = North, 90 = East, 180 = South, 270 = West.'),
            ('Rng - range',
             'The length of the line drawn from the station, in km (must be greater than 0). '
             'If the intersection is farther away, the line is extended to reach it automatically.'),
            ('Reading the map',
             '- Black lines: the bearing lines of your stations.\n'
             '- Red pin: the calculated position (average of the crossings).\n'
             '- Red ellipse: the estimated error area, built from the main group of crossings.\n'
             '- Only the forward direction of each bearing is used.'),
            ('Map buttons',
             'Target icon: centre the map on the position.\n'
             '+ and -: zoom in and out.'),
            ('Import File',
             'Load stations from a .txt file. The first line must be the header '
             'lat,lon,bear,rangge (commas or semicolons), then one station per line, for example:\n'
             'lat,lon,bear,rangge\n'
             '36.75,3.04,45,120\n'
             'Importing replaces the stations already stored.'),
            ('Limits and license',
             'Up to 100 lines can be stored. The free trial lasts 7 days or 10 Locate operations, '
             'whichever comes first. Open Menu > License / Activate to send your Device ID and '
             'enter a Full license code.'),
            ('Troubleshooting',
             '- "No forward intersection": check the bearings and station positions; lines that '
             'are parallel or point away from each other never cross.\n'
             '- Position far from what you expect: check the signs of Lat and Lon (+/-).\n'
             '- Menu > Clear All Data removes every station.'),
        )
        layout = BoxLayout(orientation='vertical', spacing=dp(10),
                           padding=[dp(12), dp(8), dp(12), dp(12)])
        popup = make_popup('Help', layout, size_hint=(0.94, 0.9))
        scroll = ScrollView(do_scroll_x=False)
        body = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(10))
        body.bind(minimum_height=body.setter('height'))
        for title, text in sections:
            card = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(4),
                             padding=[dp(12), dp(8), dp(12), dp(10)])
            card.bind(minimum_height=card.setter('height'))
            add_panel_bg(card)
            card.add_widget(wrapped_label(title, '14sp', color=(0.35, 0.72, 1, 1), bold=True))
            card.add_widget(wrapped_label(text, '13sp'))
            body.add_widget(card)
        scroll.add_widget(body)
        close_btn = styled_button('Close', bg_color=NAVY, icon='close', size_hint_y=None, height=dp(46))
        close_btn.bind(on_press=popup.dismiss)
        layout.add_widget(scroll)
        layout.add_widget(close_btn)
        popup.open()

    def show_about_popup(self, *args):
        layout = BoxLayout(orientation='vertical', spacing=dp(10),
                           padding=[dp(14), dp(8), dp(14), dp(12)])
        popup = make_popup('About', layout, size_hint=(0.92, 0.86))

        # header
        header = BoxLayout(size_hint_y=None, height=dp(64), spacing=dp(12))
        header.add_widget(Icon(name='locate', color=[0.35, 0.72, 1, 1], size_hint=(None, None),
                               size=(dp(48), dp(48)), pos_hint={'center_y': 0.5}))
        title_col = BoxLayout(orientation='vertical')
        name_label = Label(text=APP_NAME, bold=True, font_size='22sp', halign='left',
                           valign='bottom', color=(1, 1, 1, 1))
        ver_label = Label(text='Version ' + APP_VERSION, font_size='13sp', halign='left',
                          valign='top', color=(0.62, 0.72, 0.84, 1))
        for lbl in (name_label, ver_label):
            lbl.bind(size=lambda w, s: setattr(w, 'text_size', (s[0], s[1])))
            title_col.add_widget(lbl)
        header.add_widget(title_col)

        # description (scrolls on small screens)
        scroll = ScrollView(do_scroll_x=False)
        info_box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(10))
        info_box.bind(minimum_height=info_box.setter('height'))
        info_box.add_widget(wrapped_label(
            'Triangulation locates a transmitter by intersecting the bearing lines '
            'of several direction-finding stations. Enter latitude, longitude, bearing '
            'and range for each station, then press Locate Intersection: the app draws '
            'the lines, calculates the forward intersection and shows the estimated '
            'error ellipse on the map.', font_size='14sp'))
        info_box.add_widget(wrapped_label(
            '\u2022 Up to 100 bearing lines per session\n'
            '\u2022 Import stations from a .txt file (lat, lon, bear, rangge)\n'
            '\u2022 Error ellipse built from the main cluster of intersections\n'
            '\u2022 Open the computed position in Google Maps\n'
            '\u2022 7-day / 10-operation trial, then a one-time Full license',
            font_size='13sp', color=(0.70, 0.78, 0.88, 1)))
        scroll.add_widget(info_box)

        # developer contact
        contact = BoxLayout(orientation='vertical', size_hint_y=None, height=dp(142),
                            spacing=dp(6), padding=[dp(10), dp(8)])
        add_panel_bg(contact)
        contact_title = Label(text='Contact the developer', bold=True, font_size='14sp',
                              color=(0.35, 0.72, 1, 1), size_hint_y=None, height=dp(22))
        phone_label = Label(text=DEV_PHONE_DISPLAY, bold=True, font_size='19sp',
                            color=(1, 1, 1, 1), size_hint_y=None, height=dp(30))
        contact_row = BoxLayout(spacing=dp(8))
        wa_btn = styled_button('WhatsApp', bg_color=TEAL_BTN, icon='chat')
        call_btn = styled_button('Call', bg_color=NAVY, icon='call')
        wa_btn.bind(on_press=lambda *_: open_url(
            'https://wa.me/' + DEV_PHONE_INTL + '?text=' + quote('Hello, I have a question about the Triangulation app.'),
            'Could not open WhatsApp. Please contact ' + DEV_PHONE_DISPLAY + ' manually.'))
        call_btn.bind(on_press=lambda *_: open_url(
            'tel:+' + DEV_PHONE_INTL,
            'Could not open the dialer. Please call ' + DEV_PHONE_DISPLAY + ' manually.'))
        contact_row.add_widget(wa_btn)
        contact_row.add_widget(call_btn)
        contact.add_widget(contact_title)
        contact.add_widget(phone_label)
        contact.add_widget(contact_row)

        close_btn = styled_button('Close', bg_color=NAVY, icon='close', size_hint_y=None, height=dp(46))
        close_btn.bind(on_press=popup.dismiss)

        layout.add_widget(header)
        layout.add_widget(scroll)
        layout.add_widget(contact)
        layout.add_widget(close_btn)
        popup.open()

    def clear_data(self):
        save_stations([])
        self.stations = []
        if self.map:
            self.map.clear_all()
        self.ids.label_lat.text = '0.0000°'
        self.ids.label_lon.text = '0.0000°'
        show_message('All data cleared successfully.')

    def show_popup(self, *args):
        layout = FloatLayout()
        self.file_chooser = FileChooserListView(filters=['*.txt'])
        layout.add_widget(self.file_chooser)
        select = styled_button('Import File', bg_color=GREEN_BTN, icon='folder',
                               size_hint=(0.5, 0.1), pos_hint={'x': 0.25, 'y': 0.02})
        select.bind(on_press=self.select_file)
        layout.add_widget(select)
        self.import_popup = make_popup('Select Text File (lat, lon, bear, range)', layout,
                                       size_hint=(0.95, 0.9))
        self.import_popup.open()

    def select_file(self, *args):
        if not self.file_chooser.selection:
            show_message('Please select a .txt file first.')
            return
        path = self.file_chooser.selection[0]
        try:
            rows = []
            with open(path, newline='', encoding='utf-8-sig') as f:
                sample = f.read(2048)
                f.seek(0)
                delimiter = ';' if ';' in sample else ','
                reader = csv.DictReader(f, delimiter=delimiter)
                reader.fieldnames = [h.strip().lower() for h in (reader.fieldnames or [])]
                for row in reader:
                    rows.append((float(row['lat']), float(row['lon']), float(row['bear']), float(row['rangge'])))
            if not rows:
                raise ValueError('File is empty or invalid format')
            
            save_stations(rows)
            self.stations = rows
            self.import_popup.dismiss()
            Clock.schedule_once(lambda dt: self.refresh_map(), 0.05)
            show_message(f'Imported {len(rows)} lines successfully!')
        except Exception as e:
            show_message(f'Error reading file:\n{e}')

def to_float(text):
    return float(text.strip().replace(',', '.'))

# ---- ملف التصميم (KV) ----------------------------------------------------
KV = '''
<NumInput>:
    hint_text: '0'
    multiline: False
    write_tab: False
    halign: 'left'
    font_size: '14sp'
    padding: ('3dp', '5dp')
    background_normal: ''
    background_active: ''
    # Opaque background identical to the panel colour: a transparent one
    # rendered as a black block while the field had focus.
    background_color: (0.90, 0.92, 0.94, 1)
    foreground_color: (0.06, 0.09, 0.14, 1)
    hint_text_color: (0.06, 0.09, 0.14, 0.78)
    cursor_color: (0.05, 0.45, 0.8, 1)
    selection_color: (0.35, 0.62, 0.92, 0.45)
    # No cut/copy/paste bubble or drag handles on numeric fields.
    use_bubble: False
    use_handles: False

<BubbleButton>:
    # Cut / Copy / Paste bubble (used by the licence code field): the generic
    # Button rule made it white-on-white, so give it a dark face.
    background_color: (0.05, 0.15, 0.26, 1)
    color: (1, 1, 1, 1)
    font_size: '14sp'

<FieldCell>:
    orientation: 'vertical'
    padding: ('7dp', '5dp', '4dp', '1dp')
    canvas.after:
        Color:
            rgba: (0.62, 0.66, 0.72, 1 if self.show_div else 0)
        Line:
            points: [self.right, self.y + dp(10), self.right, self.top - dp(10)]
            width: 1

<IconButton>:
    background_normal: ''
    background_down: ''
    border: (0, 0, 0, 0)
    canvas.before:
        # Subtle offset shadow gives each button a raised, tactile look.
        Color:
            rgba: (0.005, 0.012, 0.02, 0.9)
        RoundedRectangle:
            pos: (self.x, self.y - dp(3))
            size: (self.width, self.height + dp(1))
            radius: [dp(14), dp(14), dp(14), dp(14)]
        # Main face (rounded corners)
        Color:
            rgba: self.face_color
        RoundedRectangle:
            pos: (self.x, self.y + dp(1))
            size: (self.width, max(dp(1), self.height - dp(3)))
            radius: [dp(14), dp(14), dp(14), dp(14)]
        # Thin border in a lighter tone of the button colour
        Color:
            rgba: (min(1.0, self.face_color[0] * 1.8 + 0.10), min(1.0, self.face_color[1] * 1.8 + 0.10), min(1.0, self.face_color[2] * 1.8 + 0.10), 0.85)
        Line:
            rounded_rectangle: (self.x, self.y + dp(1), self.width, max(dp(1), self.height - dp(3)), dp(14))
            width: 1.1
        # Pressed feedback
        Color:
            rgba: (1, 1, 1, 0.0 if self.state == 'normal' else 0.18)
        RoundedRectangle:
            pos: (self.x, self.y + dp(1))
            size: (self.width, max(dp(1), self.height - dp(3)))
            radius: [dp(14), dp(14), dp(14), dp(14)]

<MyWidget>:
    FloatLayout:
        canvas.before:
            Color:
                rgba: (0.012, 0.027, 0.045, 1)
            Rectangle:
                pos: self.pos
                size: self.size
        BoxLayout:
            orientation: 'vertical'
            spacing: '8dp'
            padding: '8dp'

            # ---- top bar -------------------------------------------------
            GridLayout:
                cols: 3
                size_hint_y: None
                height: '52dp'
                spacing: '8dp'
                IconButton:
                    caption: 'Menu'
                    icon: 'menu'
                    background_color: (0.05, 0.15, 0.26, 1)
                    color: (0.95, 0.98, 1, 1)
                    icon_color: (0.95, 0.98, 1, 1)
                    bold: True
                    font_size: '15sp'
                    on_press: root.show_menu()
                IconButton:
                    caption: 'Import File'
                    icon: 'folder'
                    background_color: (0.05, 0.15, 0.26, 1)
                    color: (0.95, 0.98, 1, 1)
                    icon_color: (0.95, 0.98, 1, 1)
                    bold: True
                    font_size: '15sp'
                    on_release: root.show_popup()
                IconButton:
                    caption: 'Exit'
                    icon: 'exit'
                    background_color: (0.33, 0.07, 0.08, 1)
                    color: (1, 1, 1, 1)
                    icon_color: (1, 1, 1, 1)
                    bold: True
                    font_size: '15sp'
                    on_press: app.stop()

            # ---- input panel ---------------------------------------------
            BoxLayout:
                size_hint_y: None
                height: '66dp'
                spacing: '8dp'
                BoxLayout:
                    size_hint_x: 4.4
                    canvas.before:
                        Color:
                            rgba: (0.90, 0.92, 0.94, 1)
                        RoundedRectangle:
                            pos: self.pos
                            size: self.size
                            radius: [dp(10), dp(10), dp(10), dp(10)]
                    FieldCell:
                        BoxLayout:
                            size_hint_y: None
                            height: '18dp'
                            spacing: '3dp'
                            Icon:
                                name: 'pin'
                                color: (0.10, 0.13, 0.18, 1)
                                size_hint: None, None
                                size: '15dp', '15dp'
                                pos_hint: {'center_y': 0.5}
                            Label:
                                text: 'Lat°'
                                font_size: '10sp'
                                color: (0.25, 0.29, 0.35, 1)
                                text_size: self.size
                                halign: 'left'
                                valign: 'middle'
                                shorten: True
                                shorten_from: 'right'
                        NumInput:
                            id: input_lat
                            hint_text: '0.0000'
                    FieldCell:
                        BoxLayout:
                            size_hint_y: None
                            height: '18dp'
                            spacing: '3dp'
                            Icon:
                                name: 'pin'
                                color: (0.10, 0.13, 0.18, 1)
                                size_hint: None, None
                                size: '15dp', '15dp'
                                pos_hint: {'center_y': 0.5}
                            Label:
                                text: 'Lon°'
                                font_size: '10sp'
                                color: (0.25, 0.29, 0.35, 1)
                                text_size: self.size
                                halign: 'left'
                                valign: 'middle'
                                shorten: True
                                shorten_from: 'right'
                        NumInput:
                            id: input_lon
                            hint_text: '0.0000'
                    FieldCell:
                        BoxLayout:
                            size_hint_y: None
                            height: '18dp'
                            spacing: '3dp'
                            Icon:
                                name: 'compass'
                                color: (0.10, 0.13, 0.18, 1)
                                size_hint: None, None
                                size: '15dp', '15dp'
                                pos_hint: {'center_y': 0.5}
                            Label:
                                text: 'Bear°'
                                font_size: '10sp'
                                color: (0.25, 0.29, 0.35, 1)
                                text_size: self.size
                                halign: 'left'
                                valign: 'middle'
                                shorten: True
                                shorten_from: 'right'
                        NumInput:
                            id: input_brg
                            hint_text: '0.0'
                    FieldCell:
                        show_div: False
                        BoxLayout:
                            size_hint_y: None
                            height: '18dp'
                            spacing: '3dp'
                            Icon:
                                name: 'ruler'
                                color: (0.10, 0.13, 0.18, 1)
                                size_hint: None, None
                                size: '15dp', '15dp'
                                pos_hint: {'center_y': 0.5}
                            Label:
                                text: 'Rng Km'
                                font_size: '10sp'
                                color: (0.25, 0.29, 0.35, 1)
                                text_size: self.size
                                halign: 'left'
                                valign: 'middle'
                                shorten: True
                                shorten_from: 'right'
                        NumInput:
                            id: input_rng
                            hint_text: '0.00'
                IconButton:
                    caption: 'Add'
                    icon: 'plus'
                    icon_dp: 16
                    background_color: (0.02, 0.36, 0.19, 1)
                    color: (1, 1, 1, 1)
                    icon_color: (1, 1, 1, 1)
                    bold: True
                    font_size: '15sp'
                    size_hint_x: 1.15
                    on_press: root.add_line()

            # ---- map -----------------------------------------------------
            MyMapView:
                id: map
                size_hint_y: 0.65
                lat: 36.5
                lon: 6.5
                zoom: 8

            # ---- coordinates bar -----------------------------------------
            BoxLayout:
                size_hint_y: None
                height: '72dp'
                spacing: '4dp'
                padding: ('8dp', '6dp', '6dp', '6dp')
                canvas.before:
                    Color:
                        rgba: (0.035, 0.075, 0.115, 1)
                    RoundedRectangle:
                        size: self.size
                        pos: self.pos
                        radius: [dp(12), dp(12), dp(12), dp(12)]
                    Color:
                        rgba: (0.14, 0.27, 0.38, 1)
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, dp(12))
                        width: 1.1
                BoxLayout:
                    size_hint_x: 1.2
                    spacing: '5dp'
                    Icon:
                        name: 'locate'
                        color: (0.25, 0.62, 1, 1)
                        size_hint: None, None
                        size: '24dp', '24dp'
                        pos_hint: {'center_y': 0.5}
                    BoxLayout:
                        orientation: 'vertical'
                        Label:
                            text: 'Latitude'
                            font_size: '11sp'
                            color: (0.30, 0.62, 0.95, 1)
                            text_size: self.size
                            halign: 'left'
                            valign: 'bottom'
                            shorten: True
                            shorten_from: 'right'
                        Label:
                            id: label_lat
                            text: '0.0000°'
                            bold: True
                            color: (0.35, 0.72, 1, 1)
                            font_size: '16sp'
                            text_size: self.size
                            halign: 'left'
                            valign: 'top'
                            shorten: True
                            shorten_from: 'right'
                BoxLayout:
                    size_hint_x: 1.2
                    spacing: '5dp'
                    Icon:
                        name: 'pin'
                        color: (0.30, 0.82, 0.62, 1)
                        size_hint: None, None
                        size: '24dp', '24dp'
                        pos_hint: {'center_y': 0.5}
                    BoxLayout:
                        orientation: 'vertical'
                        Label:
                            text: 'Longitude'
                            font_size: '11sp'
                            color: (0.30, 0.78, 0.58, 1)
                            text_size: self.size
                            halign: 'left'
                            valign: 'bottom'
                            shorten: True
                            shorten_from: 'right'
                        Label:
                            id: label_lon
                            text: '0.0000°'
                            bold: True
                            color: (0.40, 0.88, 0.68, 1)
                            font_size: '16sp'
                            text_size: self.size
                            halign: 'left'
                            valign: 'top'
                            shorten: True
                            shorten_from: 'right'
                IconButton:
                    caption: 'Google Maps'
                    icon: 'map'
                    icon_dp: 16
                    size_hint_x: 1.0
                    background_color: (0.40, 0.18, 0.04, 1)
                    color: (1, 1, 1, 1)
                    icon_color: (1, 0.85, 0.65, 1)
                    bold: True
                    font_size: '12sp'
                    on_press: root.go_map()

            # ---- locate button -------------------------------------------
            IconButton:
                caption: 'Locate Intersection'
                center_text: True
                icon: 'locate'
                icon_dp: 28
                size_hint_y: None
                height: '66dp'
                background_color: (0.02, 0.34, 0.19, 1)
                color: (1, 1, 1, 1)
                icon_color: (1, 1, 1, 1)
                bold: True
                font_size: '19sp'
                on_press: root.locate()

        # ---- overlays drawn above the map (do not take part in the layout) ----
        Widget:
            size_hint: None, None
            pos: map.pos
            size: map.size
            canvas:
                Color:
                    rgba: (0.20, 0.45, 0.68, 1)
                Line:
                    rounded_rectangle: (self.x, self.y, self.width, self.height, dp(12))
                    width: 2
        BoxLayout:
            orientation: 'vertical'
            size_hint: None, None
            size: '44dp', '146dp'
            pos: map.x + dp(10), map.center_y - dp(55)
            spacing: '8dp'
            IconButton:
                icon: 'locate'
                icon_dp: 22
                size_hint_y: None
                height: '44dp'
                background_color: (0.04, 0.12, 0.20, 0.95)
                icon_color: (0.90, 0.96, 1, 1)
                on_release: root.center_map()
            BoxLayout:
                orientation: 'vertical'
                spacing: '2dp'
                IconButton:
                    icon: 'plus'
                    icon_dp: 18
                    background_color: (0.04, 0.12, 0.20, 0.95)
                    icon_color: (0.90, 0.96, 1, 1)
                    on_release: root.zoom_in()
                IconButton:
                    icon: 'minus'
                    icon_dp: 18
                    background_color: (0.04, 0.12, 0.20, 0.95)
                    icon_color: (0.90, 0.96, 1, 1)
                    on_release: root.zoom_out()
'''

Builder.load_string(KV)

class TriangulationApp(App):
    def build(self):
        Window.bind(on_keyboard=self.on_back_key)
        container = BoxLayout()
        container.add_widget(MyWidget())
        return container

    def on_back_key(self, window, key, *args):
        if key == 27:
            for child in Window.children:
                if isinstance(child, Popup):
                    child.dismiss()
                    return True
        return False

if __name__ == '__main__':
    _checkpoint('Starting TriangulationApp.run()')
    try:
        TriangulationApp().run()
        _checkpoint('Application event loop ended normally')
    except BaseException:
        _log_uncaught(*sys.exc_info())
        raise
