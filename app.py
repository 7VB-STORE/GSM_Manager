from flask import Flask, Response, jsonify, request
from pathlib import Path
import threading
import time
import json
import re
import os
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import zipfile
import shutil
import datetime
import sys
import base64
import gzip
import zlib
import hashlib
import hmac
import shlex
import winreg
import psutil
import pickle
import ctypes
from ctypes import wintypes
from html import unescape as html_unescape
from html.parser import HTMLParser

try:
    import pyperclip
except Exception:
    pyperclip = None

try:
    import pyautogui
except Exception:
    pyautogui = None


app = Flask(__name__)
WEBVIEW_DEBUG_PORT = None

BASE_DIR = Path(__file__).resolve().parent
LOGPASS_FILE = BASE_DIR / "logpass.txt"
MAFILES_DIR = BASE_DIR / "maFiles"
HISTORY_FILE = BASE_DIR / "history.log"
AUTH_CACHE_FILE = BASE_DIR / "account_cache.json"
FX_CACHE_FILE = BASE_DIR / "fx_rates.json"
MARKED_FILE = BASE_DIR / "marked_accounts.json"
REMOVED_FILE = BASE_DIR / "removed.txt"
TRADE_LINK_FILE = BASE_DIR / "saved_trade_link.json"
WINDOW_POSITION_FILE = BASE_DIR / "window_position.json"
SESSIONS_DIR = BASE_DIR / "sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
STEAM_API_KEY_FILE = SESSIONS_DIR / "steam_api.key"


# ---------------------------------------------------------------------------
# Encrypted Steam refresh-token sessions (.pkl)
# ---------------------------------------------------------------------------
def _session_path(login):
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(login or "").strip())
    return SESSIONS_DIR / ((safe or "steam_account") + ".pkl")


def _dpapi_protect(data: bytes) -> bytes:
    """Windows DPAPI encryption: the .pkl can be decrypted only by this Windows user."""
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    src_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    src = DATA_BLOB(len(data), src_buf)
    dst = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(dst)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(dst.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    src_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    src = DATA_BLOB(len(data), src_buf)
    dst = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(dst)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(dst.pbData)


def save_steam_session(login, refresh_token, steamid=""):
    token = str(refresh_token or "").strip()
    if not token:
        return False
    try:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        payload = {"version":1, "login":str(login or "").strip(), "steamid":str(steamid or "").strip(), "refresh_token":token, "saved_at":int(time.time())}
        encrypted = _dpapi_protect(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
        path = _session_path(login)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(encrypted)
        tmp.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return True
    except Exception as exc:
        log_event("Не удалось сохранить зашифрованную Steam-сессию: " + str(exc), "WARN", login)
        return False


def load_steam_session(login):
    path = _session_path(login)
    try:
        if not path.exists():
            return None
        payload = pickle.loads(_dpapi_unprotect(path.read_bytes()))
        if not isinstance(payload, dict):
            return None
        if not str(payload.get("refresh_token") or "").strip():
            return None
        return payload
    except Exception as exc:
        log_event("Зашифрованная Steam-сессия недоступна: " + str(exc), "WARN", login)
        return None


def delete_steam_session(login):
    try:
        _session_path(login).unlink(missing_ok=True)
    except OSError:
        pass


def _web_session_path(login):
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(login or "").strip())
    return SESSIONS_DIR / ((safe or "steam_account") + ".web")


def save_steam_web_cookies(login, cookies):
    values = [str(cookie).strip() for cookie in (cookies or []) if str(cookie).strip()]
    if not values:
        return False
    try:
        encrypted = _dpapi_protect(json.dumps(values).encode("utf-8"))
        path = _web_session_path(login)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(encrypted)
        tmp.replace(path)
        return True
    except Exception as exc:
        log_event("Не удалось сохранить Steam web-сессию: " + str(exc), "WARN", login)
        return False


def load_steam_web_cookies(login):
    try:
        path = _web_session_path(login)
        if not path.exists():
            return []
        values = json.loads(_dpapi_unprotect(path.read_bytes()).decode("utf-8"))
        return [str(value) for value in values if isinstance(value, str)] if isinstance(values, list) else []
    except Exception:
        return []


def log_event(message, level="INFO", login=""):
    """Append a timestamped event to history.log without exposing passwords/secrets."""
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        if login:
            prefix += f" [{login}]"
        line = prefix + " " + str(message).replace("\r", " ").replace("\n", " ")
        with HISTORY_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def read_history():
    """Read the complete local history log for the History window."""
    try:
        if not HISTORY_FILE.exists():
            return "", 0
        text = HISTORY_FILE.read_text(encoding="utf-8", errors="replace")
        return text, len(text.splitlines()) if text else 0
    except OSError as exc:
        return "Ошибка чтения history.log: " + str(exc), 0


def load_account_cache():
    """Load non-secret account UI data so balances/avatars survive app restarts."""
    try:
        if not AUTH_CACHE_FILE.exists():
            return {}
        data = json.loads(AUTH_CACHE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        return data
    except (OSError, ValueError, TypeError):
        return {}


def save_account_cache():
    """Persist only safe UI data; never store passwords or Steam shared secrets."""
    try:
        payload = {}
        with AUTH_LOCK:
            for login, state in AUTH_STATE.items():
                payload[login] = {
                    "auth_status": state.get("auth_status", "idle"),
                    "auth_error": state.get("auth_error", ""),
                    "balance": state.get("balance", ""),
                    "avatar_url": state.get("avatar_url"),
                    "steamid": state.get("steamid", ""),
                    "currency": state.get("currency", ""),
                    "country": state.get("country", ""),
                    "games": state.get("games", []),
                    "games_count": state.get("games_count", len(state.get("games", [])) if isinstance(state.get("games", []), list) else 0),
                    "games_updated": state.get("games_updated", ""),
                    "card_games": state.get("card_games", []),
                    "level": state.get("level"),
                    "xp": state.get("xp"),
                    "level_updated": state.get("level_updated", ""),
                    "community_banned": bool(state.get("community_banned", False)),
                    "vac_banned": bool(state.get("vac_banned", False)),
                    "game_banned": bool(state.get("game_banned", False)),
                    "limited_account": bool(state.get("limited_account", False)),
                    "trade_banned": bool(state.get("trade_banned", False)),
                    "trade_hold": bool(state.get("trade_hold", False)),
                    "market_hold": bool(state.get("market_hold", False)),
                    "bans_updated": state.get("bans_updated", ""),
                }
        tmp = AUTH_CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(AUTH_CACHE_FILE)
    except (OSError, TypeError, ValueError):
        pass

# ---------------------------------------------------------------------------
# Persistent account marks (safe UI metadata only)
# ---------------------------------------------------------------------------
MARKED_LOCK = threading.RLock()


def load_marked_accounts():
    try:
        if not MARKED_FILE.exists():
            return set()
        data = json.loads(MARKED_FILE.read_text(encoding="utf-8"))
        values = data.get("marked", []) if isinstance(data, dict) else data
        if not isinstance(values, list):
            return set()
        return {str(value).strip() for value in values if str(value).strip()}
    except (OSError, ValueError, TypeError):
        return set()


def save_marked_accounts():
    try:
        with MARKED_LOCK:
            values = sorted(MARKED_ACCOUNTS, key=str.casefold)
        payload = {"marked": values}
        tmp = MARKED_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(MARKED_FILE)
        return True
    except (OSError, TypeError, ValueError):
        return False


MARKED_ACCOUNTS = load_marked_accounts()


# ---------------------------------------------------------------------------
# Isolated Steam client launcher
# ---------------------------------------------------------------------------
STEAM_LAUNCH_LOCK = threading.RLock()
STEAM_LAUNCHES = {}  # login -> {status, message, pid, started_at}
STEAM_PROFILE_ROOT = BASE_DIR / "SteamProfiles"


def _steam_status(login, status=None, message=None, pid=None):
    login = str(login or "").strip()
    with STEAM_LAUNCH_LOCK:
        state = STEAM_LAUNCHES.setdefault(login, {
            "status": "idle", "message": "", "pid": None, "started_at": 0
        })
        if status is not None:
            state["status"] = status
        if message is not None:
            state["message"] = str(message)
        if pid is not None:
            state["pid"] = int(pid) if pid else None
        return dict(state)


def _safe_profile_name(login):
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", str(login or "").strip())
    return value[:80] or "steam_account"


STEAM_SETTINGS_FILE = BASE_DIR / "steam_settings.json"


def _saved_steam_path():
    try:
        data = json.loads(STEAM_SETTINGS_FILE.read_text(encoding="utf-8"))
        return str(data.get("steam_path") or "").strip() if isinstance(data,dict) else ""
    except (OSError,ValueError,TypeError):
        return ""


def _steam_path():
    saved = _saved_steam_path()
    path = saved or os.environ.get(
        "ACCOUNT_MANAGER_STEAM_PATH",
        r"C:\Program Files (x86)\Steam\steam.exe"
    )
    return Path(path)


def validate_steam_path(value):
    text = str(value or "").strip().strip('"').strip()
    if not text:
        raise ValueError("Укажите полный путь к steam.exe")
    path = Path(text).expanduser()
    if path.name.casefold() != "steam.exe":
        raise ValueError("Путь должен указывать именно на steam.exe")
    if not path.is_file():
        raise ValueError("Файл steam.exe не найден по указанному пути")
    return path


def _steam_window_processes(pid):
    """Return visible top-level windows belonging to Steam or its children."""
    try:
        import psutil
        root = psutil.Process(pid)
        pids = {root.pid}
        pids.update(child.pid for child in root.children(recursive=True))
    except Exception:
        pids = {pid}

    try:
        import win32gui
        import win32process
        windows = []

        def callback(hwnd, _):
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
                if window_pid in pids:
                    title = win32gui.GetWindowText(hwnd).strip()
                    if title:
                        windows.append((hwnd, window_pid, title))
            except Exception:
                pass
            return True

        win32gui.EnumWindows(callback, None)
        return windows
    except Exception:
        return []


def _fill_steam_login_window(pid, login, password, guard_code=None):
    """
    Drive the normal Steam sign-in window only. No Steam token is injected.
    The account data remains local to this worker and is never returned by API.
    """
    try:
        from pywinauto import Application
        import win32gui
        import win32con
    except Exception as exc:
        raise RuntimeError("Для запуска Steam нужен pywinauto/pywin32: " + str(exc))

    windows = _steam_window_processes(pid)
    for hwnd, window_pid, _title in windows:
        try:
            app_ui = Application(backend="uia").connect(process=window_pid)
            for win in app_ui.windows():
                try:
                    descendants = win.descendants()
                    edits = [
                        c for c in descendants
                        if c.friendly_class_name() == "Edit"
                        and c.is_visible() and c.is_enabled()
                    ]
                    buttons = [
                        c for c in descendants
                        if c.friendly_class_name() == "Button"
                    ]
                    statics = [
                        c for c in descendants
                        if c.friendly_class_name() == "Static"
                    ]

                    sign_in = next(
                        (b for b in buttons if b.window_text().strip().lower() == "sign in"),
                        None
                    )
                    if len(edits) >= 2 and sign_in is not None:
                        edits[0].set_text(login)
                        edits[1].set_text(password)
                        sign_in.click_input()
                        time.sleep(1.5)
                        return True

                    code_prompt = any(
                        "Enter the code from your Steam Mobile App" in
                        s.window_text().strip() for s in statics
                    )
                    if code_prompt and guard_code:
                        target = next(
                            (e for e in edits if e.is_visible() and e.is_enabled()),
                            None
                        )
                        if target is not None:
                            target.set_text(guard_code)
                            time.sleep(0.5)
                            return True

                    # Newer Steam login UI may expose "Enter a code instead".
                    target = next(
                        (s for s in statics if s.window_text().strip() == "Enter a code instead"),
                        None
                    )
                    if target is not None:
                        target.click_input()
                        time.sleep(0.4)
                        return True

                except Exception:
                    continue
        except Exception:
            continue
    return False



def _set_steam_autologin_user(login):
    """Set Steam's local AutoLoginUser value, matching the existing panel flow."""
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as key:
            winreg.SetValueEx(key, "AutoLoginUser", 0, winreg.REG_SZ, str(login))
    except Exception as exc:
        log_event("Не удалось установить AutoLoginUser: " + str(exc), "WARN", login)


def _steam_process_pids(root_pid):
    """Return Steam root PID plus all child PIDs."""
    pids = [int(root_pid)]
    try:
        import psutil
        parent = psutil.Process(int(root_pid))
        pids.extend(child.pid for child in parent.children(recursive=True))
    except Exception:
        pass
    return list(dict.fromkeys(pids))


def _get_fresh_steam_auth_code(shared_secret, min_validity_seconds: int = 18):
    """Точная логика свежего Steam Guard-кода из рабочего ProcessWindowsBeforeCS."""
    min_validity_seconds = max(5, min(25, int(min_validity_seconds)))
    while True:
        now = time.time()
        seconds_left = 30 - (int(now) % 30)
        if seconds_left <= min_validity_seconds:
            time.sleep(seconds_left + 0.15)
            continue
        code = generate_steam_guard_code(shared_secret)
        if code == generate_steam_guard_code(shared_secret):
            return code
        time.sleep(0.1)


def launch_isolated_steam(account_name: str, steam_path: str | Path, extra_args: list[str] | None = None) -> subprocess.Popen:
    """Запускает отдельную копию Steam в изолированном PanelData-профиле."""
    steam_path = Path(steam_path)
    safe_name = _safe_profile_name(account_name)
    base_profile = (
        Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        / "PanelData"
        / safe_name
    )
    local_path = base_profile / "AppData" / "Local"
    locallow_path = base_profile / "AppData" / "LocalLow"

    if local_path.exists():
        shutil.rmtree(local_path, ignore_errors=True)
    local_path.mkdir(parents=True, exist_ok=True)
    locallow_path.mkdir(parents=True, exist_ok=True)

    # NVIDIA cache/данные доступны из изолированного LOCALAPPDATA.
    try:
        original_local = Path(os.environ.get("LOCALAPPDATA", ""))
        nvidia_src = original_local / "NVIDIA"
        nvidia_dest = local_path / "NVIDIA"
        if nvidia_dest.exists() or nvidia_dest.is_symlink():
            try:
                if nvidia_dest.is_dir() and not nvidia_dest.is_symlink():
                    shutil.rmtree(nvidia_dest, ignore_errors=True)
                else:
                    nvidia_dest.unlink(missing_ok=True)
            except Exception:
                pass
        if nvidia_src.exists():
            subprocess.run(
                ["cmd", "/c", "mklink", "/D", str(nvidia_dest), str(nvidia_src)],
                creationflags=0x08000000,
                check=False,
            )
    except Exception:
        pass

    env = os.environ.copy()
    env["USERPROFILE"] = str(base_profile)
    env["LOCALAPPDATA"] = str(local_path)

    args = [
        str(steam_path),
        "-master_ipc_name_override",
        safe_name,
        "-nosingleinstance",
        "-silent",
    ]
    if extra_args:
        args.extend(extra_args)

    return subprocess.Popen(
        args,
        env=env,
        cwd=str(steam_path.parent),
        creationflags=0x08000000,
    )


def _steam_process_pids(root_pid: int) -> list[int]:
    """Возвращает PID Steam и всех дочерних процессов, как в рабочем коде."""
    pids = [int(root_pid)]
    try:
        parent = psutil.Process(int(root_pid))
        children = parent.children(recursive=True)
        pids.extend(child.pid for child in children)
    except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
        pass
    return list(dict.fromkeys(pids))


def _window_texts(win):
    """Безопасно получает элементы UI окна Steam."""
    descendants = win.descendants()
    edits = []
    buttons = []
    statics = []
    for control in descendants:
        try:
            cls = control.friendly_class_name()
            if cls == "Edit":
                edits.append(control)
            elif cls == "Button":
                buttons.append(control)
            elif cls == "Static":
                statics.append(control)
        except Exception:
            continue
    return edits, buttons, statics


def _set_edit_text(control, value: str) -> bool:
    """Пытается заполнить Edit через UIA, затем через clipboard Ctrl+A/Ctrl+V."""
    try:
        control.click_input()
    except Exception:
        try:
            control.set_focus()
        except Exception:
            pass

    try:
        control.set_edit_text(str(value))
        return True
    except Exception:
        pass

    try:
        control.set_text(str(value))
        return True
    except Exception:
        pass

    if pyperclip is not None and pyautogui is not None:
        try:
            pyperclip.copy(str(value))
            pyautogui.hotkey("ctrl", "a")
            pyautogui.hotkey("ctrl", "v")
            return True
        except Exception:
            pass
    return False


def _click_steam_button(win, button, force_foreground=False) -> bool:
    """Клик по Steam-кнопке с тем же защитным фокусом, что в рабочем коде."""
    try:
        hwnd = int(win.handle)
    except Exception:
        hwnd = 0

    try:
        if force_foreground and hwnd:
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            win32gui.SetWindowPos(
                hwnd,
                win32con.HWND_TOPMOST,
                0, 0, 0, 0,
                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW,
            )
            try:
                win32gui.SetForegroundWindow(hwnd)
            except Exception:
                pass
            time.sleep(0.1)

        try:
            button.click_input()
        except Exception:
            button.click()
        return True
    except Exception:
        return False
    finally:
        if force_foreground and hwnd:
            try:
                win32gui.SetWindowPos(
                    hwnd,
                    win32con.HWND_NOTOPMOST,
                    0, 0, 0, 0,
                    win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW,
                )
            except Exception:
                pass


def _process_steam_login_windows(root_pid, login, password, shared_secret=None, submit_login=True, guard_attempted=False):
    """
    Полный Steam UI login flow из рабочего Account-кода:
    login/password -> Enter a code instead -> Steam Guard -> Play anyway/Continue/No thanks.

    Секреты и пароль никогда не печатаются в лог.
    """
    try:
        from pywinauto import Application, findwindows
        import win32con
        import win32gui
    except Exception as exc:
        raise RuntimeError("Для автоматического входа нужны pywinauto и pywin32: " + str(exc))

    handled = False
    guard_entered = False

    for pid in _steam_process_pids(root_pid):
        try:
            # В отличие от старой версии НЕ исключаем окно с заголовком "Steam".
            # У новых версий Steam auth-окно часто имеет именно такой title.
            windows = findwindows.find_windows(process=pid)
            if not windows:
                continue

            app = Application(backend="uia").connect(process=pid)
            for win in app.windows():
                try:
                    edits, buttons, statics = _window_texts(win)
                    button_texts = [str(b.window_text()).strip() for b in buttons]
                    static_texts = [str(x.window_text()).strip() for x in statics]

                    # ---------------------------------------------------------
                    # 1. Логин + пароль
                    # ---------------------------------------------------------
                    sign_in = next((b for b in buttons if str(b.window_text()).strip().casefold() == "sign in"), None)
                    if submit_login and sign_in is not None and len(edits) >= 2:
                        # Заполняем форму ОДИН раз. Раньше цикл каждые ~0.75 сек
                        # снова видел ту же форму и повторно нажимал Sign in.
                        if not _set_edit_text(edits[0], login):
                            print(f"[{login}] Steam: не удалось заполнить поле логина")
                            continue
                        if not _set_edit_text(edits[1], password):
                            print(f"[{login}] Steam: не удалось заполнить поле пароля")
                            continue

                        submitted = False

                        # Steam принимает Enter из поля пароля. Это предпочтительный
                        # способ: после заполнения не нужно искать/кликать кнопку
                        # повторно на каждом проходе цикла.
                        if pyautogui is not None:
                            try:
                                pyautogui.press("enter")
                                submitted = True
                                print(f"[{login}] Steam: форма входа отправлена Enter")
                            except Exception:
                                pass

                        # Если Enter не удалось отправить — один раз кликаем Sign in.
                        if not submitted:
                            submitted = _click_steam_button(win, sign_in, force_foreground=True)
                            if submitted:
                                print(f"[{login}] Steam: Sign in нажата")

                        if submitted:
                            handled = True
                            time.sleep(2)
                            # UI мог полностью обновиться — перечитываем элементы.
                            try:
                                edits, buttons, statics = _window_texts(win)
                            except Exception:
                                pass

                    # ---------------------------------------------------------
                    # 2. Переключение на ввод кода вместо подтверждения
                    # ---------------------------------------------------------
                    enter_code_instead = next(
                        (x for x in statics if str(x.window_text()).strip().casefold() == "enter a code instead"),
                        None,
                    )
                    if enter_code_instead is not None:
                        try:
                            enter_code_instead.click_input()
                        except Exception:
                            try:
                                enter_code_instead.click()
                            except Exception:
                                pass
                        handled = True
                        time.sleep(0.5)
                        edits, buttons, statics = _window_texts(win)

                    # ---------------------------------------------------------
                    # 3. Steam Guard из shared_secret maFile
                    # ---------------------------------------------------------
                    guard_prompt = any(
                        str(x.window_text()).strip().casefold()
                        in {
                            "enter the code from your steam mobile app",
                            "enter the code from your steam mobile authenticator",
                            "введите код из мобильного приложения steam",
                            "введите код из мобильного аутентификатора steam",
                        }
                        for x in statics
                    )

                    if guard_prompt and shared_secret and not guard_entered and not guard_attempted:
                        code = generate_steam_guard_code(shared_secret)
                        try:
                            # ВАЖНО: это окно Steam использует web/custom controls.
                            # На скриншоте видно 5 отдельных визуальных ячеек, но UIA
                            # не отдаёт их как обычный Edit. Поэтому отсутствие Edit
                            # НЕ означает отсутствие поля. Сначала пробуем UIA, затем
                            # кликаем по первой ячейке координатно и вставляем весь код
                            # через clipboard + Ctrl+V.
                            target_edit = next(
                                (e for e in edits if e.is_enabled() and e.is_visible()),
                                None,
                            )
                            entered = False

                            if target_edit is not None:
                                try:
                                    target_edit.click_input()
                                except Exception:
                                    try:
                                        target_edit.set_focus()
                                    except Exception:
                                        pass
                                try:
                                    target_edit.set_edit_text(code)
                                    entered = True
                                except Exception:
                                    try:
                                        target_edit.set_text(code)
                                        entered = True
                                    except Exception:
                                        pass

                            # Надёжный fallback для текущего Steam Guard UI:
                            # окно имеет фиксированный auth-layout, а поле кода находится
                            # примерно на 32.3% ширины и 45.9% высоты client-area.
                            # Кликаем первую ячейку, затем вставляем весь код одним Ctrl+V.
                            if not entered and pyautogui is not None and pyperclip is not None:
                                try:
                                    hwnd = int(win.handle)
                                    left, top, right, bottom = win32gui.GetWindowRect(hwnd)
                                    width = max(1, right - left)
                                    height = max(1, bottom - top)

                                    # Для данного Steam auth окна: первая ячейка
                                    # находится около x=0.323, y=0.459.
                                    click_x = int(left + width * 0.323)
                                    click_y = int(top + height * 0.459)

                                    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                                    win32gui.SetForegroundWindow(hwnd)
                                    time.sleep(0.15)
                                    pyautogui.click(click_x, click_y)
                                    time.sleep(0.08)

                                    pyperclip.copy(code)
                                    time.sleep(0.08)
                                    pyautogui.hotkey("ctrl", "a")
                                    time.sleep(0.05)
                                    pyautogui.hotkey("ctrl", "v")
                                    time.sleep(0.35)
                                    entered = True
                                    print(f"[{login}] Steam Guard: поле найдено по координатам, код вставлен через Ctrl+V")
                                except Exception as coord_exc:
                                    print(f"[{login}] Steam Guard: координатный ввод не сработал: {coord_exc}")

                            if not entered:
                                raise RuntimeError("поле Steam Guard не найдено через UIA и координатный fallback")

                            print(f"[{login}] Steam Guard: код введён")
                            guard_entered = True
                            guard_attempted = True
                            handled = True

                            # Подтверждаем код после вставки.
                            if pyautogui is not None:
                                try:
                                    pyautogui.press("enter")
                                except Exception:
                                    pass
                        except Exception as exc:
                            print(f"[{login}] Steam Guard: не удалось ввести код: {exc}")

                    # ---------------------------------------------------------
                    # 4. Play anyway
                    # ---------------------------------------------------------
                    play_anyway = next(
                        (b for b in buttons if str(b.window_text()).strip().casefold() == "play anyway"),
                        None,
                    )
                    if play_anyway is not None:
                        if _click_steam_button(win, play_anyway, force_foreground=True):
                            handled = True
                            print(f"[{login}] Steam: Play anyway нажата")
                            time.sleep(2)
                            # В рабочем коде выполнялась повторная проверка этой кнопки.
                            try:
                                _, fresh_buttons, _ = _window_texts(win)
                                repeat = next(
                                    (b for b in fresh_buttons if str(b.window_text()).strip().casefold() == "play anyway"),
                                    None,
                                )
                                if repeat is not None:
                                    _click_steam_button(win, repeat, force_foreground=True)
                            except Exception:
                                pass

                    # ---------------------------------------------------------
                    # 5. Continue
                    # ---------------------------------------------------------
                    continue_button = next(
                        (b for b in buttons if str(b.window_text()).strip().casefold() == "continue"),
                        None,
                    )
                    if continue_button is not None:
                        if _click_steam_button(win, continue_button, force_foreground=True):
                            handled = True
                            print(f"[{login}] Steam: Continue нажата")
                            time.sleep(2)
                            try:
                                _, fresh_buttons, _ = _window_texts(win)
                                repeat = next(
                                    (b for b in fresh_buttons if str(b.window_text()).strip().casefold() == "continue"),
                                    None,
                                )
                                if repeat is not None:
                                    _click_steam_button(win, repeat, force_foreground=True)
                            except Exception:
                                pass

                    # ---------------------------------------------------------
                    # 6. No thanks
                    # ---------------------------------------------------------
                    no_thanks = next(
                        (b for b in buttons if str(b.window_text()).strip().casefold() == "no thanks"),
                        None,
                    )
                    if no_thanks is not None:
                        if _click_steam_button(win, no_thanks, force_foreground=False):
                            handled = True
                            print(f"[{login}] Steam: No thanks нажата")

                except Exception as exc:
                    print(f"[{login}] Steam UI PID {pid}: {exc}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
            continue
        except Exception as exc:
            print(f"[{login}] Не удалось обработать Steam PID {pid}: {exc}")

    return handled


def _steam_ui_state(root_pid):
    """Проверяет состояние auth UI без вывода секретных данных."""
    state = {
        "login_form": False,
        "guard": False,
        "signin": False,
        "windows": 0,
    }
    try:
        from pywinauto import Application, findwindows
        for pid in _steam_process_pids(root_pid):
            try:
                if not findwindows.find_windows(process=pid):
                    continue
                app = Application(backend="uia").connect(process=pid)
                for win in app.windows():
                    try:
                        state["windows"] += 1
                        edits, buttons, statics = _window_texts(win)
                        btn_texts = {str(b.window_text()).strip().casefold() for b in buttons}
                        static_texts = {str(x.window_text()).strip().casefold() for x in statics}
                        if "sign in" in btn_texts and len(edits) >= 2:
                            state["login_form"] = True
                            state["signin"] = True
                        if (
                            "enter the code from your steam mobile app" in static_texts
                            or "enter the code from your steam mobile authenticator" in static_texts
                        ):
                            state["guard"] = True
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return state


def _steam_login_worker(login):
    """Steam auth worker: same polling model as the supplied working code."""
    login = str(login or "").strip()
    if not login:
        return

    try:
        creds = find_account_credentials(login)
        if not creds:
            _steam_status(login, "error", "Аккаунт не найден в logpass.txt")
            return

        account_login, password = creds
        steam_path = _steam_path()
        if not steam_path.is_file() or steam_path.suffix.lower() != ".exe":
            _steam_status(login, "error", "Некорректный SteamPath: " + str(steam_path))
            return

        ma = find_mafile_data(login) or {}
        shared_secret = ma.get("shared_secret")
        if not shared_secret:
            _steam_status(login, "error", "Для аккаунта не найден shared_secret в maFiles")
            return

        _set_steam_autologin_user(account_login)
        _steam_status(login, "starting", "Запуск Steam...")

        # Точно тот же набор аргументов, что был в рабочем StartSteamOnly.
        self_proc = launch_isolated_steam(
            account_login,
            steam_path,
            ["-nofriendsui", "-vgui", "-noreactlogin"],
        )
        pid = int(self_proc.pid)
        _steam_status(login, "login", "Steam открыт, выполняется вход...", pid)

        # В исходнике ProcessWindowsBeforeCS вызывается каждые 0.75 сек.
        # Делаем то же самое, но дольше, чтобы Steam успел создать дочерние окна.
        deadline = time.time() + 90
        action_seen = False
        last_state = None
        login_submit_attempted = False
        guard_attempted = False

        while time.time() < deadline:
            if self_proc.poll() is not None:
                _steam_status(login, "error", "Steam завершился во время авторизации", pid)
                return

            try:
                state = _steam_ui_state(pid)
                last_state = state
                if state.get("login_form"):
                    _steam_status(login, "login", "Steam: найдено окно авторизации...", pid)

                handled = _process_steam_login_windows(
                    pid,
                    account_login,
                    password,
                    shared_secret,
                    submit_login=not login_submit_attempted,
                    guard_attempted=guard_attempted,
                )
                if handled:
                    action_seen = True
                    # После первой успешной отправки формы больше не трогаем
                    # логин/пароль, пока Steam сам не покажет следующий экран.
                    # Это предотвращает бесконечное повторное нажатие Sign in.
                    if not login_submit_attempted and state.get("login_form"):
                        login_submit_attempted = True

                # После клика Steam может полностью пересоздать окно.
                time.sleep(0.75)

                state_after = _steam_ui_state(pid)
                if action_seen and not state_after.get("login_form") and not state_after.get("guard"):
                    # Не завершаем мгновенно: даём Steam сохранить сессию.
                    time.sleep(1.5)
                    final_state = _steam_ui_state(pid)
                    if not final_state.get("login_form") and not final_state.get("guard"):
                        _steam_status(login, "running", "Steam авторизован и запущен", pid)
                        log_event("Steam авторизация завершена", "INFO", login)
                        start_authorization(login)
                        return

                if state_after.get("guard"):
                    _steam_status(login, "login", "Steam: ожидается/вводится Steam Guard...", pid)
                elif action_seen:
                    _steam_status(login, "login", "Steam: авторизация продолжается...", pid)
                else:
                    _steam_status(login, "login", "Steam открыт, ищем окно входа...", pid)

            except Exception as exc:
                log_event("Steam UI cycle: " + str(exc), "WARNING", login)

            time.sleep(0.1)

        final_state = _steam_ui_state(pid)
        if not final_state.get("login_form") and not final_state.get("guard"):
            _steam_status(login, "running", "Steam запущен", pid)
            log_event("Steam запущен без видимой формы авторизации", "INFO", login)
            start_authorization(login)
        else:
            _steam_status(login, "error", "Не удалось автоматически пройти окно авторизации Steam", pid)
            log_event("Steam auth timeout; окно авторизации осталось", "ERROR", login)

    except Exception as exc:
        _steam_status(login, "error", str(exc))
        log_event("Steam launcher exception: " + str(exc), "ERROR", login)


def start_steam_isolated(login):
    login = str(login or "").strip()
    if not login:
        return False, "Пустой логин"

    with STEAM_LAUNCH_LOCK:
        # Also discovers clients started by a previous manager instance.
        if steam_process_alive(login):
            return False, "Steam уже запущен для этого аккаунта"

        state = STEAM_LAUNCHES.setdefault(login, {})
        state.update({
            "status": "queued",
            "message": "Подготовка...",
            "pid": None,
            "started_at": time.time()
        })

    threading.Thread(
        target=_steam_login_worker,
        args=(login,),
        daemon=True,
        name="SteamLaunch-" + _safe_profile_name(login)
    ).start()
    return True, "Запуск Steam начат"


@app.route("/api/steam/launch/<path:login>", methods=["POST"])
def api_steam_launch(login):
    ok, message = start_steam_isolated(login)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 409)


@app.route("/api/steam/status/<path:login>")
def api_steam_status(login):
    steam_process_alive(login)
    return jsonify({"ok": True, **_steam_status(login)})



STEAM_QUEUE_LOCK = threading.Lock()
AUTO_ACCEPT_LOCK = threading.Lock()


def steam_launch_queue_worker(logins, delay):
    try:
        for index, login in enumerate(logins):
            ok, message = start_steam_isolated(login)
            log_event("Очередь: "+str(index+1)+"/"+str(len(logins))+" — "+message, "INFO" if ok else "WARN", login)
            if ok:
                deadline = time.time() + 125
                while time.time() < deadline:
                    state = _steam_status(login)
                    if state.get("status") in ("running", "error"):
                        break
                    time.sleep(1)
            if index + 1 < len(logins):
                time.sleep(delay)
    finally:
        STEAM_QUEUE_LOCK.release()


@app.route("/api/steam/queue", methods=["POST"])
def api_steam_queue():
    data = request.get_json(silent=True) or {}
    logins = list(dict.fromkeys(str(v).strip() for v in data.get("logins", []) if str(v).strip()))
    delay = max(1, min(120, int(data.get("delay", 5) or 5)))
    if not logins:
        return jsonify({"ok":False,"message":"Выберите аккаунты."}), 400
    if not STEAM_QUEUE_LOCK.acquire(blocking=False):
        return jsonify({"ok":False,"message":"Очередь запуска уже выполняется."}), 409
    threading.Thread(target=steam_launch_queue_worker, args=(logins, delay), daemon=True, name="SteamLaunchQueue").start()
    return jsonify({"ok":True,"message":"Очередь запущена: "+str(len(logins))+" аккаунтов, пауза "+str(delay)+" сек."})


@app.route("/api/steam/close-selected", methods=["POST"])
def api_close_selected_steam():
    data = request.get_json(silent=True) or {}
    logins = list(dict.fromkeys(str(v).strip() for v in data.get("logins", []) if str(v).strip()))
    closed = 0
    errors = []
    for login in logins:
        with STEAM_LAUNCH_LOCK:
            pid = (STEAM_LAUNCHES.get(login) or {}).get("pid")
        if not pid:
            continue
        try:
            parent = psutil.Process(int(pid))
            children = parent.children(recursive=True)
            for proc in reversed(children):
                try: proc.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            parent.terminate()
            _, alive = psutil.wait_procs(children + [parent], timeout=4)
            for proc in alive:
                try: proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            _steam_status(login, "idle", "Steam закрыт", 0)
            log_event("Выбранный Steam-клиент закрыт", "INFO", login)
            closed += 1
        except Exception as exc:
            errors.append(login+": "+str(exc))
    return jsonify({"ok":not errors,"closed":closed,"message":"Закрыто аккаунтов: "+str(closed)+((". "+"; ".join(errors)) if errors else "")}), (200 if not errors else 500)


def close_all_steam_processes():
    """Close all running Steam client processes without touching this application."""
    try:
        import psutil
    except Exception as exc:
        return {"ok": False, "closed": 0, "message": "psutil недоступен: " + str(exc)}

    targets = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = str(proc.info.get("name") or "").lower()
            if name.startswith("steam"):
                targets.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    closed = 0
    for proc in targets:
        try:
            proc.terminate()
            closed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if targets:
        try:
            _, alive = psutil.wait_procs(targets, timeout=3)
        except Exception:
            alive = []
        for proc in alive:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    log_event(f"Закрыты процессы Steam: {closed}", "INFO")
    return {"ok": True, "closed": closed, "message": f"Закрыто процессов Steam: {closed}"}


@app.route("/api/steam/close-all", methods=["POST"])
def api_steam_close_all():
    result = close_all_steam_processes()
    return jsonify(result), (200 if result.get("ok") else 500)


PAGE = r"""
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=1280,height=720">
<title>GSM 1.0.2</title>
<style>
*{box-sizing:border-box}
html,body{margin:0;width:100%;height:100%;overflow:hidden;background:#071013;color:#dce8e8;font-family:"Segoe UI",Arial,sans-serif}
body{user-select:none}button,input{font:inherit}
.app{width:1280px;height:720px;position:relative;overflow:hidden;background:radial-gradient(ellipse at 78% 10%,rgba(0,180,180,.13),transparent 32%),radial-gradient(ellipse at 30% 80%,rgba(20,95,105,.11),transparent 34%),linear-gradient(135deg,#081113,#061012 52%,#071417)}
.app:before{content:"";position:absolute;inset:0;opacity:.2;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(255,255,255,.018) 0,rgba(255,255,255,.018) 1px,transparent 1px,transparent 4px)}
.app:after{content:"";position:absolute;inset:0;pointer-events:none;box-shadow:inset 0 0 100px rgba(0,0,0,.55)}
.top-nav{position:absolute;left:29px;right:29px;top:13px;height:40px;display:flex;align-items:center;gap:10px;z-index:5}.top-tab{height:36px;min-width:132px;padding:0 18px;border:1px solid rgba(52,91,97,.72);border-radius:10px;background:linear-gradient(180deg,rgba(13,30,34,.96),rgba(7,18,21,.96));color:#829296;font-size:12px;font-weight:700;letter-spacing:.25px;cursor:pointer;transition:.15s;box-shadow:inset 0 1px rgba(255,255,255,.035),0 5px 16px rgba(0,0,0,.18)}.top-tab:hover{color:#d2eef0;background:linear-gradient(180deg,rgba(20,58,64,.98),rgba(10,31,35,.98));border-color:#347b84;transform:translateY(-1px)}.top-tab.active{color:#e5ffff;background:linear-gradient(180deg,rgba(22,125,133,.92),rgba(11,76,84,.92));border-color:rgba(89,220,227,.7);box-shadow:0 0 0 1px rgba(59,199,207,.12),0 6px 20px rgba(0,150,160,.16),inset 0 1px rgba(255,255,255,.08)}
.main{position:absolute;inset:0;padding:62px 29px 70px;display:grid;grid-template-columns:660px minmax(0,1fr);gap:22px;z-index:2}
.left{min-width:0;min-height:0;overflow:hidden}.stats{height:40px;display:flex;align-items:center;gap:34px;font-size:11px;color:#8d969a}.stat{display:flex;align-items:center;gap:8px}.stat strong{color:#aeb8ba}.stat.green strong{color:#6fc88c}.stat-icon{color:#788489}.stat.green .stat-icon{color:#65ce83}
.toolbar{height:46px;display:flex;align-items:center;gap:7px;width:100%;min-width:0;overflow:visible}.search{flex:0 0 126px;width:126px;height:38px;border:1px solid #176b78;border-radius:10px;background:linear-gradient(180deg,rgba(7,21,24,.96),rgba(5,15,18,.96));color:#dbe4e5;padding:0 12px;outline:none;font-size:11px;box-shadow:inset 0 1px rgba(255,255,255,.025),0 4px 14px rgba(0,0,0,.12)}.search:focus{border-color:#27c7d0;box-shadow:0 0 0 2px rgba(39,199,208,.10),inset 0 1px rgba(255,255,255,.04)}.search::placeholder{color:#809397}
.pill{flex:0 0 auto;height:38px;border:1px solid rgba(54,86,91,.72);border-radius:11px;padding:0 10px;background:linear-gradient(180deg,rgba(20,36,40,.96),rgba(13,27,30,.96));font-size:10px;font-weight:650;cursor:pointer;white-space:nowrap;box-shadow:inset 0 1px rgba(255,255,255,.035),0 4px 12px rgba(0,0,0,.12);transition:background .15s ease,border-color .15s ease,transform .12s ease,box-shadow .15s ease}.pill:hover{background:linear-gradient(180deg,rgba(27,48,53,.98),rgba(17,34,38,.98));border-color:#47747a;transform:translateY(-1px);box-shadow:0 6px 16px rgba(0,0,0,.18)}.pill:active{transform:translateY(0);box-shadow:inset 0 2px 5px rgba(0,0,0,.18)}.pill:disabled{opacity:.5;cursor:not-allowed;transform:none}.pill.blue{min-width:72px;color:#25c8ff}.pill.orange{min-width:82px;color:#f0a54b}.pill.green{min-width:108px;color:#5de083}.pill.purple{min-width:72px;color:#ce91ee}.pill.refresh-pill{min-width:86px;color:#72d3da}.selection-count{margin-left:auto;flex:0 0 auto;font-size:9px;color:#66868b;white-space:nowrap;padding-left:2px}.selection-tools,.selection-tool{display:none!important}
.account-panel{height:calc(100% - 86px);min-height:0;display:flex;flex-direction:column;border:1px solid rgba(50,80,84,.45);border-radius:4px;background:rgba(4,12,14,.42);overflow:hidden}.table-head,.account-row{display:grid;grid-template-columns:28px 30px 84px minmax(150px,1fr) 270px;align-items:center}.table-head{height:42px;padding:0 16px;color:#7f898d;font-size:10px;font-weight:600} .select-all-wrap{display:flex;align-items:center;justify-content:center}.account-check{width:18px;height:18px;border:1px solid #31565d;border-radius:6px;background:linear-gradient(145deg,#0a171a,#101f22);display:flex;align-items:center;justify-content:center;color:transparent;cursor:pointer;transition:.15s;box-shadow:inset 0 1px rgba(255,255,255,.03)}.account-check:hover{border-color:#52dbe2;transform:scale(1.04)}.account-check.checked{background:linear-gradient(145deg,#16464c,#1b7379);border-color:#55dfe5;color:#dffeff;box-shadow:0 0 12px rgba(67,218,226,.18),inset 0 1px rgba(255,255,255,.12)}.account-check svg{width:11px;height:11px;stroke:currentColor;stroke-width:2.5;fill:none;stroke-linecap:round;stroke-linejoin:round}.table-head .actions-title{text-align:right;padding-right:15px}.sortable-head{cursor:pointer;display:flex;align-items:center;gap:5px;user-select:none}.sortable-head:hover{color:#b8d7da}.sort-arrow{font-size:10px;color:#4e7479;line-height:1}.sort-arrow.active{color:#61dce2}.rows{height:auto;min-height:0;flex:1 1 auto;overflow-y:scroll;overflow-x:hidden;scrollbar-gutter:stable;overscroll-behavior:contain}.rows::-webkit-scrollbar{width:5px}.rows::-webkit-scrollbar-thumb{background:#33474b;border-radius:10px}
.account-row{min-height:52px;padding:0 16px;border-top:1px solid rgba(82,111,113,.18);background:rgba(4,13,15,.24);transition:.12s}.account-row:hover{background:rgba(23,52,56,.32)}.account-row.selected{background:rgba(24,71,76,.36);box-shadow:inset 2px 0 #2ec5cf}
.number{font-size:10px;color:#8b9698}.login-cell{min-width:0;display:flex;align-items:center;gap:9px}.avatar{width:34px;height:34px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;color:#d8eeee;font-weight:700;font-size:12px;border:1px solid rgba(100,175,181,.38);background:linear-gradient(145deg,#263b3e,#102023)}.avatar-wrap{width:34px;height:34px;flex:none;position:relative}.avatar-img{width:34px;height:34px;border-radius:50%;object-fit:cover;border:1px solid rgba(100,175,181,.38);display:block}.balance-cell{font-size:10px;color:#73d2d7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.avatar.green{background:linear-gradient(145deg,#27563f,#123024)}.avatar.red{background:linear-gradient(145deg,#6b2028,#251216)}.avatar.purple{background:linear-gradient(145deg,#4d315f,#21152b)}.avatar.blue{background:linear-gradient(145deg,#284a67,#142432)}
.login-name{min-width:0;width:115px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#b9c3c4;font-size:11px}.pass{display:none}.actions{display:flex;justify-content:flex-end;align-items:center;gap:4px;width:100%;min-width:0;padding-left:4px;box-sizing:border-box;overflow:visible}.actions .action{font-family:"Segoe UI Symbol","Segoe UI",Arial,sans-serif;font-weight:700}
.action{width:28px!important;height:28px!important;min-width:28px;min-height:28px;padding:0!important;display:flex;align-items:center;justify-content:center;font-size:14px;color:#62e0e8;cursor:pointer;border:1px solid rgba(82,116,121,.65);border-radius:8px;background:linear-gradient(145deg,rgba(18,34,37,.98),rgba(8,19,22,.98));box-shadow:inset 0 1px rgba(255,255,255,.035),0 3px 9px rgba(0,0,0,.16);transition:transform .12s ease,border-color .12s ease,background .12s ease,box-shadow .12s ease,filter .12s ease}
.action .action-icon{width:15px;height:15px;display:block;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;transition:transform .12s ease}.action .action-icon-fill{fill:currentColor;stroke:none}.action:hover .action-icon{transform:scale(1.08)}.action.busy .action-icon{animation:actionSpin 1s linear infinite}@keyframes actionSpin{to{transform:rotate(360deg)}}
.action:hover{transform:translateY(-1px);filter:brightness(1.16);border-color:rgba(100,180,187,.9);box-shadow:0 5px 13px rgba(0,0,0,.22),0 0 8px rgba(60,180,190,.08)}
.action:active{transform:translateY(1px) scale(.96);box-shadow:inset 0 2px 5px rgba(0,0,0,.3)}
.action.cyan{color:#55d9e8;border-color:rgba(85,217,232,.48);background:linear-gradient(145deg,rgba(17,47,53,.98),rgba(8,24,29,.98))}.action.blue{color:#9aa8ff;border-color:rgba(139,154,255,.46);background:linear-gradient(145deg,rgba(35,38,70,.98),rgba(17,19,39,.98))}.action.lime{color:#76dc85;border-color:rgba(118,220,133,.45)}.action.purple{color:#d487df;border-color:rgba(212,135,223,.45)}.action.green{color:#62daa0;border-color:rgba(98,218,160,.48);background:linear-gradient(145deg,rgba(18,49,39,.98),rgba(8,27,22,.98))}.action.yellow{color:#efb65c;border-color:rgba(239,182,92,.48);background:linear-gradient(145deg,rgba(55,42,22,.98),rgba(29,23,14,.98))}.action.red{color:#f07880;border-color:rgba(240,120,128,.5);background:linear-gradient(145deg,rgba(57,27,33,.98),rgba(30,16,20,.98))}
.steam-launch-action{border:1px solid rgba(74,190,117,.62);border-radius:8px;background:linear-gradient(145deg,rgba(17,48,35,.96),rgba(8,27,19,.96));color:#63dd88;font-size:15px;font-weight:800;cursor:pointer;white-space:nowrap;transition:transform .12s ease,border-color .12s ease,background .12s ease,box-shadow .12s ease}
.steam-launch-action:hover{border-color:#66e695;background:linear-gradient(145deg,rgba(24,67,47,.98),rgba(10,40,27,.98));transform:translateY(-1px);box-shadow:0 5px 14px rgba(40,190,100,.16)}
.steam-launch-action:active{transform:translateY(1px) scale(.96);box-shadow:inset 0 2px 5px rgba(0,0,0,.28)}
.steam-launch-action.running{color:#8ce9a5;border-color:#3f9c61}.steam-launch-action.busy{color:#f0c36b;border-color:#806432;animation:steamPulse 1.1s ease-in-out infinite}
@keyframes steamPulse{0%,100%{box-shadow:0 0 0 rgba(240,195,107,0)}50%{box-shadow:0 0 10px rgba(240,195,107,.14)}}
.right{min-width:0;position:relative}.right-top{height:92px;display:flex;flex-direction:column}.right-main-tabs{display:flex;align-items:center;gap:8px;height:34px;white-space:nowrap}.mode{display:flex;align-items:center;gap:7px;font-size:12px;color:#747d81;padding:8px 11px;border-radius:7px;cursor:pointer}.mode.active{color:#75cbd0;background:rgba(32,113,120,.3)}.node-download{height:28px;padding:0 11px;border:1px solid #315b63;border-radius:7px;background:#0c191c;color:#70d7de;font-size:10px;cursor:pointer;margin-left:2px}.node-download:hover{background:#163238}.node-download.installing{color:#f0b55b;border-color:#69502d}.node-download.ready{color:#69d58a;border-color:#2d6042}.game-tabs{display:flex;align-items:center;gap:8px;height:38px}.game{min-width:48px;padding:7px 11px;border-radius:16px;color:#717a7d;font-size:10px;text-align:center;cursor:pointer}.game.active{color:#d7ecee;background:rgba(32,116,139,.68)}.item-count{position:absolute;right:0;top:43px;color:#6ca4ad;font-size:10px}.inventory{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:5px;padding-top:15px}.games-panel{display:none;height:590px;padding-top:0;overflow:hidden}.games-panel.show{display:flex;flex-direction:column}.games-overview{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:8px 0 8px}.games-overview-left{min-width:0}.games-count{color:#75cbd0;font-size:9px;font-weight:700}.games-count.success{color:#72b7ff}.games-count.error{color:#ef929b}.games-updated{color:#5f777b;font-size:8px;margin-left:8px}.games-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 0 10px;border-bottom:1px solid rgba(65,100,105,.22)}.games-head-main{min-width:0}.games-title{font-size:17px;font-weight:700;color:#d9f4f5;letter-spacing:.2px}.games-sub{margin-top:3px;color:#6e8c91;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.games-head-actions{display:flex;align-items:center;gap:6px;flex:none}.games-search{width:130px;height:32px;border:1px solid #294c52;border-radius:8px;background:#081619;color:#d8e9ea;padding:0 10px;font-size:9px;outline:none}.games-search:focus{border-color:#3bc6cf}.game-target-input{width:150px;height:32px;border:1px solid #294c52;border-radius:8px;background:#081619;color:#d8e9ea;padding:0 10px;font-size:9px;outline:none}.game-target-input:focus{border-color:#3bc6cf;box-shadow:0 0 0 2px rgba(59,198,207,.08)}.game-target-input::placeholder,.games-search::placeholder{color:#60767a}.add-game-btn,.refresh-games-btn{height:32px;border:1px solid #2e6e76;border-radius:8px;background:linear-gradient(180deg,#12363b,#0b2327);color:#70dfe5;font-size:9px;font-weight:700;cursor:pointer;padding:0 10px}.add-game-btn:hover,.refresh-games-btn:hover{border-color:#52dbe2;background:#153f45}.refresh-games-btn{width:34px;padding:0;font-size:13px}.games-list{flex:1;min-height:0;overflow:auto;padding:2px 3px 8px 0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));grid-auto-rows:96px;gap:8px}.games-list::-webkit-scrollbar{width:6px}.games-list::-webkit-scrollbar-thumb{background:#33474b;border-radius:10px}.game-card{min-width:0;border:1px solid rgba(54,82,87,.55);border-radius:9px;background:linear-gradient(145deg,rgba(12,29,33,.95),rgba(7,18,21,.95));display:flex;align-items:center;gap:10px;padding:9px;transition:.12s}.game-card:hover{border-color:#3d7c83;transform:translateY(-1px)}.game-cover{width:68px;height:68px;border-radius:7px;object-fit:cover;background:#122126;flex:none}.game-cover-empty{width:68px;height:68px;border-radius:7px;background:linear-gradient(145deg,#17343a,#0b191d);display:flex;align-items:center;justify-content:center;color:#5c8d92;font-size:24px;flex:none}.game-info{min-width:0;flex:1;display:flex;flex-direction:column;justify-content:center}.game-name{color:#d5e9eb;font-size:11px;font-weight:650;line-height:1.25;white-space:normal;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}.game-id{color:#5f7d81;font-size:8px;margin-top:6px}.game-hours{color:#6fcf9a;font-size:9px;margin-top:4px;font-weight:600}.game-open{height:28px;min-width:28px;border:1px solid #315c64;border-radius:7px;background:#0d2024;color:#70cbd2;font-size:10px;cursor:pointer;flex:none}.game-open:hover{border-color:#55dbe2}.games-empty{grid-column:1/-1;padding:45px 10px;text-align:center;color:#657c80;font-size:10px}.account-row.login-selected{background:linear-gradient(90deg,rgba(25,91,97,.46),rgba(20,58,63,.26));box-shadow:inset 3px 0 #50d9df,inset 0 0 0 1px rgba(80,217,223,.08)}.account-row.login-selected .login-name{color:#e2ffff;font-weight:700}.account-row.login-selected .avatar{border-color:#54dce2;box-shadow:0 0 12px rgba(70,215,222,.12)}.functional-panel{display:none;height:590px;padding-top:15px}.functional-panel.show{display:flex;align-items:flex-start}.close-steam-btn{height:42px;padding:0 18px;border:1px solid #743e45;border-radius:8px;background:linear-gradient(145deg,rgba(73,30,36,.95),rgba(39,20,24,.95));color:#ef929b;font-size:11px;font-weight:600;cursor:pointer;transition:.15s}.close-steam-btn:hover{border-color:#b45a65;background:linear-gradient(145deg,rgba(100,39,47,.98),rgba(48,22,28,.98));box-shadow:0 5px 16px rgba(190,70,85,.14);transform:translateY(-1px)}.close-steam-btn:active{transform:translateY(1px)}.close-steam-btn.busy{color:#e7bd76;border-color:#765c32}.login-panel{display:none;padding-top:15px;height:590px;overflow:auto}.login-panel.show{display:block}.login-card{height:48px;display:flex;align-items:center;gap:10px;padding:0 12px;margin-bottom:5px;border:1px solid rgba(50,80,84,.45);border-radius:7px;background:rgba(8,19,22,.72);color:#b9c7c9}.login-card .login-index{width:28px;color:#6d8589;font-size:10px}.login-card .login-text{min-width:0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}.login-card .login-status{font-size:9px;color:#63d58a}.login-empty{padding:30px 10px;color:#718084;font-size:11px;text-align:center}.item{height:80px;border-radius:4px;border:1px solid rgba(86,69,113,.85);background:linear-gradient(145deg,rgba(33,28,47,.92),rgba(21,20,32,.92));position:relative;overflow:hidden;cursor:pointer}.item:hover{border-color:#6e72a3;transform:translateY(-1px)}.item-icon{position:absolute;left:0;right:0;top:10px;height:46px;display:flex;align-items:center;justify-content:center;color:#bda8d7;font-size:30px}.item-label{position:absolute;bottom:7px;left:4px;right:4px;text-align:center;color:#7e798b;font-size:8px}
.confirm-window{width:760px;max-width:calc(100vw - 40px);width:680px;max-width:calc(100vw - 44px);max-height:calc(100vh - 70px);overflow:hidden}.confirm-toolbar{display:flex;gap:8px;align-items:center;padding:12px 18px;border-bottom:1px solid rgba(50,80,84,.55)}.confirm-select{flex:1;height:32px;border:1px solid #31565d;border-radius:7px;background:#0a1518;color:#cfe0e2;padding:0 10px;font-size:10px;outline:none}.confirm-list{height:290px;overflow:auto;padding:10px 18px}.confirmation-loading{min-height:220px;display:flex;align-items:center;justify-content:center;gap:14px;padding:35px;color:#d5e5e8}.confirmation-loading b{display:block;font-size:12px;letter-spacing:.1px}.confirmation-loading small{display:block;margin-top:6px;color:#76959c;font-size:10px}.confirmation-loading-spinner{width:26px;height:26px;box-sizing:border-box;border:2px solid rgba(81,207,216,.16);border-top-color:#55d5de;border-radius:50%;animation:confirmationSpin .75s linear infinite}#confirmReload.loading{opacity:.55;cursor:wait}@keyframes confirmationSpin{to{transform:rotate(360deg)}}.confirm-empty{padding:55px 20px;text-align:center;color:#718084;font-size:10px}.confirm-item{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:11px 12px;margin-bottom:7px;border:1px solid rgba(50,80,84,.5);border-radius:8px;background:rgba(8,19,22,.7)}.confirm-item-title{color:#dce8e8;font-size:10px;font-weight:700}.confirm-item-sub{color:#718084;font-size:9px;margin-top:4px}.confirm-actions{display:flex;gap:5px}.confirm-actions button{height:28px;padding:0 9px;border-radius:6px;font-size:9px;cursor:pointer;border:1px solid #31565d;background:#0c191c;color:#cfe0e2}.confirm-actions .accept{border-color:#2d6d43;color:#67d88a}.confirm-actions .reject{border-color:#704044;color:#e08087}.guard-circle-high{margin-top:2px}.guard-confirm-btn{height:31px;width:min(430px,82%);margin-top:10px;border:1px solid #2f7140;border-radius:7px;background:rgba(16,27,21,.92);color:#d0ded2;font-size:9px;font-weight:700;cursor:pointer}.guard-confirm-btn:hover{background:#17311e;border-color:#4aab60}.theme-light .confirm-select{background:#f7fbfb;color:#203033}.theme-light .confirm-item{background:rgba(255,255,255,.65)}
.toast{position:fixed!important;right:24px!important;bottom:24px!important;width:300px;min-height:52px;padding:12px 16px;display:flex;align-items:center;border:1px solid #3b8f98;border-radius:10px;background:#101c20;color:#e8f5f6;font-size:11px;font-weight:600;box-shadow:0 12px 40px rgba(0,0,0,.65);opacity:0;visibility:hidden;transform:translateY(18px);pointer-events:none;transition:.18s;z-index:999999}.toast.show{opacity:1;visibility:visible;transform:translateY(0)}
.auth-progress{position:fixed;right:24px;bottom:24px;width:310px;padding:13px 15px;border:1px solid #315b63;border-radius:11px;background:#0d191c;box-shadow:0 14px 45px rgba(0,0,0,.68);z-index:999998;display:none;pointer-events:none}.auth-progress.show{display:block}.auth-progress-head{display:flex;align-items:center;justify-content:space-between;gap:12px;color:#dceced;font-size:11px;font-weight:700}.auth-progress-percent{color:#61dce2;font:700 12px Consolas,monospace}.auth-progress-bar{height:6px;margin-top:10px;border-radius:8px;background:#172a2e;overflow:hidden}.auth-progress-fill{height:100%;width:0;border-radius:8px;background:linear-gradient(90deg,#2bbbc5,#61e0e5);transition:width .25s ease}.auth-progress-sub{margin-top:7px;color:#70878b;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.auth-progress-stage{margin-top:4px;color:#9db2b5;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.modal-backdrop{position:absolute;inset:0;z-index:100;display:none;align-items:center;justify-content:center;background:rgba(2,7,9,.72);backdrop-filter:blur(7px)}.modal-backdrop.show{display:flex}
.file-modal{width:690px;border:1px solid #315158;border-radius:12px;background:linear-gradient(145deg,#10191c,#0b1215);box-shadow:0 30px 100px rgba(0,0,0,.62);overflow:hidden}
.file-modal-head{height:64px;padding:0 18px;display:flex;align-items:center;border-bottom:1px solid #22373c}.file-modal-icon{width:34px;height:34px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:#102e33;border:1px solid #275b62;color:#52d5dc;margin-right:11px}.file-modal-title{font-size:14px;font-weight:650;color:#e0e9ea}.file-modal-sub{font-size:9px;color:#718084;margin-top:3px}.modal-close{margin-left:auto;width:32px;height:32px;border:0;background:transparent;color:#718084;font-size:18px;cursor:pointer}.project-path{margin:18px 22px 14px;padding:12px;border:1px solid #253c41;border-radius:8px;background:#081114;color:#8ba0a4;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.project-path b{color:#c9d8da}.file-actions{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;padding:0 22px 20px}.file-card{min-height:128px;padding:16px;border:1px solid #263e43;border-radius:10px;background:#111b1f;text-align:left;cursor:pointer;color:#d5e0e1}.file-card-icon{font-size:24px;margin-bottom:12px;color:#5dd8de}.file-card-title{font-size:11px;font-weight:600}.file-card-text{font-size:9px;color:#718083;line-height:1.45;margin-top:5px}.modal-footer{padding:13px 18px;border-top:1px solid #1d3034;display:flex;align-items:center;gap:14px;justify-content:space-between}.modal-footer .modal-hint{flex:1;min-width:0}.history-actions{flex-shrink:0}.modal-hint{font-size:9px;color:#647579}.modal-secondary{height:32px;padding:0 12px;border:1px solid #294349;border-radius:7px;background:#101b1e;color:#9eb0b3;font-size:10px;cursor:pointer}
.history-modal{width:900px;max-width:calc(100vw - 60px);height:560px;display:flex;flex-direction:column}.history-body{padding:14px 18px;display:flex;flex:1;min-height:0}.history-text{width:100%;height:100%;resize:none;border:1px solid #263e43;border-radius:8px;background:#071114;color:#a9c0c3;padding:12px;font:10px/1.5 Consolas,monospace;outline:none;user-select:text}.history-actions{display:flex;gap:8px;align-items:center}.history-actions button{height:32px;min-width:82px;padding:0 12px;border:1px solid #294349;border-radius:7px;background:#101b1e;color:#9eb0b3;font-size:10px;cursor:pointer}.history-actions button:hover{background:#183237;color:#dceff0}
.account-context-menu{position:fixed;z-index:999998;width:170px;padding:5px;border:1px solid #31565d;border-radius:8px;background:#0d181b;box-shadow:0 14px 40px rgba(0,0,0,.65);display:none}.account-context-menu.show{display:block}.context-item{height:34px;display:flex;align-items:center;gap:9px;padding:0 10px;border-radius:5px;color:#b9c9cb;font-size:10px;cursor:pointer}.context-item:hover{background:#183237;color:#e2f3f4}.ctx-icon{width:18px;text-align:center;color:#51d5dc}

/* Account / 2FA detail UI — strictly inside the fixed 1280×720 viewport */
.right{overflow:hidden}
.account-detail{position:absolute;left:0;right:0;top:0;bottom:0;display:none;z-index:80;overflow:hidden;border:1px solid #244047;border-radius:14px;background:radial-gradient(circle at 50% 28%,#102a24,transparent 36%),linear-gradient(180deg,#091618,#050d0f);padding:16px;box-shadow:0 18px 50px rgba(0,0,0,.48),inset 0 1px rgba(255,255,255,.025);}
.account-detail.show{display:block;isolation:isolate;position:absolute;inset:0;z-index:80;background:#081416}body.detail-open #inventory,body.detail-open #functionalPanel,body.detail-open #gamesPanel{display:none!important}body.detail-open .right-top,body.detail-open .right-main-tabs,body.detail-open .game-tabs{visibility:hidden!important}
.account-detail.collapsed .detail-grid{display:none}


.detail-head{height:48px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #1d3338;padding-bottom:10px;margin-bottom:12px}
.detail-back{width:34px;height:34px;border:1px solid #2b5960;border-radius:9px;background:linear-gradient(180deg,#102124,#0b1719);color:#67dbe1;cursor:pointer;font-size:20px;line-height:1;transition:.15s}.detail-back:hover{background:#153137;transform:translateX(-2px)}
.detail-title{font-size:14px;font-weight:750;color:#e0eeee}.detail-sub{font-size:9px;color:#708286;margin-top:3px}
.detail-grid{height:calc(100% - 60px);display:grid;grid-template-columns:260px minmax(0,1fr);gap:12px;min-height:0}
.detail-card{border:1px solid #25454a;border-radius:12px;background:linear-gradient(180deg,rgba(10,25,28,.94),rgba(7,16,18,.94));padding:14px;min-height:0;overflow:hidden;box-shadow:inset 0 1px rgba(255,255,255,.018)}
.detail-card h3{margin:0 0 12px;color:#61d8de;font-size:11px;letter-spacing:.2px}.detail-status{padding:11px;border:1px dashed #31535a;border-radius:8px;color:#8da3a7;font-size:10px;line-height:1.5}
.security-row{display:grid;grid-template-columns:58px minmax(0,1fr) 30px;gap:8px;align-items:center;margin-bottom:9px}.copy-credential{width:30px;height:30px;padding:0;border:1px solid #29474c;background:linear-gradient(180deg,#101f22,#0b1719);color:#73dce1;border-radius:7px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:.15s;box-shadow:inset 0 1px rgba(255,255,255,.03)}.copy-credential:hover{color:#d9ffff;border-color:#43aeb6;background:#153238;transform:translateY(-1px)}.copy-credential:active{transform:scale(.94)}.copy-credential svg{width:14px;height:14px;display:block}.security-label{font-size:9px;color:#789095}.security-value{height:32px;box-sizing:border-box;border:1px solid #29474c;border-radius:7px;background:#071013;color:#a9babc;padding:0 9px;display:flex;align-items:center;font:10px Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.security-value.password{letter-spacing:2px;color:#718286}
.account-meta{margin-top:16px;padding:11px;border:1px solid #1d383d;border-radius:9px;background:rgba(5,14,16,.65)}.account-meta-title{font-size:9px;color:#54d9df;margin-bottom:7px;font-weight:700}.account-meta-line{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid rgba(60,91,95,.18);font-size:9px}.account-meta-line:last-child{border-bottom:0}.account-meta-line span:first-child{color:#657b80}.account-meta-line span:last-child{color:#a8b9bb;max-width:145px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.guard-card{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;box-sizing:border-box;border:1px solid rgba(47,111,64,.65);border-radius:12px;background:radial-gradient(circle at 50% 28%,rgba(48,221,102,.10),transparent 30%),linear-gradient(180deg,rgba(8,20,15,.78),rgba(7,15,13,.92));box-shadow:inset 0 0 45px rgba(44,211,91,.035)}
.guard-title{color:#49e66b;font-size:13px;font-weight:750;margin-bottom:12px;text-shadow:0 0 12px rgba(73,230,107,.25)}.guard-caption{font-size:9px;color:#60786a;margin-top:7px}
.guard-circle{position:relative;width:166px;height:166px;border-radius:50%;border:2px solid #2f8d4a;box-shadow:0 0 24px rgba(53,220,94,.12),inset 0 0 30px rgba(53,220,94,.05);display:flex;align-items:center;justify-content:center;cursor:pointer;overflow:hidden;transition:.2s;user-select:none}.guard-circle:before{content:"";position:absolute;inset:9px;border-radius:50%;border:1px solid rgba(68,225,101,.18);box-shadow:0 0 18px rgba(62,226,98,.08) inset}.guard-circle:hover{transform:scale(1.018);border-color:#43b85e;box-shadow:0 0 34px rgba(53,220,94,.24),inset 0 0 30px rgba(53,220,94,.09)}.guard-circle:active{transform:scale(.985)}
.guard-ring{position:absolute;inset:-2px;border-radius:50%;background:conic-gradient(#45e66a var(--progress,100%),rgba(54,93,61,.12) 0);-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 6px),#000 calc(100% - 5px));mask:radial-gradient(farthest-side,transparent calc(100% - 6px),#000 calc(100% - 5px));pointer-events:none;filter:drop-shadow(0 0 4px rgba(69,230,106,.4))}.guard-demo{position:relative;z-index:2;font:750 18px Consolas,monospace;color:#4de56b;letter-spacing:3px;text-shadow:0 0 13px rgba(77,229,107,.35)}.guard-time{font:700 10px Consolas,monospace;color:#6e9878;margin-top:10px}.guard-copied{font-size:9px;color:#55e96f;height:14px;margin-top:4px}.guard-management{width:min(430px,82%);margin-top:13px}.guard-management-title{text-align:center;color:#55e96f;font-size:10px;font-weight:700;margin-bottom:7px}.guard-action{height:31px;width:100%;border:1px solid #2f7140;border-radius:7px;background:rgba(16,27,21,.92);color:#d0ded2;margin-top:5px;font-size:9px;cursor:pointer;transition:.15s}.guard-action:hover{background:#17311e;border-color:#3e9953}.guard-note{position:absolute;left:14px;right:14px;bottom:10px;text-align:center;font-size:8px;color:#53685b}
@media(max-width:1000px){.detail-grid{grid-template-columns:220px minmax(0,1fr)}.guard-circle{width:145px;height:145px}}

/* Appearance / theme editor */
.theme-modal{width:720px;max-width:calc(100vw - 44px);border:1px solid #315158;border-radius:14px;background:linear-gradient(145deg,#101a1d,#0a1215);box-shadow:0 30px 100px rgba(0,0,0,.7);overflow:hidden}
.theme-head{height:62px;padding:0 18px;display:flex;align-items:center;border-bottom:1px solid #22373c}.theme-head-icon{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;background:#102e33;border:1px solid #275b62;color:#55dce2;margin-right:11px}.theme-title{font-size:14px;font-weight:700;color:#e3eeee}.theme-sub{font-size:9px;color:#718084;margin-top:3px}.theme-body{padding:15px 18px 16px;max-height:510px;overflow:auto}.theme-section-title{font-size:9px;color:#62d9df;text-transform:uppercase;letter-spacing:.8px;margin:0 0 9px;font-weight:800}.theme-presets{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:15px}.theme-preset{height:68px;border:1px solid #29464b;border-radius:10px;background:#0e191c;padding:8px;cursor:pointer;text-align:left;color:#dce7e8;transition:.15s}.theme-preset:hover{border-color:#4eafb7;transform:translateY(-1px)}.theme-preset.active{border-color:#5bdbe1;box-shadow:0 0 0 1px rgba(91,219,225,.2),0 8px 22px rgba(0,0,0,.25)}.preset-preview{height:26px;border-radius:6px;margin-bottom:7px;border:1px solid rgba(255,255,255,.12)}.theme-preset span{font-size:9px;color:#a8b8ba}.theme-colors{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.color-control{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:9px 10px;border:1px solid #223d42;border-radius:9px;background:rgba(7,17,20,.68)}.color-info b{display:block;font-size:10px;color:#c9d8da}.color-info span{display:block;font-size:8px;color:#647a7e;margin-top:3px}.color-control input[type=color]{width:34px;height:28px;padding:2px;border:1px solid #3a5b60;border-radius:7px;background:#081113;cursor:pointer}.theme-gradient{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}.theme-switches{display:flex;gap:7px;margin-top:10px}.theme-action{height:32px;padding:0 12px;border:1px solid #2c4c52;border-radius:8px;background:#101c20;color:#b8c8ca;font-size:9px;cursor:pointer}.theme-action:hover{background:#173137;border-color:#4a9098}.theme-action.primary{color:#d9ffff;border-color:#357e86;background:#123238}.theme-footer{padding:11px 18px;border-top:1px solid #1d3034;display:flex;justify-content:space-between;align-items:center}.theme-hint{font-size:8px;color:#607478}.theme-footer-actions{display:flex;gap:7px}.appearance-trigger{position:relative}.appearance-trigger:after{content:"";display:inline-block;width:5px;height:5px;border-right:1px solid currentColor;border-bottom:1px solid currentColor;transform:rotate(45deg) translateY(-2px);margin-left:7px}
body.theme-light{color:#243235}.theme-light .app{box-shadow:inset 0 0 80px rgba(0,0,0,.05)}
@media(max-width:900px){.theme-colors{grid-template-columns:1fr}.theme-presets{grid-template-columns:repeat(2,1fr)}}



/* Persistent marked accounts */
.account-row.marked{background:linear-gradient(90deg,rgba(112,86,16,.20),rgba(52,42,13,.10))}
.account-row.marked .login-cell .login-name{color:#ffd75e!important;font-weight:750;text-shadow:0 0 10px rgba(255,199,55,.18)}
.account-row.marked .avatar,.account-row.marked .avatar-img{border-color:rgba(255,205,73,.72)}
.account-row.marked .number{color:#d9b64d}
.functional-panel.show{display:flex;align-items:flex-start;gap:10px}
.marked-btn{height:42px;padding:0 18px;border:1px solid #9b792b;border-radius:8px;background:linear-gradient(145deg,rgba(76,58,17,.96),rgba(39,31,13,.96));color:#ffd75e;font-size:11px;font-weight:700;cursor:pointer;transition:.15s}
.marked-btn:hover{border-color:#e2b94f;background:linear-gradient(145deg,rgba(99,75,20,.98),rgba(51,40,14,.98));transform:translateY(-1px)}
.marked-btn:disabled{opacity:.55;cursor:wait;transform:none}
.marked-help{align-self:center;color:#77888a;font-size:9px;line-height:1.45}
.get-level-btn{height:42px;padding:0 18px;border:1px solid #2d7185;border-radius:8px;background:linear-gradient(145deg,rgba(18,59,72,.97),rgba(10,32,40,.97));color:#75e5f2;font-size:11px;font-weight:750;cursor:pointer;white-space:nowrap;transition:.15s}
.get-level-btn:hover{border-color:#56cbdc;background:#123e49;transform:translateY(-1px)}
.get-level-btn:disabled{opacity:.55;cursor:wait;transform:none}
.account-row:has(.level-widget){min-height:66px}
.account-main{min-width:0;flex:1}
.level-widget{width:132px;max-width:100%;height:25px;margin-top:4px;display:flex;align-items:center;gap:6px}
.level-badge{width:25px;height:25px;flex:none;display:flex;align-items:center;justify-content:center;clip-path:polygon(50% 0,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);background:linear-gradient(145deg,#58e1ed,#197b9e);color:#031317;font-size:10px;font-weight:900;filter:drop-shadow(0 0 5px rgba(69,211,227,.28))}
.level-info{min-width:0;flex:1}
.level-line{height:10px;display:flex;align-items:center;justify-content:space-between;gap:4px;color:#a9c2c6;font-size:7px;line-height:1}
.level-line b{color:#72e89a;font-size:7px;letter-spacing:.25px}.level-line span{color:#72e89a;font-weight:750;white-space:nowrap}
.xp-track{height:5px;margin-top:3px;border-radius:6px;background:#182b30;overflow:hidden;box-shadow:inset 0 1px 2px rgba(0,0,0,.45)}
.xp-fill{height:100%;min-width:0;border-radius:6px;background:linear-gradient(90deg,#1d9f55,#65ed91);box-shadow:0 0 7px rgba(74,229,128,.38);transition:width .35s ease}
.level-loading{color:#6f9298;font-size:8px;margin-top:4px}
.trade-modal{width:650px;max-width:calc(100vw - 44px);border:1px solid #315158;border-radius:12px;background:linear-gradient(145deg,#10191c,#0b1215);box-shadow:0 30px 100px rgba(0,0,0,.65);overflow:hidden}
.trade-body{padding:18px;display:grid;grid-template-columns:minmax(0,1fr) 190px;gap:16px;align-items:start}.trade-saved{border:1px solid #243f45;border-radius:9px;background:rgba(5,14,16,.55);padding:10px;min-height:105px}.trade-saved-title{color:#7edbe2;font-size:9px;font-weight:750;margin-bottom:8px}.trade-saved-empty{color:#5f777b;font-size:8px;line-height:1.5}.trade-saved-item{display:flex;align-items:center;gap:4px;margin-bottom:6px}.trade-saved-use{flex:1;min-width:0;height:30px;padding:0 7px;text-align:left;border:1px solid #2b5158;border-radius:6px;background:#0d2024;color:#b8d7da;font-size:8px;cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.trade-saved-use:hover{border-color:#56cbd5;color:#e4ffff}.trade-saved-del{width:25px;height:30px;border:1px solid #59383d;border-radius:6px;background:#211316;color:#d97b83;cursor:pointer}.trade-account{margin-bottom:12px;color:#69dce4;font-size:11px;font-weight:700}.trade-label{display:block;margin-bottom:7px;color:#91a6aa;font-size:9px}.trade-input{width:100%;height:38px;padding:0 11px;border:1px solid #31565d;border-radius:8px;outline:none;background:#071114;color:#d8e9ea;font-size:10px;user-select:text}.trade-input:focus{border-color:#45cbd5;box-shadow:0 0 0 2px rgba(69,203,213,.10)}.trade-input-row{display:flex;align-items:center;gap:6px}.trade-input-row .trade-input{flex:1;min-width:0}.trade-pin-btn{width:38px;height:38px;flex:none;border:1px solid #31565d;border-radius:8px;background:#102126;color:#73dce4;cursor:pointer;font-size:15px}.trade-pin-btn:hover{border-color:#55cbd5;background:#17343a}.trade-pin-btn.saved{color:#ffd75e;border-color:#8c7131}.trade-hint{margin-top:9px;color:#647c81;font-size:8px;line-height:1.5}.trade-error{min-height:15px;margin-top:7px;color:#ed7d85;font-size:9px}.trade-footer{display:flex;justify-content:flex-end;gap:8px;padding:12px 18px;border-top:1px solid #22373c}.trade-open{height:32px;padding:0 14px;border:1px solid #2c7550;border-radius:7px;background:#123525;color:#72e59b;font-size:10px;font-weight:700;cursor:pointer}.trade-open:disabled{opacity:.5;cursor:wait}
.delete-modal{width:420px;max-width:calc(100vw - 40px);border:1px solid #59383d;border-radius:12px;background:#10191c;box-shadow:0 25px 80px rgba(0,0,0,.7);padding:22px;text-align:center}.delete-title{font-size:15px;font-weight:750;color:#e7edef}.delete-text{margin-top:10px;color:#91a3a7;font-size:11px;line-height:1.5}.delete-actions{display:flex;justify-content:center;gap:9px;margin-top:19px}.delete-yes,.delete-no{min-width:100px;height:34px;border-radius:7px;cursor:pointer;font-size:10px;font-weight:700}.delete-yes{border:1px solid #8c3f48;background:#401c22;color:#f18c94}.delete-no{border:1px solid #31565d;background:#102126;color:#b9d5d8}

.sort-select{height:29px;min-width:118px;border:1px solid #29434a;border-radius:7px;background:#0d1b20;color:#bcd0d3;padding:0 8px;font-size:10px;outline:none;cursor:pointer}.sort-select:focus{border-color:#3b98a4}.check-vac-btn{height:37px;padding:0 16px;border:1px solid #725c2d;border-radius:8px;background:linear-gradient(180deg,#292315,#17160f);color:#e9c865;font-weight:700;cursor:pointer}.check-vac-btn:hover{border-color:#c29b43;background:#332a16}.check-vac-btn:disabled{opacity:.55;cursor:wait}
.vac-modal{width:410px;max-width:92vw;background:#202a31;border:1px solid #35464e;border-radius:19px;box-shadow:0 25px 80px #0009;overflow:hidden}.vac-head{padding:24px 25px 17px;font-size:19px;font-weight:600;color:#e3e9eb}.vac-body{padding:0 25px 20px}.vac-status{min-height:42px;padding:10px 0;color:#9eb0b5;font-size:12px;text-align:center}.vac-result-row{display:flex;align-items:center;gap:13px;padding:14px 15px;margin-bottom:11px;border-radius:9px;font-size:14px;font-weight:700}.vac-result-icon{width:20px;text-align:center;font-size:18px}.vac-community{background:#492a2e;color:#ef9aa3}.vac-vac{background:#493b26;color:#e2b775}.vac-game{background:#454426;color:#ded985}.vac-total{background:#254334;color:#91d2b2}.vac-footer{display:flex;align-items:center;justify-content:space-between;padding:16px 25px 22px;border-top:1px solid #344149;color:#8da1a7;font-size:11px}.vac-close{border:0;background:transparent;color:#72bdd4;font-weight:700;cursor:pointer}.vac-key-setup{display:none;padding:0 25px 20px}.vac-key-text{color:#aebdc2;font-size:12px;line-height:1.55;margin-bottom:11px}.vac-key-input{box-sizing:border-box;width:100%;height:37px;border:1px solid #3c515a;border-radius:7px;background:#111b20;color:#d5e3e6;padding:0 11px;outline:none}.vac-key-actions{display:flex;gap:8px;margin-top:10px}.vac-key-actions button{height:33px;padding:0 12px;border-radius:7px;cursor:pointer}.vac-save-key{border:1px solid #317883;background:#15383d;color:#8de0e7}.vac-get-key{border:1px solid #3d4d54;background:#253238;color:#b8c9ce}.vac-loading{display:inline-block;width:17px;height:17px;border:2px solid #36515a;border-top-color:#6ed4df;border-radius:50%;animation:vacspin .8s linear infinite;vertical-align:middle;margin-right:8px}@keyframes vacspin{to{transform:rotate(360deg)}}


.functional-panel.show{display:block;overflow:auto;padding:15px 3px 15px 0}.functional-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.functional-card{border:1px solid #294149;border-radius:11px;background:linear-gradient(145deg,#0e2025,#091619);padding:13px}.functional-card.full{grid-column:1/-1}.functional-card-title{font-size:11px;font-weight:700;color:#bcd3d7;margin-bottom:10px}.refresh-data-btn,.relogin-btn{min-height:34px;border:1px solid #31636a;border-radius:7px;background:#102b30;color:#75dce2;padding:0 12px;cursor:pointer;font-size:10px}.refresh-data-btn:disabled{opacity:.55;cursor:wait}.refresh-data-progress{margin-top:9px;color:#78969b;font-size:10px;min-height:14px}.session-badge{display:inline-flex;align-items:center;gap:4px;margin-left:6px;color:#738b90;font-size:8px;font-weight:500;white-space:nowrap}.session-badge.online{color:#58cda0}.session-badge.offline{color:#68797d}.session-badge.relogin_required{color:#ef8b83}.session-dot{width:5px;height:5px;border-radius:50%;background:currentColor}.relogin-btn{display:none;margin-top:10px;width:100%}.relogin-btn.show{display:block}.functional-actions{display:flex;flex-wrap:wrap;gap:8px}.queue-delay{width:58px;height:36px;border:1px solid #34515a;border-radius:7px;background:#0a171b;color:#d6e5e7;padding:0 7px}.queue-unit{font-size:10px;color:#78959b}.auto-trade-row{display:flex;align-items:center;justify-content:space-between;gap:15px}.auto-trade-copy b{display:block;color:#c7dbde;font-size:12px}.auto-trade-copy span{display:block;margin-top:5px;color:#718d93;font-size:10px;line-height:1.4}.switch{position:relative;width:45px;height:24px;flex:none}.switch input{opacity:0;width:0;height:0}.switch-slider{position:absolute;inset:0;border-radius:20px;background:#29393e;border:1px solid #43565c;cursor:pointer;transition:.2s}.switch-slider:before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;border-radius:50%;background:#8da0a5;transition:.2s}.switch input:checked+.switch-slider{background:#176b52;border-color:#39b781}.switch input:checked+.switch-slider:before{transform:translateX(20px);background:#b9f6d9}.proxy-row{display:flex;gap:7px}.proxy-input{min-width:0;flex:1;height:35px;border:1px solid #34515a;border-radius:7px;background:#09171b;color:#c9dadd;padding:0 9px;font-size:10px}.proxy-btn,.queue-btn,.close-selected-btn,.account-history-btn{height:35px;padding:0 11px;border:1px solid #316773;border-radius:7px;background:#12333b;color:#85d9e2;font-size:10px;font-weight:700;cursor:pointer}.close-selected-btn{border-color:#79424b;background:#371b21;color:#ed98a2}.proxy-btn:hover,.queue-btn:hover,.account-history-btn:hover{filter:brightness(1.2)}.account-history-btn{width:100%;margin-top:12px}.login-name-wrap{display:flex;align-items:center;gap:5px;min-width:0}.account-row.steam-running .login-name{color:#61ed96!important;text-shadow:0 0 9px rgba(64,225,132,.25)}.ban-badge{display:inline-flex;align-items:center;justify-content:center;min-width:16px;height:16px;padding:0 3px;border-radius:4px;background:#541f27;color:#ff8c98;font-size:9px;font-weight:800;flex:none}.ban-badge.vac{background:#543b18;color:#ffc46e}.ban-badge.game{background:#4d451b;color:#e9d56c}


/* Functional dashboard — compact, aligned controls */
.functional-grid{gap:12px}.functional-card{position:relative;padding:14px 15px;border:1px solid rgba(54,91,99,.62);border-radius:12px;background:linear-gradient(145deg,rgba(15,34,39,.96),rgba(8,21,25,.96));box-shadow:inset 0 1px rgba(255,255,255,.025),0 7px 20px rgba(0,0,0,.12)}.functional-card:before{content:"";position:absolute;left:15px;right:15px;top:0;height:1px;background:linear-gradient(90deg,transparent,rgba(92,210,218,.18),transparent)}.functional-card-title{margin-bottom:11px;color:#9eb8bd;font-size:10px;font-weight:700;letter-spacing:.3px;text-transform:uppercase}.functional-actions{gap:9px;align-items:center}.functional-actions button{height:37px;border-radius:8px;box-shadow:inset 0 1px rgba(255,255,255,.035),0 4px 12px rgba(0,0,0,.13);transition:border-color .16s,filter .16s,transform .16s}.functional-actions button:hover{filter:brightness(1.15);transform:translateY(-1px)}.functional-actions button:active{transform:translateY(0)}.auto-trade-row{min-height:38px;gap:10px}.auto-trade-copy b{color:#d3e6e8;font-size:11px;white-space:nowrap}.switch{width:42px;height:23px}.switch-slider{background:#24363b;border-color:#3d545b}.switch-slider:before{width:15px;height:15px}.switch input:checked+.switch-slider{background:#176f53;border-color:#42c58d;box-shadow:0 0 12px rgba(54,205,143,.16)}.switch input:checked+.switch-slider:before{transform:translateX(18px);background:#c5f8df}.queue-btn{height:37px!important;padding:0 14px;background:linear-gradient(180deg,#16434c,#102e35);border-color:#347d89;color:#8ce6ec}.close-selected-btn,.functional-actions .close-steam-btn{height:37px;padding:0 15px}.close-selected-btn{background:linear-gradient(180deg,#3d2026,#28171b)}.functional-actions .close-steam-btn{background:linear-gradient(180deg,#48242b,#301a1f)}


.sort-strip{height:32px;display:flex;align-items:center;gap:7px;padding:0 2px}.sort-strip-label{color:#728b90;font-size:10px;margin-right:2px}.metric-sort-btn{height:25px;padding:0 10px;border:1px solid #2c4c54;border-radius:7px;background:linear-gradient(180deg,#11282e,#0b1c21);color:#9fc3c8;font-size:10px;font-weight:700;cursor:pointer;transition:.15s}.metric-sort-btn:hover{border-color:#4a9ca8;color:#d2f5f7}.metric-sort-btn.active{border-color:#3a9ba6;background:linear-gradient(180deg,#17424a,#102c33);color:#70e1e8;box-shadow:0 0 10px rgba(54,187,199,.1)}.metric-sort-btn span{margin-left:4px;color:#66dce4}.sort-strip-hint{color:#526c72;font-size:9px;margin-left:3px}.account-panel{height:calc(100% - 118px)}


.table-head,.account-row{grid-template-columns:28px 28px 76px minmax(125px,1fr) 52px 62px 214px}.metric-sort-head{display:flex;align-items:center;gap:4px;cursor:pointer;white-space:nowrap;user-select:none;transition:color .15s}.metric-sort-head:hover,.metric-sort-head.active{color:#68dce4}.metric-sort-head span{color:#54cbd5;font-size:11px}.metric-cell{text-align:center;font-size:10px;font-weight:700;font-variant-numeric:tabular-nums}.level-cell{color:#77dce4}.xp-cell{color:#72d99a}.account-panel{height:calc(100% - 86px)}


.table-head,.account-row{grid-template-columns:28px 28px 76px minmax(150px,1fr) 230px}.login-head-wrap{display:flex;align-items:center;gap:5px;min-width:0}.login-metric-sort{height:23px;min-width:29px;padding:0 5px;border:1px solid #2d4b52;border-radius:6px;background:linear-gradient(180deg,#11272c,#0b191d);color:#789ba1;font-size:9px;font-weight:800;cursor:pointer;transition:.15s}.login-metric-sort:hover{border-color:#438b96;color:#c7f2f4}.login-metric-sort.active{border-color:#3c9ba6;background:#143840;color:#6fe2e9;box-shadow:0 0 8px rgba(58,180,192,.12)}.login-metric-sort span{margin-left:2px;font-size:9px;color:#59ccd6}


.login-cell{gap:4px}.login-head-wrap{gap:8px}.login-metric-sort{display:flex;align-items:center;gap:3px;min-width:0;height:auto;padding:0;border:0;border-radius:0;background:none;box-shadow:none;color:#7f898d;font-size:10px;font-weight:600;cursor:pointer;white-space:nowrap}.login-metric-sort:hover{color:#b5dadd;transform:none}.login-metric-sort.active{border:0;background:none;box-shadow:none;color:#64d9e1}.login-metric-sort .sort-arrow{margin:0;color:#6b8e94;font-size:10px}.login-metric-sort.active .sort-arrow{color:#64d9e1}


/* Keep avatar spacing original; place account actions close to the login block. */
.login-cell{gap:9px}.table-head,.account-row{grid-template-columns:28px 28px 76px 185px 230px}.actions{justify-content:flex-start;padding-left:4px}


/* Balanced final grid: moderate login width, actions fill the remaining row. */
.table-head,.account-row{grid-template-columns:28px 28px 76px minmax(185px,220px) minmax(210px,1fr)}.actions{width:100%;justify-content:space-between;gap:5px;padding-left:5px;padding-right:0}.actions-title{padding-left:5px}


/* Actions: right-aligned with a fixed 3px gap. */
.actions{justify-content:flex-end;gap:3px;padding-left:4px;padding-right:0}.actions-title{text-align:right;padding-left:0;padding-right:5px}


.confirm-window{width:670px!important;max-width:94vw!important}.confirm-list{max-height:390px;overflow:auto;padding:10px 14px;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;align-items:start}.confirm-list .confirm-empty{grid-column:1/-1}.confirmation-card{min-width:0;border:1px solid #2e4b52;border-radius:10px;background:linear-gradient(145deg,#10262c,#0a191d);padding:10px;margin-bottom:0}.confirmation-card.incoming-only{border-color:#3b9a68;background:linear-gradient(145deg,#123326,#0a1d18);box-shadow:inset 0 0 20px rgba(64,190,119,.06)}.confirmation-kind.incoming{background:#1d5135;color:#8cebb0}.confirmation-sender{display:flex;align-items:center;gap:8px;margin-top:7px}.confirmation-avatar{width:34px;height:34px;border-radius:50%;object-fit:cover;border:1px solid #3a6469;background:#102126}.confirmation-sender .confirmation-recipient{margin-top:0}.confirmation-direction{margin-top:3px;color:#7e999e;font-size:9px}.incoming-only .confirmation-direction{color:#79dca1}.confirmation-item-gallery{display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}.confirmation-item-image{width:78px;min-height:80px;box-sizing:border-box;padding:5px;border:1px solid #31545c;border-radius:8px;background:radial-gradient(circle at 50% 28%,#17333a,#09171a 72%);text-align:center}.confirmation-item-image img{width:66px;height:48px;object-fit:contain;display:block;margin:auto;filter:drop-shadow(0 3px 4px rgba(0,0,0,.35))}.confirmation-image-empty{width:66px;height:48px;align-items:center;justify-content:center;margin:auto;color:#50747b;font-size:22px}.confirmation-item-image span{display:block;margin-top:4px;color:#b6cdd1;font-size:8px;line-height:1.25;word-break:break-word}.confirmation-wear{display:inline-block;margin:4px 0 0;padding:0 4px;border:1px solid #49747c;border-radius:3px;color:#9edce2;font-size:7px;font-weight:800;line-height:1.35;vertical-align:1px}.confirmation-wear.wear-fn{color:#83e2ad;border-color:#37795a}.confirmation-wear.wear-mw{color:#b2dfa0;border-color:#557a45}.confirmation-wear.wear-ft{color:#e7cc7f;border-color:#7b693c}.confirmation-wear.wear-ww{color:#e9a474;border-color:#81573d}.confirmation-wear.wear-bs{color:#ed929b;border-color:#81454e}.confirmation-trade-sides{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px;margin-top:10px}.confirmation-trade-side{min-width:0;padding:10px;border:1px solid #2a474d;border-radius:10px;background:#09171a}.confirmation-trade-side.outgoing{border-color:#82505a;background:linear-gradient(145deg,rgba(111,42,53,.28),rgba(20,22,26,.94));box-shadow:inset 0 1px rgba(255,255,255,.025)}.confirmation-trade-side.incoming{border-color:#3b8964;background:linear-gradient(145deg,rgba(35,113,72,.25),rgba(12,27,23,.94));box-shadow:inset 0 1px rgba(255,255,255,.025)}.confirmation-side-title{display:flex;align-items:center;justify-content:space-between;gap:6px;padding-bottom:7px;border-bottom:1px solid rgba(126,160,165,.14);font-size:10px;font-weight:800}.confirmation-side-title b{min-width:18px;padding:1px 5px;border-radius:5px;background:rgba(255,255,255,.06);text-align:center;font-size:9px}.outgoing .confirmation-side-title{color:#f39aa4}.incoming .confirmation-side-title{color:#82e5aa}.confirmation-trade-item-list{display:flex;flex-direction:column;gap:5px;margin-top:8px;max-height:270px;overflow-y:auto;padding-right:2px;scrollbar-width:thin;scrollbar-color:#35565e #091518}.confirmation-trade-item-list.collapsed{overflow:hidden}.confirmation-trade-item-list.collapsed>.confirmation-trade-item:nth-child(n+5){display:none}.confirmation-trade-expand{width:100%;min-height:29px;margin-top:7px;padding:5px 10px;display:flex;align-items:center;justify-content:center;gap:7px;border:1px solid rgba(103,150,158,.2);border-radius:7px;background:linear-gradient(180deg,rgba(70,108,116,.1),rgba(20,38,43,.2));color:#8eafb6;font:inherit;font-size:9px;font-weight:700;cursor:pointer;transition:color .18s,border-color .18s,background .18s}.confirmation-trade-expand:hover{color:#d7e9ec;border-color:rgba(102,197,205,.42);background:linear-gradient(180deg,rgba(70,137,145,.18),rgba(20,48,54,.28))}.confirmation-trade-expand:focus-visible{outline:2px solid rgba(85,213,222,.55);outline-offset:2px}.confirmation-trade-expand svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;transition:transform .22s ease}.confirmation-trade-expand.expanded{color:#c5e0e4}.confirmation-trade-expand.expanded svg{transform:rotate(180deg)}.confirmation-trade-item{--rarity-color:#48636a;display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:34px;padding:6px 8px;box-sizing:border-box;border:1px solid var(--rarity-color);border-left-width:3px;border-radius:6px;background:rgba(5,15,18,.58);box-shadow:inset 0 0 12px rgba(255,255,255,.012)}.confirmation-trade-item.rarity-consumer{--rarity-color:#b0c3d9}.confirmation-trade-item.rarity-industrial{--rarity-color:#5e98d9}.confirmation-trade-item.rarity-milspec{--rarity-color:#4b69ff}.confirmation-trade-item.rarity-restricted{--rarity-color:#8847ff}.confirmation-trade-item.rarity-classified{--rarity-color:#d32ce6}.confirmation-trade-item.rarity-covert{--rarity-color:#eb4b4b}.confirmation-trade-item.rarity-exceedingly,.confirmation-trade-item.rarity-contraband{--rarity-color:#e4ae39}.confirmation-trade-item-index{flex:0 0 19px;height:19px;display:inline-flex;align-items:center;justify-content:center;border-radius:5px;background:rgba(119,157,165,.09);color:#78969d;font-size:9px;font-weight:800}.confirmation-trade-item-thumb{flex:0 0 30px;width:30px;height:30px;object-fit:contain;filter:drop-shadow(0 2px 4px rgba(0,0,0,.35))}.confirmation-trade-item-name{flex:1;min-width:0;color:#e0ecee;font-size:11px;font-weight:600;line-height:1.4;overflow-wrap:anywhere}.confirmation-trade-item-meta{display:flex;align-items:center;justify-content:flex-end;gap:5px;flex-shrink:0}.confirmation-trade-item-meta .confirmation-wear{margin:0}.confirmation-trade-amount{padding:2px 6px;border-radius:5px;background:rgba(255,255,255,.07);color:#c7dadd;font-size:9px;white-space:nowrap}.confirmation-side-empty{padding:16px 4px 10px;color:#68878d;font-size:10px;text-align:center}.confirmation-top{display:flex;justify-content:space-between;align-items:center}.confirmation-kind{padding:3px 7px;border-radius:5px;background:#173f47;color:#70dbe4;font-size:9px;font-weight:800;text-transform:uppercase}.confirmation-kind.market{background:#493a1b;color:#e6c86f}.confirmation-date{color:#718c92;font-size:9px}.confirmation-recipient{margin-top:9px;color:#d5e7e9;font-size:12px;font-weight:700}.confirmation-count{margin-top:3px;color:#85a4a9;font-size:10px}.confirmation-items{margin-top:7px;max-height:80px;overflow:auto}.confirmation-item{padding:3px 0;color:#abc1c5;font-size:10px;border-bottom:1px solid rgba(58,86,92,.25)}.confirmation-actions{display:flex;justify-content:flex-start;gap:7px;margin-top:7px}.confirmation-actions button,#confirmAcceptAll,#confirmRejectAll{height:31px;padding:0 12px;border-radius:7px;font-size:10px;font-weight:700;cursor:pointer}.confirmation-accept,#confirmAcceptAll{border:1px solid #32785a;background:#173d2c;color:#85e4ad}.confirmation-reject,#confirmRejectAll{border:1px solid #79414a;background:#3a1e24;color:#ee98a2}.confirmation-card .confirmation-actions button{height:28px;min-width:88px;padding:0 10px;font-size:9px}.trade-confirmation{grid-column:1/-1}.market-confirmation{padding-bottom:9px}.market-confirmation .confirmation-top{gap:5px;align-items:flex-start}.market-confirmation .confirmation-date{font-size:8px;white-space:nowrap}.market-confirmation .confirmation-direction{font-size:8px;line-height:1.35}.market-confirmation .confirmation-actions{display:grid;width:100%;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.market-confirmation .confirmation-actions button{min-width:0;padding:0 4px;font-size:8px}.trade-confirmation .confirmation-actions{margin-top:8px}


.farm-cards-btn{border:0;background:transparent;color:#63d89a;font-size:10px;font-weight:700;cursor:pointer;padding:3px 8px}.farm-cards-btn:hover{color:#9af2bd;text-decoration:underline}.farm-cards-btn.running{color:#ef9099}.card-drops-label{margin-top:4px;color:#67e39b;font-size:10px;font-weight:700}.game-card:has(.card-drops-label){border-color:#3b8b62;box-shadow:inset 0 0 18px rgba(55,190,115,.06)}


.account-restrictions{width:15px;min-width:15px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;max-height:48px;overflow:hidden}.account-restrictions:empty{visibility:hidden}.account-restrictions .ban-badge{width:14px;min-width:14px;height:14px;min-height:14px;padding:0;border-radius:4px;font-size:8px;line-height:14px}.ban-badge.limited{background:#554218;color:#f2ce65}.ban-badge.trade{background:#512633;color:#f08aa4}.ban-badge.hold{background:#3b3560;color:#c0aff2}


/* Real Steam inventory */
.inventory{grid-template-columns:repeat(5,minmax(0,1fr));align-content:start;gap:9px;height:590px;overflow-y:auto;padding:14px 3px 14px 0}
.inventory-item{position:relative;display:flex;flex-direction:column;min-width:0;min-height:170px;border:1px solid #263e43;border-radius:10px;background:linear-gradient(160deg,#0d1d20,#091417);padding:9px 8px 10px;transition:border-color .16s,background .16s}
.inventory-item:hover{border-color:#3d6870;background:linear-gradient(160deg,#11262a,#0a171a)}
.inventory-item-icon{flex:0 0 70px;height:70px;display:flex;align-items:center;justify-content:center}.inventory-item-icon img{max-width:100%;max-height:66px;object-fit:contain;filter:drop-shadow(0 5px 8px rgba(0,0,0,.28))}
.inventory-item-name{flex:0 0 27px;min-height:27px;margin-top:5px;overflow:hidden;color:#c3d2d5;font-size:9px;line-height:1.45;text-align:center}.inventory-item-lock{align-self:center;max-width:100%;min-height:19px;margin-top:2px;padding:2px 7px;box-sizing:border-box;overflow:hidden;border:1px solid rgba(255,103,116,.3);border-radius:6px;background:rgba(116,29,40,.22);color:#ff7d87;font-size:8px;font-weight:700;line-height:13px;text-align:center;letter-spacing:.1px;white-space:nowrap;text-overflow:ellipsis;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.inventory-item-lock:empty{display:none}.inventory-item-bottom{display:flex;align-items:center;justify-content:space-between;gap:5px;min-height:16px;margin-top:auto;padding-top:5px}.inventory-item-price{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;color:#71d6a0;font-size:10px;font-weight:700;white-space:nowrap}.inventory-item-price.unavailable{color:#6e8084;font-size:8px;font-weight:500}.inventory-item-flags{flex:none;display:inline-flex;align-items:center;gap:3px;color:#607b80;font-size:8px;white-space:nowrap}.inventory-flag-tradable{color:#59dc91;font-weight:800}.inventory-flag-locked{color:#ff6f78;font-weight:700}.inventory-flag-marketable{color:#7d9aa0}.inventory-flag-separator{color:#405a60}.inventory-amount{position:absolute;right:7px;top:7px;border:1px solid #35545b;border-radius:5px;background:#0b181bcc;color:#b7d4d8;padding:2px 5px;font-size:8px}.inventory-empty{grid-column:1/-1;padding:50px 20px;text-align:center;color:#6f888d;font-size:11px;line-height:1.7}.inventory-loading{display:inline-block;color:#70ccd3}.inventory-refresh-btn{width:25px!important;min-width:25px;max-width:25px;flex:0 0 25px;align-self:center;height:25px;margin-left:5px;border:1px solid #315058;border-radius:6px;background:transparent;color:#75b9c0;cursor:pointer}.inventory-refresh-btn:hover{border-color:#55959e;color:#b7e6e9;background:#102429}.inventory-refresh-btn:disabled{opacity:.45;cursor:wait}

/* Functional: light outline controls instead of heavy filled buttons */
.functional-card{border:1px solid rgba(60,91,97,.55);border-radius:10px;background:rgba(8,20,23,.62);box-shadow:none}
.functional-card:before{display:none}.functional-card-title{color:#8fa9ad;font-weight:600;letter-spacing:.2px}
.functional-actions{gap:7px}.functional-actions button{height:31px!important;min-height:31px;padding:0 11px!important;border:1px solid #36565d!important;border-radius:6px!important;background:transparent!important;box-shadow:none!important;color:#9ab9be!important;font-size:10px!important;font-weight:500!important;letter-spacing:0;transition:border-color .15s,color .15s,background .15s!important;transform:none!important}
.functional-actions button:hover{border-color:#56858e!important;background:rgba(48,91,99,.12)!important;color:#d1e5e7!important;filter:none!important;transform:none!important}
.functional-actions button:active{background:rgba(48,91,99,.2)!important}.functional-actions button:disabled{opacity:.45;cursor:wait}
.functional-actions .marked-btn{border-color:#5d583c!important;color:#c4b982!important}.functional-actions .marked-btn:hover{border-color:#8b8051!important;background:rgba(112,98,45,.08)!important}
.functional-actions .check-vac-btn{border-color:#465866!important;color:#9eb4c5!important}.functional-actions .close-selected-btn,.functional-actions .close-steam-btn{border-color:#65464b!important;color:#c7959b!important;background:transparent!important}
.functional-actions .close-selected-btn:hover,.functional-actions .close-steam-btn:hover{border-color:#95636b!important;background:rgba(120,55,65,.08)!important}

.market-sell-modal{width:420px}.sell-item-preview{display:flex;align-items:center;gap:14px;margin:16px 0}.sell-item-preview img{width:92px;height:72px;object-fit:contain}.sell-item-name{color:#d2e4e6;font-size:12px;line-height:1.4}.sell-item-account{margin-top:6px;color:#718b90;font-size:10px}.market-field-label{display:block;margin:12px 0 6px;color:#8ca5aa;font-size:10px}.market-price-row{display:flex;align-items:center;gap:8px}.market-price-input,.buy-field input{height:35px;min-width:0;border:1px solid #36555c;border-radius:7px;background:#081519;color:#d7e9eb;padding:0 10px;outline:none}.market-price-input{flex:1}.market-price-input:focus,.buy-field input:focus{border-color:#57959f}.market-warning{margin:12px 0;color:#8b9895;font-size:9px;line-height:1.5}.market-primary-btn{width:100%;height:35px;border:1px solid #39755f;border-radius:7px;background:transparent;color:#79cfa6;cursor:pointer}.market-primary-btn:hover{background:#15352b}.market-primary-btn:disabled{opacity:.5;cursor:wait}
.buy-tf2{padding:15px 0;overflow-y:auto;height:590px}.buy-products{display:flex;gap:7px}.buy-product-btn{height:32px;border:1px solid #36545b;border-radius:6px;background:transparent;color:#9db7bc;padding:0 12px;cursor:pointer;font-size:10px}.buy-product-btn.active{border-color:#5c939c;color:#d2eaed;background:#12282d}.buy-order-layout{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}.buy-order-card{border:1px solid #294249;border-radius:9px;padding:12px;background:#091619}.buy-order-card h3{margin:0 0 10px;color:#9bb8bd;font-size:11px}.buy-order-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #172a2f;color:#88a2a7;font-size:10px}.buy-order-row b{color:#c4dadd;font-weight:600}.buy-order-row.buy b{color:#73d39e}.buy-order-row.sell b{color:#e0b578}.buy-create{margin-top:12px;border:1px solid #304c52;border-radius:9px;padding:13px;background:#0a181b}.buy-create-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.buy-field label{display:block;margin-bottom:5px;color:#80999e;font-size:9px}.buy-field input{width:100%;box-sizing:border-box}.buy-create .market-primary-btn{margin-top:12px}.buy-order-status{margin-top:9px;color:#6f8b90;font-size:9px}.buy-tf2-empty{color:#6f888d;text-align:center;padding:45px 10px}

.buy-tf2-modal{width:520px;max-height:92vh;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#35565e #091518}.buy-modal-icon{width:54px;height:48px;object-fit:contain;flex:none}.buy-product-grid{display:grid;grid-template-columns:repeat(2,minmax(0,260px));gap:14px;justify-content:center;padding-top:35px}.buy-product-card{border:1px solid #2c484e;border-radius:12px;background:linear-gradient(160deg,#0d1e22,#081518);padding:18px;text-align:center;min-width:0}.buy-product-card:hover{border-color:#456f77}.buy-product-image{height:125px;display:flex;align-items:center;justify-content:center;color:#52747a;font-size:24px;font-weight:700}.buy-product-image img{max-width:145px;max-height:115px;object-fit:contain;filter:drop-shadow(0 10px 14px rgba(0,0,0,.35))}.buy-product-name{min-height:36px;color:#c9dcdf;font-size:12px;line-height:1.45}.buy-product-price{min-height:30px;margin:8px 0 14px;color:#79a99a;font-size:10px;line-height:1.5}.buy-product-open{height:32px!important}.buy-tf2-modal .buy-order-layout{margin-top:14px}.buy-tf2-modal .buy-order-card{min-width:0}.buy-tf2-modal .buy-create{margin-top:10px}

/* Align account metric headers with avatar-offset content. */
.login-head-wrap{padding-left:45px;box-sizing:border-box}
.login-head-wrap #loginSort,.login-head-wrap #levelSort,.login-head-wrap #xpSort{padding-left:0;margin-left:0;flex:none}

.inventory{scrollbar-width:thin;scrollbar-color:#35565e #091518;overscroll-behavior:contain}.inventory::-webkit-scrollbar{width:7px}.inventory::-webkit-scrollbar-thumb{background:#35565e;border-radius:7px}.inventory::-webkit-scrollbar-track{background:#091518}
.inventory-item.selected{border-color:#4d9a83;box-shadow:inset 0 0 0 1px rgba(77,154,131,.18)}.inventory-select{position:absolute;left:7px;top:7px;z-index:2;width:20px;height:20px;display:flex;align-items:center;justify-content:center;border-radius:5px;background:#081517d9;cursor:pointer}.inventory-select input{width:13px;height:13px;margin:0;accent-color:#50bd94;cursor:pointer}
.inventory-trade-btn{height:25px;margin-left:5px;border:1px solid #315058;border-radius:6px;background:transparent;color:#75b9c0;cursor:pointer;font-size:9px}.inventory-trade-btn:hover{border-color:#55959e;background:#102429}.inventory-trade-modal{width:470px}.inventory-trade-select{width:100%;height:36px;border:1px solid #36555c;border-radius:7px;background:#081519;color:#c8dbde;padding:0 9px}.inventory-trade-items{max-height:145px;overflow-y:auto;margin-top:10px;border:1px solid #243d43;border-radius:7px;padding:7px}.inventory-trade-line{padding:4px 5px;color:#92aeb3;font-size:10px;border-bottom:1px solid #17292d}.inventory-trade-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.market-secondary-btn{border:1px solid #36555c;border-radius:7px;background:transparent;color:#9db9be;cursor:pointer}.market-secondary-btn:hover{background:#10252a}

.inventory-trade-btn{width:64px!important;min-width:64px;max-width:64px;flex:0 0 64px;align-self:center;white-space:nowrap;height:25px;padding:0 7px;border:1px solid #3d7068;border-radius:7px;background:rgba(36,91,78,.10);color:#86cdb6;font-size:10px;font-weight:600;letter-spacing:.15px;display:inline-flex;align-items:center;gap:5px;box-shadow:none;transition:border-color .15s,background .15s,color .15s}.inventory-trade-btn:hover{border-color:#65a795;background:rgba(55,125,104,.18);color:#b4ead5}.inventory-trade-btn:active{background:rgba(55,125,104,.25)}
.inventory-sell{position:absolute;right:7px;bottom:31px;z-index:2;width:23px;height:23px;border:1px solid #52664a;border-radius:6px;background:#0b1817dc;color:#a9c785;cursor:pointer;font-size:11px;line-height:1}.inventory-sell:hover{border-color:#8ba76d;background:#183027;color:#d1e9af}
.inventory-item{cursor:pointer}.inventory-item.selected{background:linear-gradient(160deg,#102a25,#0a1b18);border-color:#54a088}

.game-tabs{flex:1;min-width:0;flex-wrap:nowrap}.inventory-sort{flex:0 0 116px;width:116px;height:25px;margin:0;padding:0 6px;border:1px solid #315058;border-radius:6px;background:#0a171a;color:#8eaaaf;font-size:9px;outline:none;cursor:pointer}.inventory-sort:focus{border-color:#55959e;color:#c3dadd}.inventory-controls{display:flex;align-items:center;flex-direction:row;flex-wrap:nowrap;gap:5px;flex:0 0 auto;width:auto;height:25px;margin:0;padding:0}.inventory-controls .inventory-refresh-btn,.inventory-controls .inventory-trade-btn{display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;height:25px!important;min-height:25px!important;max-height:25px!important;margin:0!important;padding:0!important;line-height:1!important;vertical-align:top!important}.inventory-controls .inventory-refresh-btn{width:25px!important;min-width:25px!important;max-width:25px!important;flex:0 0 25px!important}.inventory-controls .inventory-trade-btn{width:64px!important;min-width:64px!important;max-width:64px!important;flex:0 0 64px!important;font-size:9px!important}

.inventory-trade-items{display:flex;flex-direction:row;align-items:stretch;gap:7px;max-height:none;overflow-x:auto;overflow-y:hidden;margin-top:10px;padding:8px;scrollbar-width:thin;scrollbar-color:#35565e #091518}.inventory-trade-thumb{flex:0 0 76px;width:76px;min-width:76px;border:1px solid #294249;border-radius:7px;background:#0a181b;padding:6px;box-sizing:border-box;text-align:center}.inventory-trade-thumb img{display:block;width:62px;height:48px;object-fit:contain;margin:0 auto 4px}.inventory-trade-thumb>div{height:23px;overflow:hidden;color:#a1b7bb;font-size:8px;line-height:1.35;word-break:break-word}.inventory-trade-empty{padding:12px;color:#718b90;font-size:10px}.inventory-trade-modal .market-warning{display:none!important}
.inventory-trade-thumb{cursor:pointer;transition:border-color .15s,opacity .15s}.inventory-trade-thumb:hover{border-color:#a25e66;opacity:.72}.inventory-trade-thumb:hover>div{color:#e5a0a6}

.inventory-select{width:17px;height:17px;left:7px;top:7px;border:1px solid #426168;border-radius:5px;background:rgba(7,18,20,.88);box-shadow:0 2px 6px rgba(0,0,0,.18);transition:border-color .15s,background .15s,box-shadow .15s}
.inventory-select:hover{border-color:#71a69c;background:#102722}.inventory-select input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
.inventory-checkmark{position:relative;display:block;width:100%;height:100%;pointer-events:none}.inventory-checkmark:after{content:"";position:absolute;left:5px;top:2px;width:4px;height:8px;border:solid #e4fff4;border-width:0 2px 2px 0;border-radius:1px;transform:rotate(45deg) scale(0);opacity:0;transition:transform .14s,opacity .14s}
.inventory-select:has(input:checked){border-color:#58b393;background:#327d62;box-shadow:0 0 0 2px rgba(72,168,132,.12)}.inventory-select input:checked+.inventory-checkmark:after{transform:rotate(45deg) scale(1);opacity:1}

/* Functional: only the buttons have decorative outlines, never whole panels. */
.functional-grid{display:flex;flex-direction:column;gap:15px}
.functional-card,.functional-card.full{position:static;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;padding:0!important;margin:0!important}
.functional-card:before{display:none!important}
.functional-actions{display:flex;flex-wrap:wrap;gap:9px}
.functional-actions button{position:relative;height:38px!important;min-height:38px;min-width:112px;padding:0 16px!important;border:1px solid transparent!important;border-radius:8px!important;background:linear-gradient(rgba(9,23,27,.94),rgba(9,23,27,.94)) padding-box,linear-gradient(115deg,#28515a,#65d9df 48%,#28515a) border-box!important;box-shadow:0 0 0 1px rgba(59,191,201,.04),0 0 12px rgba(54,192,203,.07)!important;color:#b9e4e7!important;font-size:11px!important;font-weight:600!important;transition:box-shadow .18s,filter .18s,color .18s!important}
.functional-actions button:hover{border-color:transparent!important;background:linear-gradient(rgba(14,34,39,.96),rgba(14,34,39,.96)) padding-box,linear-gradient(115deg,#4b8e98,#8df4f5 48%,#4b8e98) border-box!important;box-shadow:0 0 15px rgba(74,218,225,.17)!important;color:#ecffff!important;filter:none!important}
.functional-actions .marked-btn{background:linear-gradient(rgba(25,25,17,.94),rgba(25,25,17,.94)) padding-box,linear-gradient(115deg,#5b512c,#e0c96f 48%,#5b512c) border-box!important;color:#e5d593!important;box-shadow:0 0 12px rgba(218,192,96,.06)!important}
.functional-actions .check-vac-btn{background:linear-gradient(rgba(13,20,29,.94),rgba(13,20,29,.94)) padding-box,linear-gradient(115deg,#344e66,#8cb9df 48%,#344e66) border-box!important;color:#bdd4e8!important}
.functional-actions .close-selected-btn,.functional-actions .close-steam-btn{background:linear-gradient(rgba(27,16,20,.94),rgba(27,16,20,.94)) padding-box,linear-gradient(115deg,#60343f,#d17c8b 48%,#60343f) border-box!important;color:#e5abb4!important;box-shadow:0 0 12px rgba(194,91,107,.05)!important}
.refresh-data-progress{margin:8px 0 0;color:#78969b;font-size:10px;min-height:0}
.refresh-data-progress:empty{display:none}

/* Buy TF2 always owns the full inventory width, even if inventory grid was restored. */
#inventory:has(.buy-tf2){display:block}
.buy-tf2{width:100%;box-sizing:border-box;grid-column:1/-1}
.buy-product-grid{width:100%;box-sizing:border-box;grid-template-columns:repeat(2,minmax(220px,280px));justify-content:center;gap:16px}
.buy-product-card{width:100%;box-sizing:border-box;min-width:0}
.buy-product-name{overflow-wrap:normal;word-break:normal}
.buy-product-open{width:100%;white-space:nowrap;padding:0 10px!important}

.buy-order-summary{margin-top:10px;padding-top:10px;border-top:1px solid rgba(57,88,94,.38);display:flex;align-items:center;justify-content:space-between;gap:12px}.buy-order-total{color:#d9eeee;font-size:11px;font-weight:700;text-align:left}.buy-order-balance{color:#b8d5d8;font-size:11px;font-weight:600;text-align:right}
.buy-active-orders{margin-top:10px;border:1px solid #304c52;border-radius:9px;padding:11px 13px;background:#091619}.buy-active-orders h3{margin:0 0 7px;color:#9bb8bd;font-size:11px}.buy-active-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:7px 0;border-top:1px solid #172a2f}.buy-active-info{min-width:0;display:flex;align-items:center;gap:9px}.buy-active-info b{color:#73d39e;font-size:11px;white-space:nowrap}.buy-active-info span{color:#89a3a8;font-size:9px;white-space:nowrap}.buy-active-cancel{flex:0 0 auto;height:26px;padding:0 9px;border:1px solid #6d3c43;border-radius:6px;background:transparent;color:#ed8992;font-size:9px;cursor:pointer}.buy-active-cancel:hover{background:#2d181c;border-color:#a6535d}.buy-active-cancel:disabled{opacity:.45;cursor:wait}.buy-active-empty{padding:5px 0;color:#617d82;font-size:9px}.buy-active-main{max-width:545px;margin:16px auto 0;padding:12px 14px}.buy-active-main .buy-active-info{min-width:0}.buy-active-item{min-width:0}.buy-active-item>b{display:block;overflow:hidden;text-overflow:ellipsis;color:#c6dadd;font-size:10px;white-space:nowrap}.buy-active-item>span{display:block;margin-top:4px;color:#7f9ca1;font-size:9px;white-space:nowrap}.buy-active-main .buy-active-row:first-child{border-top:0}
.lock-calendar-modal{width:min(790px,94%);max-height:86%;display:flex;flex-direction:column}.lock-calendar-toolbar,.lock-calendar-actions{display:flex;gap:8px;padding:12px 16px 0}.lock-calendar-toolbar .bulk-select{flex:1}.lock-calendar-toolbar button{min-width:175px}.lock-calendar-actions{padding-top:8px}.lock-calendar-actions button{flex:1;height:31px}.lock-calendar-view-tabs{display:flex;gap:6px;padding:10px 16px 0}.lock-calendar-view-tabs button{flex:1;height:31px;border:1px solid #29474c;border-radius:6px;background:#0a191c;color:#779398;font-size:10px;cursor:pointer}.lock-calendar-view-tabs button.active{border-color:#4c8791;background:#10262b;color:#c7e2e5}.lock-calendar-view-tabs span{display:inline-block;min-width:17px;margin-left:4px;padding:1px 4px;border-radius:8px;background:#1b343a;color:#a9c4c8;font-size:9px}.lock-calendar-status{padding:10px 16px 7px;color:#78959b;font-size:10px;line-height:1.45}.lock-calendar-list{margin:0 16px 16px;overflow-y:auto;min-height:90px;border:1px solid #29434a;border-radius:8px;background:#081518;scrollbar-width:thin;scrollbar-color:#35565e #091518}.lock-calendar-row{display:grid;grid-template-columns:145px minmax(0,1fr) 142px;align-items:center;gap:12px;min-height:66px;padding:8px 12px;border-bottom:1px solid #1b3035}.lock-calendar-row:last-child{border-bottom:0}.lock-calendar-login{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#d1e3e5;font-size:11px;font-weight:700}.lock-calendar-item{display:flex;align-items:center;gap:10px;min-width:0}.lock-calendar-item img{flex:0 0 48px;width:48px;height:42px;object-fit:contain}.lock-calendar-item-text{min-width:0}.lock-calendar-item-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#b7cccf;font-size:10px}.lock-calendar-game{margin-top:4px;color:#66878d;font-size:9px}.lock-calendar-date{text-align:right;color:#ef8d8d;font-size:10px;line-height:1.45}.lock-calendar-date small{display:block;color:#806f72;font-size:8px}.lock-calendar-row.history .lock-calendar-date{color:#70d19c}.lock-calendar-row.history .lock-calendar-date small{color:#608a73}.lock-calendar-empty{padding:28px 16px;text-align:center;color:#6e898f;font-size:10px;line-height:1.6}.bulk-trade-modal{width:min(620px,92%);max-height:88%;display:flex;flex-direction:column}.bulk-trade-body{padding:3px 16px 16px;overflow-y:auto}.bulk-trade-input,.bulk-select{height:36px;min-width:0;border:1px solid #36555c;border-radius:7px;background:#081519;color:#c8dbde;padding:0 9px;outline:none}.bulk-trade-input{width:100%;box-sizing:border-box}.bulk-trade-input:focus,.bulk-select:focus{border-color:#57959f}.bulk-trade-form{display:grid;grid-template-columns:1fr 150px;gap:8px;margin-top:9px}.bulk-trade-warning{margin:12px 0;color:#839b9f;font-size:9px;line-height:1.55}.bulk-trade-actions{display:grid;grid-template-columns:1fr 135px;gap:8px}.bulk-trade-actions .market-secondary-btn{height:35px}.bulk-trade-status{margin-top:11px;color:#91acb1;font-size:10px;line-height:1.5}.bulk-trade-log{margin-top:8px;max-height:190px;overflow-y:auto;border-top:1px solid #243b41}.bulk-trade-log-row{display:grid;grid-template-columns:145px minmax(0,1fr);gap:10px;padding:8px 3px;border-bottom:1px solid #192d32;font-size:9px}.bulk-trade-log-login{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#bdd1d4}.bulk-trade-log-message{color:#78969b;line-height:1.4}.bulk-trade-log-row.success .bulk-trade-log-message{color:#70d19c}.bulk-trade-log-row.error .bulk-trade-log-message{color:#ed8c95}.bulk-trade-log-row.waiting .bulk-trade-log-message{color:#d1b875}.bulk-operation-modal{width:min(760px,94%);max-height:90%;display:flex;flex-direction:column}.bulk-operation-grid{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px;margin-bottom:8px}.bulk-operation-load{width:100%;height:35px}.bulk-operation-list-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:10px 0 6px;color:#8ca7ac;font-size:10px}.bulk-operation-list-head button{width:auto;min-width:125px;height:28px}.bulk-operation-list{max-height:260px;min-height:70px;overflow-y:auto;border:1px solid #29434a;border-radius:8px;background:#081518;scrollbar-width:thin}.bulk-operation-row{display:grid;grid-template-columns:24px 48px minmax(0,1fr) 175px;align-items:center;gap:9px;min-height:58px;padding:7px 10px;border-bottom:1px solid #1b3035}.bulk-operation-row:last-child{border-bottom:0}.bulk-operation-row input{width:16px;height:16px;accent-color:#43cbd3;cursor:pointer}.bulk-operation-row img{width:46px;height:40px;object-fit:contain}.bulk-operation-name{min-width:0;color:#c2d7da;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bulk-operation-account{margin-top:4px;color:#6f8e94;font-size:9px}.bulk-operation-price{text-align:right;color:#79d6a4;font-size:10px;line-height:1.5}.bulk-operation-price small{display:block;color:#769399;font-size:8px}.bulk-operation-row.error{opacity:.55}.bulk-operation-empty{padding:25px 12px;text-align:center;color:#6e898f;font-size:10px;line-height:1.5}

/* Yellow entry point and compact Steam-style market books. */
.functional-actions #bulkSellBtn{background:linear-gradient(rgba(35,30,12,.96),rgba(35,30,12,.96)) padding-box,linear-gradient(115deg,#6b5b25,#f5d365 48%,#6b5b25) border-box!important;color:#ffe082!important;box-shadow:0 0 14px rgba(245,211,101,.10)!important}
.functional-actions #bulkSellBtn:hover{background:linear-gradient(rgba(52,43,15,.98),rgba(52,43,15,.98)) padding-box,linear-gradient(115deg,#a88b35,#fff0a0 48%,#a88b35) border-box!important;color:#fff3b0!important;box-shadow:0 0 18px rgba(245,211,101,.20)!important}
#bulkSellModal .file-modal-icon{border-color:#806b2d;background:#2b2512;color:#ffdc68}
.modal-refresh-btn{margin-left:auto;width:34px;height:34px;flex:0 0 34px;border:1px solid #3c6971;border-radius:9px;background:linear-gradient(180deg,#12282d,#0a191d);color:#79dce3;font-size:19px;line-height:1;cursor:pointer;transition:border-color .15s,color .15s,background .15s,transform .15s}
.modal-refresh-btn:hover{border-color:#68cbd4;background:#17343a;color:#d9ffff;transform:translateY(-1px)}
.modal-refresh-btn:disabled{opacity:.5;cursor:wait;transform:none}
.modal-refresh-btn.loading{color:#ffe082;border-color:#9d8136;animation:marketRefreshSpin .85s linear infinite}
.file-modal-head .modal-refresh-btn+.modal-close{margin-left:6px}
@keyframes marketRefreshSpin{to{transform:rotate(360deg)}}
.bulk-sell-modal{width:min(880px,92%);max-height:84%}
#bulkSellModal .bulk-trade-body{padding-top:12px}#bulkSellModal .bulk-trade-warning{margin:9px 0}
.bulk-sell-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px}
.bulk-sell-actions .bulk-operation-load{height:35px}
#bulkSellList{max-height:300px;scrollbar-color:#35565e #091518}
.bulk-operation-row.bulk-sell-row{grid-template-columns:20px minmax(165px,1fr) 155px minmax(275px,1.4fr);gap:10px;align-items:stretch;min-height:138px;padding:8px 10px;background:linear-gradient(145deg,rgba(11,27,31,.72),rgba(7,18,21,.72))}
.bulk-operation-row.bulk-sell-row:hover{background:linear-gradient(145deg,rgba(15,34,38,.82),rgba(8,21,24,.82))}
.bulk-operation-row.bulk-sell-row>input{align-self:center}
.bulk-sell-item{display:flex;align-items:center;gap:9px;min-width:0}
.bulk-sell-icon{width:52px;height:54px;flex:0 0 52px;display:flex;align-items:center;justify-content:center;border:1px solid #29474d;border-radius:8px;background:#081518}
.bulk-operation-row .bulk-sell-icon img{width:47px;height:45px;object-fit:contain;filter:drop-shadow(0 5px 7px rgba(0,0,0,.35))}
.bulk-sell-item-copy{min-width:0}
.bulk-sell-item-copy .bulk-operation-name{white-space:normal;line-height:1.35}
.bulk-sell-price{display:flex;flex-direction:column;align-items:stretch;justify-content:center;min-width:0;padding:0 8px;border-left:1px solid #1d353a;border-right:1px solid #1d353a;text-align:left}
.bulk-sell-price-label{color:#769298;font-size:8px;text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px}
.bulk-sell-price-editor{display:flex;align-items:center;gap:5px}.bulk-sell-price-editor span{color:#8ca7ac;font-size:9px;flex:none}
.bulk-operation-row .bulk-sell-price-input{width:100%;min-width:0;height:32px;padding:0 8px;border:1px solid #3b5c63;border-radius:7px;background:#071417;color:#ffe082;font-size:12px;font-weight:700;outline:none;font-variant-numeric:tabular-nums}
.bulk-operation-row .bulk-sell-price-input:focus{border-color:#65cbd3;box-shadow:0 0 0 2px rgba(80,203,211,.08)}
.bulk-operation-row .bulk-sell-price-input:disabled{opacity:.6;cursor:wait}
.bulk-sell-price small{display:block;margin-top:6px;color:#769399;font-size:8px;line-height:1.4}
.bulk-sell-price .bulk-sell-price-error{color:#ed9aa3}.bulk-sell-price .bulk-sell-manual{color:#c7b96f}
.bulk-sell-book{display:grid;grid-template-columns:1fr 1fr;gap:7px;min-width:0}
.bulk-sell-book-side{min-width:0;padding:6px 8px;border:1px solid #29434a;border-radius:8px;background:#071417}
.bulk-sell-book-title{margin-bottom:4px;color:#8ca7ac;font-size:8px;font-weight:700;white-space:nowrap}
.bulk-sell-book-row{display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:19px;border-bottom:1px solid rgba(37,61,66,.45);font-size:9px;font-variant-numeric:tabular-nums}
.bulk-sell-book-row:last-child{border-bottom:0}
.bulk-sell-book-row b{color:#dfb474;font-weight:650;white-space:nowrap}
.bulk-sell-book-side.buy .bulk-sell-book-row b{color:#78d5a3}
.bulk-sell-book-row span{color:#789298;white-space:nowrap}
.bulk-sell-book-empty{grid-column:1/-1;display:flex;align-items:center;justify-content:center;min-height:80px;padding:10px;border:1px dashed #29434a;border-radius:8px;color:#607e84;font-size:9px;text-align:center;line-height:1.5}
@media(max-width:950px){.bulk-operation-row.bulk-sell-row{grid-template-columns:20px minmax(145px,1fr) 140px minmax(235px,1.2fr);gap:7px}.bulk-sell-price{padding:0 6px}}

/* Inventory quick sale and item context menu. */
.inventory-controls{gap:3px}
.inventory-controls .inventory-trade-btn{width:52px!important;min-width:52px!important;max-width:52px!important;flex-basis:52px!important;padding:0 4px!important}
.inventory-sell-btn{width:58px!important;min-width:58px;max-width:58px;height:25px;padding:0 5px;border:1px solid #8a7334;border-radius:6px;background:rgba(112,88,24,.12);color:#f2d575;cursor:pointer;font-size:9px;font-weight:650;white-space:nowrap;transition:.15s}
.inventory-sell-btn:hover{border-color:#d4b654;background:rgba(147,115,29,.20);color:#fff0a6}
.inventory-lots-btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;flex:0 0 auto;width:auto;min-width:62px;height:25px;padding:0 8px;border:1px solid #315058;border-radius:6px;background:#0a171a;color:#8eaaaf;font-size:9px;font-weight:650;white-space:nowrap;cursor:pointer;transition:.15s}.inventory-lots-btn span{min-width:15px;padding:1px 4px;box-sizing:border-box;border-radius:7px;background:#172b30;color:#a9c7cc;font-size:8px;line-height:13px;text-align:center}.inventory-lots-btn:hover{border-color:#55959e;color:#d2e7e9;background:#102429}.inventory-lots-btn.active{border-color:#4f9d82;background:rgba(47,133,102,.15);color:#7fe0b1}.inventory-lots-btn.active span{background:rgba(70,175,130,.2);color:#9aefc4}.inventory-lots-btn:disabled{opacity:.45;cursor:wait}
.market-lots-panel{width:min(680px,100%);max-width:680px;margin:12px auto;padding:12px 14px}.market-lots-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:5px}.market-lots-heading h3{margin:0}.market-lots-balance{color:#75d6a3;font-size:10px;white-space:nowrap}.market-lot-icon{flex:0 0 52px;width:52px;height:52px;display:flex;align-items:center;justify-content:center;overflow:hidden;border:1px solid #233d43;border-radius:7px;background:#0d1d21}.market-lot-icon img{display:block;max-width:48px;max-height:48px;object-fit:contain}.market-lot-prices{flex:0 0 auto;text-align:right;white-space:nowrap}.market-lot-prices b{display:block;color:#79dba6;font-size:11px}.market-lot-prices span{display:block;margin-top:4px;color:#7f9ca1;font-size:9px}.market-lots-warning{margin-top:8px;color:#c7a96a;font-size:9px;line-height:1.5}.market-lots-footnote{margin-top:8px;color:#617d82;font-size:9px}.market-lot-row .buy-active-info{flex:1;min-width:0}.market-lot-row .market-lot-prices b{font-size:10px}.market-lot-remove{margin-left:2px}.market-lots-balance{font-weight:700}.market-lots-remove-all{position:absolute;right:0;top:77px;z-index:4;display:none;height:30px;padding:0 12px;border:1px solid #79434d;border-radius:7px;background:#29171c;color:#eda1ab;font-size:10px;font-weight:600;cursor:pointer;box-shadow:0 5px 16px rgba(0,0,0,.16);transition:background .15s,border-color .15s,color .15s}.market-lots-remove-all.show{display:block}.market-lots-remove-all:hover{background:#3a1e26;border-color:#c87583;color:#ffd0d6}.market-lots-remove-all:disabled{opacity:.45;cursor:wait}
.inventory-sort{flex-basis:82px;width:82px}
.inventory-context-menu{position:fixed;z-index:999999;width:238px;padding:7px;border:1px solid #3b626a;border-radius:11px;background:linear-gradient(155deg,rgba(17,35,39,.99),rgba(7,18,21,.99));box-shadow:0 18px 50px rgba(0,0,0,.68),inset 0 1px rgba(255,255,255,.035);display:none}
.inventory-context-menu.show{display:block}
.inventory-context-title{padding:6px 8px 10px;overflow:hidden;text-overflow:ellipsis;color:#8ca8ad;font-size:9px;white-space:nowrap;border-bottom:1px solid #213a40}
.inventory-context-sell{width:100%;min-height:52px;margin-top:6px;padding:8px 10px;display:flex;align-items:center;gap:11px;border:1px solid #7d692e;border-radius:8px;background:linear-gradient(145deg,rgba(66,53,18,.45),rgba(30,27,15,.45));color:#f4d979;text-align:left;cursor:pointer;transition:.15s}
.inventory-context-sell>span{width:29px;height:29px;display:flex;align-items:center;justify-content:center;border:1px solid #a18838;border-radius:7px;background:#2c2512;font-size:16px;font-weight:800}
.inventory-context-sell b{display:block;color:#ffe69a;font-size:11px}.inventory-context-sell small{display:block;margin-top:4px;color:#9e9168;font-size:8px}
.inventory-context-sell:hover{border-color:#d0ae4d;background:linear-gradient(145deg,rgba(92,72,21,.58),rgba(39,32,15,.58));transform:translateY(-1px)}
.inventory-context-sell:disabled{opacity:.42;cursor:not-allowed;transform:none}
.sell-item-market-modal{width:880px;max-width:94%;max-height:92vh;overflow-y:auto}
.sell-item-market-body{padding:16px 18px 18px}
.sell-item-market-modal .sell-item-preview{margin:0 0 15px;padding:12px 14px;border:1px solid #29464c;border-radius:10px;background:linear-gradient(145deg,rgba(14,31,35,.85),rgba(8,20,23,.85))}
.sell-item-preview-icon{width:96px;height:76px;display:flex;align-items:center;justify-content:center;flex:0 0 96px;border:1px solid #2d4c52;border-radius:9px;background:#081518}
.sell-item-market-modal .sell-item-preview img{width:88px;height:68px;object-fit:contain;filter:drop-shadow(0 7px 10px rgba(0,0,0,.35))}
.sell-item-market-modal .sell-item-name{color:#f0df9a;font-size:15px;font-weight:650}
.sell-item-game{margin-top:5px;color:#617f85;font-size:9px}
.sell-item-workspace{display:grid;grid-template-columns:minmax(250px,.9fr) minmax(390px,1.35fr);gap:13px;align-items:stretch}
.sell-item-settings{padding:13px;border:1px solid #304c52;border-radius:10px;background:#0a181b}
.sell-item-section-title{margin-bottom:11px;color:#d3e6e8;font-size:12px;font-weight:700}
.sell-item-quote-summary{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:13px}
.sell-item-quote-summary>div{padding:8px 9px;border:1px solid #263f45;border-radius:7px;background:#081518}
.sell-item-quote-summary span{display:block;color:#728e94;font-size:8px}.sell-item-quote-summary b{display:block;margin-top:5px;color:#83d8ae;font-size:12px}.sell-item-quote-summary>div:first-child b{color:#dfb474}
.sell-item-suggested{width:100%;height:31px;margin-top:8px;font-size:9px}
.sell-item-net{margin-top:8px;color:#8fb0b5;font-size:9px;line-height:1.45}.sell-item-net b{color:#83d8ae;font-weight:700}
.sell-item-settings .market-warning{margin:10px 0}
.sell-item-book{display:grid;grid-template-columns:1fr 1fr;gap:10px;min-width:0}
.sell-item-book .buy-order-card{min-width:0;margin:0;padding:12px}
.sell-item-book .buy-order-row{min-height:27px;font-size:10px}
@media(max-width:900px){.sell-item-workspace{grid-template-columns:1fr}.sell-item-book{min-height:250px}.inventory-sort{flex-basis:76px;width:76px}}

.booster-modal{width:480px;max-width:calc(100vw - 38px)}
.booster-body{padding:16px 18px 18px}.booster-body .bulk-trade-input{width:100%;box-sizing:border-box;margin-top:7px;height:38px}
.booster-hint{margin-top:11px;padding:10px 11px;border:1px solid #29474c;border-radius:8px;background:#091619;color:#78969b;font-size:10px;line-height:1.6}.booster-hint b{color:#e1c76f}
.booster-targets{margin:13px 0 9px;color:#8fcbd0;font-size:10px;font-weight:700}.booster-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.booster-actions button{height:35px}.booster-stop{width:100%;height:33px;margin-top:8px}.booster-status{min-height:18px;margin-top:11px;color:#78969b;font-size:9px;line-height:1.5}
.account-booster-modal{width:350px;max-width:calc(100vw - 38px)}.account-booster-body{padding:16px 18px 18px}.account-booster-login{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:15px;padding:11px 12px;border:1px solid #29474c;border-radius:9px;background:#091619;color:#78969b;font-size:10px}.account-booster-login b{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#8de0e7;font-size:11px}.account-booster-body .bulk-trade-input{width:100%;box-sizing:border-box;margin-top:7px;height:39px}.account-booster-hint{margin:9px 0 14px;color:#718d93;font-size:9px;line-height:1.55}.account-booster-save{width:100%;height:39px;border:1px solid #3b9ca5;border-radius:9px;background:linear-gradient(180deg,#1b5159,#12373e);box-shadow:inset 0 1px rgba(255,255,255,.06),0 5px 15px rgba(0,0,0,.18);color:#a2f1f3;font-size:11px;font-weight:700;cursor:pointer;transition:border-color .15s,filter .15s,transform .15s}.account-booster-save:hover{border-color:#65dce2;filter:brightness(1.14);transform:translateY(-1px)}.account-booster-save:active{transform:translateY(0)}.account-booster-save:disabled{opacity:.55;cursor:wait;transform:none}.account-booster-status{min-height:17px;margin-top:11px;color:#78969b;font-size:9px;line-height:1.45;text-align:center}

.session-reload-progress{position:fixed;right:24px;bottom:24px;z-index:999999;width:320px;padding:13px 14px;border:1px solid #315b63;border-radius:11px;background:linear-gradient(145deg,#102126,#091519);box-shadow:0 14px 45px rgba(0,0,0,.68);display:none}.session-reload-progress.show{display:block}.session-reload-head{display:flex;align-items:center;justify-content:space-between;color:#d8e9eb;font-size:11px}.session-reload-head span{color:#64dce2;font-weight:700}.session-reload-bar{height:6px;margin-top:10px;border-radius:8px;background:#172a2e;overflow:hidden}.session-reload-bar>div{height:100%;width:0;background:linear-gradient(90deg,#2bbbc5,#61e0e5);transition:width .25s}.session-reload-current{margin-top:8px;color:#a8bdc1;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.session-reload-stats{margin-top:5px;color:#708e94;font-size:9px}.session-reload-progress button{width:100%;height:28px;margin-top:10px;border:1px solid #70434a;border-radius:7px;background:#2c181c;color:#ed9aa3;font-size:9px;cursor:pointer}.session-reload-progress button:disabled{opacity:.5;cursor:wait}

.auto-session-button{position:relative;display:inline-flex;align-items:center;justify-content:space-between;gap:15px;height:38px!important;min-height:38px;min-width:205px;padding:0 10px 0 16px!important;border:1px solid transparent!important;border-radius:8px!important;background:linear-gradient(rgba(9,23,27,.94),rgba(9,23,27,.94)) padding-box,linear-gradient(115deg,#28515a,#65d9df 48%,#28515a) border-box!important;box-shadow:0 0 0 1px rgba(59,191,201,.04),0 0 12px rgba(54,192,203,.07)!important;color:#b9e4e7!important;font-size:11px!important;font-weight:600!important;cursor:pointer;transition:box-shadow .18s,color .18s!important}.auto-session-button:hover{background:linear-gradient(rgba(14,34,39,.96),rgba(14,34,39,.96)) padding-box,linear-gradient(115deg,#4b8e98,#8df4f5 48%,#4b8e98) border-box!important;color:#ecffff!important;box-shadow:0 0 15px rgba(74,218,225,.17)!important}.auto-session-button .switch{width:37px;height:21px}.auto-session-button .switch-slider:before{width:13px;height:13px}.auto-session-button .switch input:checked+.switch-slider:before{transform:translateX(15px)}.session-badge.booster-badge{color:#68797d}.session-badge.booster-badge.online{color:#58cda0}
.functional-booster-btn{height:35px;min-height:35px;padding:0 15px}.steam-path-title{margin-bottom:9px;color:#bcd3d7;font-size:11px;font-weight:700}.steam-path-row{display:flex;align-items:center;gap:8px}.steam-path-input{min-width:0;flex:1;height:36px;box-sizing:border-box;padding:0 11px;border:1px solid #34515a;border-radius:7px;background:#09171b;color:#c9dadd;font-size:10px;outline:none}.steam-path-input:focus{border-color:#50cbd3}.steam-path-status{min-height:15px;margin-top:8px;color:#718d93;font-size:9px;line-height:1.5}.steam-path-status.success{color:#65d69a}.steam-path-status.error{color:#ed929b}
/* Functional actions use stable individual colors instead of one shared shimmer. */
#functionalPanel .functional-actions button{--action-bg:#10262c;--action-hover:#17353c;--action-border:#42646c;--action-color:#b9d7dc;--action-glow:rgba(100,180,190,.10);background:var(--action-bg)!important;border:1px solid var(--action-border)!important;box-shadow:inset 0 1px rgba(255,255,255,.025)!important;color:var(--action-color)!important}
#functionalPanel .functional-actions button:hover{background:var(--action-hover)!important;border-color:var(--action-color)!important;box-shadow:0 0 12px var(--action-glow)!important;color:var(--action-color)!important;filter:none!important}
#functionalPanel .functional-actions button:active{background:var(--action-bg)!important;box-shadow:none!important}
#functionalPanel .functional-actions #getLevelBtn{--action-bg:#102634;--action-hover:#153447;--action-border:#386b88;--action-color:#91c9ed;--action-glow:rgba(90,165,215,.14)}
#functionalPanel .functional-actions #markedBtn{--action-bg:#292513;--action-hover:#383117;--action-border:#7c6a32;--action-color:#e7d183;--action-glow:rgba(220,190,85,.12)}
#functionalPanel .functional-actions #checkVacBtn{--action-bg:#201b31;--action-hover:#2b2340;--action-border:#625489;--action-color:#c4b1ed;--action-glow:rgba(165,135,225,.13)}
#functionalPanel .functional-actions #tradeBanCalendarBtn{--action-bg:#29192d;--action-hover:#38203e;--action-border:#794b82;--action-color:#dca5e6;--action-glow:rgba(205,125,220,.12)}
#functionalPanel .functional-actions #bulkSellBtn{--action-bg:#302811;--action-hover:#403617;--action-border:#88712d;--action-color:#ffe082;--action-glow:rgba(245,211,101,.15)}
#functionalPanel .functional-actions #bulkTradeBtn{--action-bg:#102923;--action-hover:#15372f;--action-border:#2c766c;--action-color:#79dbc7;--action-glow:rgba(80,205,180,.13)}
#functionalPanel .functional-actions #itemCollectorBtn{--action-bg:#2b2117;--action-hover:#3a2c1e;--action-border:#765b3b;--action-color:#dfb98c;--action-glow:rgba(210,165,110,.12)}
#functionalPanel .functional-actions #launchSelectedSteamBtn{--action-bg:#12271b;--action-hover:#193525;--action-border:#34724c;--action-color:#8ce0aa;--action-glow:rgba(95,210,140,.13)}
#functionalPanel .functional-actions #closeSelectedSteamBtn{--action-bg:#2c1922;--action-hover:#3b202d;--action-border:#794155;--action-color:#e7a5b7;--action-glow:rgba(215,115,150,.12)}
#functionalPanel .functional-actions #closeAllSteamBtn{--action-bg:#2d171a;--action-hover:#3d1d22;--action-border:#79373d;--action-color:#ef9aa2;--action-glow:rgba(225,95,110,.12)}
#functionalPanel .functional-actions #addGamesAllBtn{--action-bg:#1c2914;--action-hover:#26381b;--action-border:#527a36;--action-color:#b3e698;--action-glow:rgba(145,215,105,.13)}
#functionalPanel .functional-actions #boosterFunctionalBtn{--action-bg:#2d2014;--action-hover:#3d2b1b;--action-border:#81552e;--action-color:#f0b377;--action-glow:rgba(230,155,80,.13)}
#functionalPanel .auto-session-button{background:#101f2b!important;border:1px solid #355d7a!important;box-shadow:none!important;color:#9cc9e8!important}
#functionalPanel .auto-session-button:hover{background:#152b3b!important;border-color:#71a9cf!important;box-shadow:0 0 12px rgba(90,155,205,.12)!important;color:#c2e2f7!important}
.functional-card.steam-path-card{margin-top:2px!important;padding:14px 15px!important;border:1px solid #3b6878!important;border-radius:10px!important;background:linear-gradient(145deg,rgba(14,31,40,.96),rgba(8,20,27,.96))!important;box-shadow:inset 0 1px rgba(255,255,255,.025),0 0 16px rgba(65,135,160,.07)!important}
.steam-path-card .steam-path-title{color:#a8d3e6}.steam-path-card .steam-path-input{border-color:#3c6577;background:#08171f}.steam-path-card .steam-path-input:focus{border-color:#78b9d8;box-shadow:0 0 0 2px rgba(95,170,205,.09)}
#steamPathBrowseBtn,#steamPathSaveBtn{height:36px;white-space:nowrap;border-radius:7px;font-size:10px;font-weight:600;cursor:pointer;box-shadow:none;transition:background .15s,border-color .15s,color .15s}#steamPathBrowseBtn{border:1px solid #34766f;background:#112c2b;color:#91d9cb}#steamPathBrowseBtn:hover{background:#183b38;border-color:#68c8b6;color:#c5f4e9}#steamPathSaveBtn{border:1px solid #3d6f9b;background:#12273a;color:#9dc9ef}#steamPathSaveBtn:hover{background:#19354e;border-color:#83bce8;color:#d0eaff}#steamPathBrowseBtn:disabled,#steamPathSaveBtn:disabled{opacity:.5;cursor:wait}
.activity-notifications{position:fixed;right:24px;bottom:24px;z-index:999998;width:340px;max-width:calc(100vw - 48px);display:flex;flex-direction:column;gap:8px;pointer-events:none}.session-reload-progress.show+.activity-notifications{bottom:190px}.activity-notification{box-sizing:border-box;width:100%;padding:11px 12px;border:1px solid #315b63;border-radius:10px;background:linear-gradient(145deg,rgba(16,33,38,.98),rgba(8,20,24,.98));box-shadow:0 12px 34px rgba(0,0,0,.55);pointer-events:auto;animation:activity-notify-in .18s ease-out}.activity-notification.success{border-color:#2f7658}.activity-notification.error{border-color:#81454e}.activity-notification-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.activity-notification-title{color:#7edce2;font-size:9px;font-weight:800;letter-spacing:.4px;text-transform:uppercase}.activity-notification.success .activity-notification-title{color:#70dca0}.activity-notification.error .activity-notification-title{color:#ef929b}.activity-notification-time{color:#5f7d82;font-size:8px}.activity-notification-message{margin-top:5px;color:#c3d7da;font-size:10px;line-height:1.45;word-break:break-word}@keyframes activity-notify-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<div class="app">
<div class="top-nav"><button class="top-tab active" id="statisticTab">▣ &nbsp;Statistic</button><button class="top-tab" id="functionalTab">⚙ &nbsp;Functional</button><button class="top-tab" id="gamesTopTab">🎮 &nbsp;Games</button></div>
<div class="main">
<section class="left">
<div class="stats"><div class="stat">♟ Всего: <strong id="totalCount">0</strong></div><div class="stat green">● Авторизовано: <strong id="authCount">0</strong></div><div class="stat">★ Отмечено: <strong id="markedCount">0</strong></div></div>
<div class="toolbar">
<input id="search" class="search" placeholder="Search by login" autocomplete="off">
<span class="selection-count" id="selectionCount">0 выбрано</span>
<button class="pill blue" id="importBtn">▣ Импорт</button>
<button class="pill refresh-pill" id="refreshBtn">↻ Обновить</button>
<button class="pill orange" id="authBtn">⇥ Auth All</button>
<button class="pill purple" id="historyBtn">◉ История</button>
</div>

<div class="account-panel"><div class="table-head"><div class="select-all-wrap"><div class="account-check" id="selectAllCheck" title="Выделить все"><svg viewBox="0 0 24 24"><path d="M5 12l4 4L19 6"/></svg></div></div><div>#</div><div class="sortable-head" id="balanceSort" title="Сортировать по балансу">Balance <span class="sort-arrow" id="balanceArrow">↕</span></div><div class="login-head-wrap"><div class="sortable-head" id="loginSort" title="Сортировать по логину">Login <span class="sort-arrow" id="loginArrow">↕</span></div><div class="sortable-head login-metric-sort" id="levelSort" title="Сортировать по уровню">Lvl <span class="sort-arrow" id="levelArrow">↕</span></div><div class="sortable-head login-metric-sort" id="xpSort" title="Сортировать по опыту">XP <span class="sort-arrow" id="xpArrow">↕</span></div></div><div class="actions-title">Actions</div></div><div id="rows" class="rows"></div></div>
</section>
<section class="right">
<div class="right-top"><div class="right-main-tabs"><div class="mode active" id="inventoryTab" data-panel="inventoryPanel">▣ Инвентарь</div><div class="mode appearance-trigger" id="craftTab">↗ Оформление</div><button class="node-download" id="nodeDownloadBtn" title="Установить Node.js и зависимости">↓ Скачать Node.js</button></div>
<div class="game-tabs"><div class="game active" data-game="CS2">CS2</div><div class="game" data-game="TF2">TF2</div><div class="game" data-game="Dota 2">Dota 2</div><div class="game" data-game="Rust">Rust</div><div class="game" data-game="Steam">Steam</div><div class="game" data-game="Buy TF2">Buy TF2</div></div><div id="itemCount" class="item-count">Выберите аккаунт</div><button type="button" id="marketLotsRemoveAllBtn" class="market-lots-remove-all">Удалить все лоты</button><div class="inventory-controls"><button id="inventoryRefreshBtn" class="inventory-refresh-btn" title="Обновить инвентарь и устаревшие цены">↻</button><button id="inventoryTradeBtn" class="inventory-trade-btn" title="Отправить выбранные предметы">⇄ Trade</button><button id="inventorySelectAllBtn" class="inventory-refresh-btn" title="Выделить весь инвентарь для трейда или продажи">☑</button><button id="inventorySellBtn" class="inventory-sell-btn" title="Продать выделенные предметы">$ Продать</button><select id="inventorySort" class="inventory-sort" title="Сортировка инвентаря"><option value="default">По умолчанию</option><option value="price-desc">Цена: сначала дорогие</option><option value="price-asc">Цена: сначала дешёвые</option><option value="lock">Трейд-бан: ближайший</option></select><button id="marketLotsBtn" class="inventory-lots-btn" title="Показать активные лоты на продаже">Lots <span id="marketLotsCount">0</span></button></div></div>
<div id="inventory" class="inventory"></div>
<div id="gamesPanel" class="games-panel">
  <div class="games-head"><div class="games-head-main"><div class="games-title">Games Library</div><div class="games-sub" id="gamesAccountLabel">Выберите аккаунт</div></div><div class="games-head-actions"><input id="gamesSearch" class="games-search" placeholder="Поиск игры..." autocomplete="off"><input id="gameTargetInput" class="game-target-input" placeholder="AppID / SubID / Steam URL" autocomplete="off"><button id="addGameBtn" class="add-game-btn">＋ Добавить в библиотеку</button><button id="refreshGamesBtn" class="refresh-games-btn">↻</button></div></div>
  <div class="games-overview"><div class="games-overview-left"><span id="gamesStatus" class="games-count">Авторизуйте аккаунт, чтобы загрузить библиотеку.</span><span id="gamesUpdated" class="games-updated"></span><button id="farmCardsBtn" class="farm-cards-btn">▶ Запустить фарм карточек</button></div></div>
  <div id="gamesList" class="games-list"></div>
</div>
<div id="functionalPanel" class="functional-panel"><div class="functional-grid">
<div class="functional-card full"><div class="functional-actions"><button class="get-level-btn" id="getLevelBtn" title="Получить уровень и опыт выбранных аккаунтов">▰ Get Level</button><button class="marked-btn" id="markedBtn" title="Отметить или снять отметку с выбранных аккаунтов">★ Marked</button><button class="check-vac-btn" id="checkVacBtn" title="Проверить Community, VAC и Game Bans выбранных аккаунтов">🛡 Check VAC</button></div></div>
<div class="functional-card full"><div class="functional-actions"><button class="calendar-btn" id="tradeBanCalendarBtn">▦ Календарь трейд-банов</button><button class="queue-btn bulk-sell-btn" id="bulkSellBtn">$ Массовая продажа</button></div></div>
<div class="functional-card full"><div class="functional-actions"><button class="queue-btn" id="bulkTradeBtn">⇄ Массовый трейд</button><button class="calendar-btn" id="itemCollectorBtn">⌕ Сбор предметов</button></div></div>
<div class="functional-card full"><div class="functional-actions"><button class="queue-btn" id="launchSelectedSteamBtn" title="Запустить выделенные аккаунты в изолированных Steam-клиентах с логином, паролем и 2FA">▶ Open Selected</button><button class="close-selected-btn" id="closeSelectedSteamBtn">✕ Close Selected</button><button class="close-steam-btn" id="closeAllSteamBtn">✕ Close All Steam</button></div></div>
<div class="functional-card full"><div class="functional-actions"><label class="auto-session-button" title="Проверять и восстанавливать сессии при запуске"><span>Auto Reload Session</span><span class="switch"><input type="checkbox" id="autoSessionToggle"><span class="switch-slider"></span></span></label><button class="queue-btn" id="addGamesAllBtn">＋ Add Games Library</button><button class="pill orange functional-booster-btn" id="boosterFunctionalBtn">▶ Booster</button></div></div>
<div class="functional-card full steam-path-card"><div class="steam-path-title">Путь к Steam</div><div class="steam-path-row"><input id="steamPathInput" class="steam-path-input" placeholder="C:\Program Files (x86)\Steam\steam.exe" autocomplete="off" spellcheck="false"><button type="button" class="queue-btn" id="steamPathBrowseBtn">Выбрать путь</button><button type="button" class="queue-btn" id="steamPathSaveBtn">Проверить и сохранить</button></div><div class="steam-path-status" id="steamPathStatus">Укажите полный путь к steam.exe. Он используется для изолированного запуска аккаунтов.</div></div>
</div>

</div><!-- close functionalPanel; account detail is shared -->
<div id="accountDetail" class="account-detail">
  <div class="detail-head">
    <button class="detail-back" id="detailBack" title="Назад">‹</button>
    <div><div class="detail-title" id="detailTitle">Аккаунт</div><div class="detail-sub">Данные аккаунта • Steam Guard</div></div>
  </div>
  <div class="detail-grid">
    <div class="detail-card">
      <h3>Данные аккаунта</h3>
      <div class="security-row"><div class="security-label">Login</div><div class="security-value" id="safeLogin">—</div><button class="copy-credential" id="copyLoginBtn" title="Скопировать логин" aria-label="Скопировать логин"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h10"></path></svg></button></div>
      <div class="security-row"><div class="security-label">Pass</div><div class="security-value password" id="safePassword">••••••••••••</div><button class="copy-credential" id="copyPasswordBtn" title="Скопировать пароль" aria-label="Скопировать пароль"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h10"></path></svg></button></div>
      <div class="account-meta">
        <div class="account-meta-title">СОСТОЯНИЕ</div>
        <div class="account-meta-line"><span>Авторизация</span><span id="safeAuthState">Готов</span></div>
        <div class="account-meta-line"><span>Steam ID</span><span id="safeSteamId">—</span></div>
        <div class="account-meta-line"><span>Баланс</span><span id="safeBalance">—</span></div>
        <div class="account-meta-line"><span>Сессия</span><span id="safeSessionState">—</span></div>
      </div>
      <button class="relogin-btn" id="reloginBtn">↻ Повторный вход</button>
      <button class="account-history-btn" id="accountHistoryBtn">◉ Журнал операций аккаунта</button>
    </div>
    <div class="guard-card">
      <div class="guard-title">Steam Guard</div>
      <div class="guard-circle guard-circle-high" id="guardCircle" title="Нажмите, чтобы скопировать код">
        <div class="guard-ring" id="guardRing"></div>
        <div class="guard-demo" id="guardCode">••••••</div>
      </div>
      <div class="guard-time" id="guardTime">30 с</div>
      <div class="guard-caption">Steam Guard • код обновляется автоматически</div>
      <button class="guard-confirm-btn" id="guardConfirmBtn">✓ Подтверждение</button>
      <div class="guard-copied" id="guardCopied"></div>
      <div class="guard-management">
        <div class="guard-management-title">Управление guard:</div>
      </div>
      <div class="guard-note">Код запрашивается только локально у app.py и не передаётся вместе с секретом в браузер.</div>
    </div>
  </div>
</div>
</section>

</div>

<div id="importModal" class="modal-backdrop"><div class="file-modal">
<div class="file-modal-head"><div class="file-modal-icon">▣</div><div><div class="file-modal-title">Импорт и файлы проекта</div><div class="file-modal-sub">Быстрый доступ к папке проекта и основным файлам</div></div><button class="modal-close" id="modalClose">×</button></div>
<div class="project-path"><b>Корень проекта:</b> <span id="projectPath">загрузка...</span></div>
<div class="file-actions">
<button class="file-card" id="openProject"><div class="file-card-icon">▰</div><div class="file-card-title">Открыть проект</div><div class="file-card-text">Открыть корневую папку, где находится app.py</div></button>
<button class="file-card" id="openMaFiles"><div class="file-card-icon">▰</div><div class="file-card-title">Открыть maFile</div><div class="file-card-text">Переход в папку maFile</div></button>
<button class="file-card" id="openLogpass"><div class="file-card-icon">▤</div><div class="file-card-title">Открыть logpass.txt</div><div class="file-card-text">Открыть файл в стандартном редакторе Windows</div></button>
</div>
<div class="modal-footer"><div class="modal-hint">После изменений нажмите «Обновить».</div><button class="modal-secondary" id="modalRefresh">Обновить список</button></div>
</div></div>

<div id="historyModal" class="modal-backdrop"><div class="file-modal history-modal">
<div class="file-modal-head"><div class="file-modal-icon">◉</div><div><div class="file-modal-title">История и логи</div><div class="file-modal-sub">Сохранённые события авторизации, Node.js и ошибок проекта</div></div><button class="modal-close" id="historyClose">×</button></div>
<div class="history-body"><textarea id="historyText" class="history-text" readonly spellcheck="false"></textarea></div>
<div class="modal-footer"><div class="modal-hint" id="historyInfo">history.log</div><div class="history-actions"><button id="historyRefresh">Обновить</button><button id="historyCopy">Копировать</button><button id="historyClear">Очистить</button></div></div>
</div></div>


<div id="vacModal" class="modal-backdrop"><div class="vac-modal">
<div class="vac-head">Результаты проверки банов</div>
<div class="vac-status" id="vacStatus">Выберите аккаунты и запустите проверку</div>
<div class="vac-key-setup" id="vacKeySetup"><div class="vac-key-text">Получите бесплатный Steam Web API ключ, вставьте его сюда. Он сохранится только на этом ПК в зашифрованном виде.</div><input id="vacApiKey" class="vac-key-input" type="password" maxlength="32" placeholder="32-символьный Steam Web API ключ" autocomplete="off"><div class="vac-key-actions"><button class="vac-save-key" id="vacSaveKey">Сохранить и проверить</button><button class="vac-get-key" id="vacGetKey">Получить ключ</button></div></div>
<div class="vac-body" id="vacResults" style="display:none"><div class="vac-result-row vac-community"><span class="vac-result-icon">▣</span><span>Community Banned: <b id="vacCommunityCount">0</b></span></div><div class="vac-result-row vac-vac"><span class="vac-result-icon">♜</span><span>VAC Banned: <b id="vacBanCount">0</b></span></div><div class="vac-result-row vac-game"><span class="vac-result-icon">▶</span><span>Game Banned: <b id="vacGameCount">0</b></span></div><div class="vac-result-row vac-game"><span class="vac-result-icon">!</span><span>Limited Account: <b id="vacLimitedCount">0</b></span></div><div class="vac-result-row vac-community"><span class="vac-result-icon">⇄</span><span>Trade Ban: <b id="vacTradeCount">0</b></span></div><div class="vac-result-row vac-vac"><span class="vac-result-icon">◷</span><span>Trade / Market Hold: <b id="vacHoldCount">0</b></span></div><div class="vac-result-row vac-total"><span class="vac-result-icon">♟</span><span>Всего проверено: <b id="vacCheckedCount">0</b></span></div></div>
<div class="vac-footer"><span id="vacFailed"></span><button class="vac-close" id="vacClose">Закрыть</button></div>
</div></div>

<div id="themeModal" class="modal-backdrop"><div class="theme-modal">
<div class="theme-head"><div class="theme-head-icon">✦</div><div><div class="theme-title">Оформление</div><div class="theme-sub">Тема, фон и собственная цветовая палитра</div></div><button class="modal-close" id="themeClose">×</button></div>
<div class="theme-body">
<div class="theme-section-title">Готовые темы</div>
<div class="theme-presets">
<button class="theme-preset" data-theme="dark"><div class="preset-preview" style="background:linear-gradient(135deg,#071013,#12252a)"></div><span>Dark Ocean</span></button>
<button class="theme-preset" data-theme="light"><div class="preset-preview" style="background:linear-gradient(135deg,#eef5f5,#cbdfe2)"></div><span>Light Ice</span></button>
<button class="theme-preset" data-theme="purple"><div class="preset-preview" style="background:linear-gradient(135deg,#0d0b17,#30204b)"></div><span>Violet</span></button>
<button class="theme-preset" data-theme="green"><div class="preset-preview" style="background:linear-gradient(135deg,#07120d,#163522)"></div><span>Emerald</span></button>
</div>
<div class="theme-section-title">Цвета</div>
<div class="theme-colors">
<label class="color-control"><div class="color-info"><b>Фон</b><span>Основной цвет окна</span></div><input type="color" id="themeBg" value="#071013"></label>
<label class="color-control"><div class="color-info"><b>Фон 2</b><span>Второй цвет градиента</span></div><input type="color" id="themeBg2" value="#12252a"></label>
<label class="color-control"><div class="color-info"><b>Панели</b><span>Карточки и блоки</span></div><input type="color" id="themePanel" value="#0b1719"></label>
<label class="color-control"><div class="color-info"><b>Акцент</b><span>Главный цвет интерфейса</span></div><input type="color" id="themeAccent" value="#3ed8df"></label>
<label class="color-control"><div class="color-info"><b>Текст</b><span>Основной текст</span></div><input type="color" id="themeText" value="#dce8e8"></label>
<label class="color-control"><div class="color-info"><b>Вторичный текст</b><span>Подписи и мелкие элементы</span></div><input type="color" id="themeMuted" value="#7f9195"></label>
<label class="color-control"><div class="color-info"><b>Границы</b><span>Контуры карточек</span></div><input type="color" id="themeBorder" value="#29474c"></label>
<label class="color-control"><div class="color-info"><b>Успех</b><span>Авторизация и Guard</span></div><input type="color" id="themeSuccess" value="#55d978"></label>
</div>
<div class="theme-switches"><button class="theme-action" id="themeReset">↺ Сбросить</button><button class="theme-action" id="themeRandom">✦ Случайная палитра</button></div>
</div>
<div class="theme-footer"><div class="theme-hint">Оформление сохраняется в файле рядом с app.py.</div><div class="theme-footer-actions"><button class="theme-action" id="themeClose2">Закрыть</button><button class="theme-action primary" id="themeApply">✓ Применить</button></div></div>
</div></div>

<div id="accountContextMenu" class="account-context-menu"><div class="context-item" id="sendTradeContext"><span class="ctx-icon">⇄</span><span>Отправить трейд</span></div><div class="context-item" id="securityContext"><span class="ctx-icon">♟</span><span>Безопасность аккаунта</span></div></div>
<div id="inventoryContextMenu" class="inventory-context-menu"><div class="inventory-context-title" id="inventoryContextName">Предмет</div><button type="button" class="inventory-context-sell" id="inventoryContextSell"><span>$</span><div><b>Продать предмет</b><small>Цена и стакан Steam Market</small></div></button></div>

<div id="tradeBanCalendarModal" class="modal-backdrop"><div class="file-modal lock-calendar-modal"><div class="file-modal-head"><div class="file-modal-icon">▦</div><div><div class="file-modal-title">Календарь трейд-банов</div><div class="file-modal-sub">Активные блокировки и сохранённая история разблокировок</div></div><button class="modal-close" id="tradeBanCalendarClose">×</button></div><div class="lock-calendar-toolbar"><select id="calendarGame" class="bulk-select"><option value="all">Все игры</option><option value="CS2">CS2</option><option value="TF2">TF2</option><option value="Dota 2">Dota 2</option><option value="Rust">Rust</option><option value="Steam">Steam</option></select><button class="market-secondary-btn" id="calendarLoadBtn">↻ Загрузить / обновить</button></div><div class="lock-calendar-actions"><button class="market-secondary-btn" id="calendarSelectAll" title="Выделить аккаунты, у которых есть предметы с активным трейд-баном">Выделить аккаунты с ТБ</button><button class="market-secondary-btn" id="calendarSelectUnlocked" title="Выделить аккаунты, у которых есть предметы с истёкшим трейд-баном">Выделить разблокированные</button></div><div class="lock-calendar-view-tabs"><button type="button" id="calendarActiveTab" class="active">Активные <span id="calendarActiveCount">0</span></button><button type="button" id="calendarHistoryTab">История разблокировок <span id="calendarHistoryCount">0</span></button></div><div class="lock-calendar-status" id="calendarStatus">Открыты сохранённые данные. Обновление выполняется только по кнопке.</div><div class="lock-calendar-list" id="calendarList"></div></div></div>
<div id="bulkTradeModal" class="modal-backdrop"><div class="file-modal bulk-trade-modal"><div class="file-modal-head"><div class="file-modal-icon">⇄</div><div><div class="file-modal-title">Массовый трейд</div><div class="file-modal-sub">Все передаваемые предметы выбранной игры • по очереди</div></div><button class="modal-close" id="bulkTradeClose">×</button></div><div class="bulk-trade-body"><label class="market-field-label" for="bulkTradeUrl">Trade URL получателя</label><input id="bulkTradeUrl" class="bulk-trade-input" placeholder="https://steamcommunity.com/tradeoffer/new/?partner=...&amp;token=..." autocomplete="off" spellcheck="false"><div class="bulk-trade-form"><select id="bulkTradeSaved" class="bulk-select"><option value="">Сохранённые Trade URL</option></select><select id="bulkTradeGame" class="bulk-select"><option value="CS2">CS2</option><option value="TF2">TF2</option><option value="Dota 2">Dota 2</option><option value="Rust">Rust</option><option value="Steam">Steam</option></select></div><div class="bulk-trade-warning">Перед каждым аккаунтом инвентарь загружается заново. Отправляются все доступные предметы выбранной игры, кроме заблокированных. Между аккаунтами — случайная пауза 20–30 секунд.</div><div class="bulk-trade-actions"><button class="market-primary-btn" id="bulkTradeStart">Начать отправку</button><button class="market-secondary-btn" id="bulkTradeStop" disabled>Остановить</button></div><div class="bulk-trade-status" id="bulkTradeStatus">Выделите аккаунты галочками слева.</div><div class="bulk-trade-log" id="bulkTradeLog"></div></div></div></div>
<div id="itemCollectorModal" class="modal-backdrop"><div class="file-modal bulk-operation-modal"><div class="file-modal-head"><div class="file-modal-icon">⌕</div><div><div class="file-modal-title">Сбор предметов</div><div class="file-modal-sub">Найти одинаковые предметы на аккаунтах и отправить их получателю</div></div><button class="modal-close" id="itemCollectorClose">×</button></div><div class="bulk-trade-body"><div class="bulk-operation-grid"><select id="collectorGame" class="bulk-select"><option value="CS2">CS2</option><option value="TF2">TF2</option><option value="Dota 2">Dota 2</option><option value="Rust">Rust</option><option value="Steam">Steam</option></select><input id="collectorQuery" class="bulk-trade-input" placeholder="Например: Kilowatt Case" autocomplete="off"></div><div class="bulk-operation-grid"><select id="collectorSaved" class="bulk-select"><option value="">Сохранённые Trade URL</option></select><button class="market-secondary-btn" id="collectorLoad">Найти предметы</button></div><label class="market-field-label" for="collectorUrl">Trade URL получателя</label><input id="collectorUrl" class="bulk-trade-input" placeholder="https://steamcommunity.com/tradeoffer/new/?partner=...&amp;token=..." autocomplete="off" spellcheck="false"><div class="bulk-trade-warning">Если слева выделены аккаунты, поиск выполняется только по ним, иначе по всем. Перед отправкой инвентарь каждого аккаунта проверяется заново; заблокированные предметы исключаются.</div><div class="bulk-operation-list-head"><span id="collectorCount">Предметы не загружены</span><button class="market-secondary-btn" id="collectorToggleAll">Снять выделение</button></div><div class="bulk-operation-list" id="collectorList"></div><div class="bulk-trade-actions"><button class="market-primary-btn" id="collectorStart" disabled>Отправить выбранное</button><button class="market-secondary-btn" id="collectorStop" disabled>Остановить</button></div><div class="bulk-trade-status" id="collectorStatus">Введите название или часть названия предмета.</div><div class="bulk-trade-log" id="collectorLog"></div></div></div></div>
<div id="bulkSellModal" class="modal-backdrop"><div class="file-modal bulk-operation-modal bulk-sell-modal">
<div class="file-modal-head"><div class="file-modal-icon">$</div><div><div class="file-modal-title">Массовая продажа</div><div class="file-modal-sub">Ручная цена или максимальный ордер • покупатель платит</div></div><button type="button" class="modal-refresh-btn" id="bulkSellRefresh" title="Обновить стакан и рассчитать цены заново" aria-label="Обновить стакан">↻</button><button class="modal-close" id="bulkSellClose">×</button></div>
<div class="bulk-trade-body"><div class="bulk-operation-grid"><select id="bulkSellGame" class="bulk-select"><option value="CS2">CS2</option><option value="TF2">TF2</option><option value="Dota 2">Dota 2</option><option value="Rust">Rust</option><option value="Steam">Steam</option></select><input id="bulkSellQuery" class="bulk-trade-input" placeholder="Название или часть названия" autocomplete="off"></div>
<div class="bulk-sell-actions"><button class="market-secondary-btn bulk-operation-load" id="bulkSellLoad">↓ Загрузить предметы</button><button class="market-primary-btn bulk-operation-load" id="bulkSellQuote" disabled>Рассчитать цены</button></div>
<div class="bulk-trade-warning">Введите свою цену «Покупатель платит» в любой позиции или рассчитайте её по максимальному ордеру. Сумма продавца определяется после комиссий Steam. Ручные цены не перезаписываются при обновлении стакана. Продаётся по 1 предмету из каждой выбранной позиции.</div>
<div class="bulk-operation-list-head"><span id="bulkSellCount">Предметы не загружены</span><button class="market-secondary-btn" id="bulkSellToggleAll">Выбрать всё</button></div><div class="bulk-operation-list" id="bulkSellList"></div>
<div class="bulk-trade-actions"><button class="market-primary-btn" id="bulkSellStart" disabled>Выставить выбранное</button><button class="market-secondary-btn" id="bulkSellStop" disabled>Остановить</button></div><div class="bulk-trade-status" id="bulkSellStatus">Загрузите предметы, затем введите свои цены или рассчитайте их по ордерам.</div><div class="bulk-trade-log" id="bulkSellLog"></div></div></div></div>
<div id="inventoryTradeModal" class="modal-backdrop"><div class="file-modal inventory-trade-modal"><div class="file-modal-head"><div class="file-modal-icon">⇄</div><div><div class="file-modal-title">Отправка из инвентаря</div><div class="file-modal-sub" id="inventoryTradeCount">0 предметов</div></div><button class="modal-close" id="inventoryTradeClose">×</button></div><label class="market-field-label">Сохранённая Trade URL</label><select id="inventoryTradeUrl" class="inventory-trade-select"></select><div id="inventoryTradeItems" class="inventory-trade-items"></div><div class="inventory-trade-actions"><button id="inventoryTradeSelectAll" class="market-secondary-btn">Выбрать весь инвентарь</button><button id="inventoryTradeSubmit" class="market-primary-btn">Отправить и подтвердить</button></div><div id="inventoryTradeStatus" class="buy-order-status"></div></div></div>
<div id="buyTf2Modal" class="modal-backdrop"><div class="file-modal buy-tf2-modal"><div class="file-modal-head"><img id="buyTf2ModalIcon" class="buy-modal-icon" alt=""><div><div class="file-modal-title" id="buyTf2ModalTitle">Buy TF2</div><div class="file-modal-sub">Ордера Steam Community Market</div></div><button type="button" class="modal-refresh-btn" id="buyTf2Refresh" title="Получить новые цены для ключа и билета" aria-label="Обновить цены TF2">↻</button><button class="modal-close" id="buyTf2Close">×</button></div><div class="buy-order-layout"><div class="buy-order-card"><h3>Цена на продажу</h3><div id="tf2SellOrders">Загрузка…</div></div><div class="buy-order-card"><h3>Ордера на скупку</h3><div id="tf2BuyOrders">Загрузка…</div></div></div><div class="buy-create"><div class="buy-create-grid"><div class="buy-field"><label id="buyTf2PriceLabel">Моя цена за 1 предмет</label><input id="buyTf2Price" type="text" inputmode="decimal" placeholder="0.00"></div><div class="buy-field"><label>Количество</label><input id="buyTf2Quantity" type="number" min="1" max="100" value="1"></div></div><button type="button" class="market-primary-btn" id="buyTf2Submit">Выставить ордер на покупку</button><div class="buy-order-status" id="buyTf2Status">Загрузка…</div><div class="buy-order-summary"><div class="buy-order-total" id="buyTf2Total">Покупка на: 0.00 USD</div><div class="buy-order-balance" id="buyTf2Balance">Мой баланс: —</div></div></div></div></div>
<div id="sellItemModal" class="modal-backdrop"><div class="file-modal market-sell-modal sell-item-market-modal">
<div class="file-modal-head"><div class="file-modal-icon">$</div><div><div class="file-modal-title">Продажа предмета</div><div class="file-modal-sub">Ручная продажа • Steam Community Market</div></div><button type="button" class="modal-refresh-btn" id="sellItemRefresh" title="Обновить цены и стакан" aria-label="Обновить стакан">↻</button><button class="modal-close" id="sellItemClose">×</button></div>
<div class="sell-item-market-body"><div class="sell-item-preview"><div class="sell-item-preview-icon"><img id="sellItemIcon" alt=""></div><div><div id="sellItemName" class="sell-item-name">—</div><div id="sellItemAccount" class="sell-item-account">—</div><div class="sell-item-game">Предмет из выбранного инвентаря</div></div></div>
<div class="sell-item-workspace"><div class="sell-item-settings"><div class="sell-item-section-title">Ручная продажа</div><div class="sell-item-quote-summary"><div><span>Мин. продажа</span><b id="sellItemLowest">—</b></div><div><span>Макс. скупка</span><b id="sellItemHighest">—</b></div></div>
<label class="market-field-label">Покупатель платит (с комиссиями Steam)</label><div class="market-price-row"><input id="sellItemPrice" class="market-price-input" type="text" inputmode="decimal" placeholder="0.00"><span id="sellItemCurrency">USD</span></div><div class="sell-item-net" id="sellItemNet">Вы получите после комиссий: —</div><button type="button" class="market-secondary-btn sell-item-suggested" id="sellItemUseSuggested">Подставить максимальный ордер покупки</button><div class="buy-order-status" id="sellItemOrderStatus">Загрузка стакана…</div><div class="market-warning">Укажите итоговую сумму для покупателя. Сумма продавца будет рассчитана после комиссий и отправлена в Steam автоматически. Объявление создаётся только при точном совпадении итоговой цены, без округления в большую сторону. При ручном изменении цена сохраняется после обновления стакана. Steam может запросить подтверждение через ✓.</div><button id="sellItemSubmit" class="market-primary-btn">Выставить на продажу</button></div>
<div class="sell-item-book"><div class="buy-order-card"><h3>Цена на продажу</h3><div id="sellItemSellOrders">Загрузка…</div></div><div class="buy-order-card"><h3>Ордера на скупку</h3><div id="sellItemBuyOrders">Загрузка…</div></div></div></div></div></div></div>
<div id="confirmModal" class="modal-backdrop"><div class="file-modal confirm-window">
<div class="file-modal-head"><div class="file-modal-icon">✓</div><div><div class="file-modal-title">Подтверждения Steam</div><div class="file-modal-sub">Получатель, предметы и время каждой операции</div></div><button class="modal-close" id="confirmClose">×</button></div>
<div class="confirm-toolbar"><select id="confirmAccountSelect" class="confirm-select"></select><button class="theme-action" id="confirmReload">↻ Обновить</button></div>
<div id="confirmList" class="confirm-list"><div class="confirm-empty">Загрузка...</div></div>
<div class="modal-footer"><div class="history-actions"><button id="confirmRejectAll">✕ Отклонить все операции</button><button id="confirmAcceptAll">✓ Принять все операции</button><button id="confirmClose2">Закрыть</button></div></div>
</div></div>

<div id="tradeModal" class="modal-backdrop"><div class="trade-modal">
<div class="file-modal-head"><div class="file-modal-icon">⇄</div><div><div class="file-modal-title">Отправить трейд</div><div class="file-modal-sub">Вставьте Trade URL получателя</div></div><button class="modal-close" id="tradeClose">×</button></div>
<div class="trade-body"><div><div class="trade-account" id="tradeAccountLabel">Аккаунт: —</div><label class="trade-label" for="tradeLinkInput">Trade URL</label><div class="trade-input-row"><input id="tradeLinkInput" class="trade-input" placeholder="https://steamcommunity.com/tradeoffer/new/?partner=...&amp;token=..." autocomplete="off" spellcheck="false"><button class="trade-pin-btn" id="tradePinBtn" title="Закрепить введённую ссылку">📌</button><button class="trade-pin-btn" id="tradePasteBtn" title="Вставить последнюю сохранённую ссылку">↓</button></div><div class="trade-hint">После авторизации выбранного аккаунта в этом же приложении откроется отдельное окно с настоящим трейдом Steam.</div><div class="trade-error" id="tradeError"></div></div><div class="trade-saved"><div class="trade-saved-title">Закреплённые ссылки</div><div id="savedTradeLinks"><div class="trade-saved-empty">Пока нет сохранённых ссылок.</div></div></div></div>
<div class="trade-footer"><button class="modal-secondary" id="tradeCancel">Отмена</button><button class="trade-open" id="tradeOpen">⇄ Открыть трейд</button></div>
</div></div>

<div id="deleteModal" class="modal-backdrop"><div class="delete-modal"><div class="delete-title">Удаление аккаунта</div><div class="delete-text" id="deleteText">Вы хотите удалить аккаунт?</div><div class="delete-actions"><button class="delete-yes" id="deleteYes">Да</button><button class="delete-no" id="deleteNo">Нет</button></div></div></div>


<div id="boosterModal" class="modal-backdrop"><div class="file-modal booster-modal">
<div class="file-modal-head"><div class="file-modal-icon">▶</div><div><div class="file-modal-title">Booster</div><div class="file-modal-sub">Общий запуск игровой активности для выбранных аккаунтов</div></div><button class="modal-close" id="boosterClose">×</button></div>
<div class="booster-body"><label class="market-field-label" for="boosterAppIds">AppID игр через запятую</label><input id="boosterAppIds" class="bulk-trade-input" value="0" placeholder="0,730" autocomplete="off" spellcheck="false"><div class="booster-hint"><b>0</b> — случайные игры из библиотеки. Всего запускается 5 игр.<br>Например, <b>0,730</b>: четыре случайные игры и CS2. Без нуля используются только указанные AppID.<br>Для выбранных аккаунтов приоритет у игр из персонального Settings Booster.<br>«Применить ко всем» только сохраняет AppID для всех аккаунтов, без запуска Booster.</div><div class="booster-targets" id="boosterTargets">Выбрано аккаунтов: 0</div><div class="booster-actions"><button class="market-primary-btn" id="boosterStartSelected">▶ Запустить выбранные</button><button class="market-secondary-btn" id="boosterApplyAll">Применить ко всем</button></div><button class="market-secondary-btn booster-stop" id="boosterStopSelected">■ Остановить выбранные</button><div class="booster-status" id="boosterStatus">Список AppID сохраняется между перезапусками.</div></div>
</div></div>
<div id="accountBoosterModal" class="modal-backdrop"><div class="file-modal account-booster-modal">
<div class="file-modal-head"><div><div class="file-modal-title">Settings Booster</div><div class="file-modal-sub">Персональные игры для аккаунта</div></div><button class="modal-close" id="accountBoosterClose">×</button></div>
<div class="account-booster-body"><div class="account-booster-login"><span>Login</span><b id="accountBoosterLogin">—</b></div><label class="market-field-label" for="accountBoosterAppIds">AppID игр через запятую</label><input id="accountBoosterAppIds" class="bulk-trade-input" value="0" placeholder="0,730" autocomplete="off" spellcheck="false"><div class="account-booster-hint"><b>0</b> — случайные игры; <b>0,730</b> — четыре случайные игры и CS2.</div><button class="account-booster-save" id="accountBoosterSave">Сохранить</button><div class="account-booster-status" id="accountBoosterStatus">Запуск и остановка — в главном меню Booster.</div></div>
</div></div>
<div id="addGamesAllModal" class="modal-backdrop"><div class="file-modal account-booster-modal"><div class="file-modal-head"><div><div class="file-modal-title">Add Games Library</div><div class="file-modal-sub">Добавление одной игры для всех аккаунтов</div></div><button class="modal-close" id="addGamesAllClose">×</button></div><div class="account-booster-body"><label class="market-field-label" for="addGamesAllTarget">AppID / SubID / Steam URL</label><input id="addGamesAllTarget" class="bulk-trade-input" placeholder="Например: 730" autocomplete="off" spellcheck="false"><div class="account-booster-hint">Аккаунты, где игра уже есть, будут пропущены. Прогресс и ошибки появятся в уведомлениях справа снизу.</div><div class="booster-actions"><button class="market-primary-btn" id="addGamesAllStart">Начать для всех</button><button class="market-secondary-btn" id="addGamesAllStop" disabled>Остановить</button></div><div class="account-booster-status" id="addGamesAllStatus">Всего аккаунтов: 0</div></div></div></div>
<div id="sessionReloadProgress" class="session-reload-progress"><div class="session-reload-head"><b>Auto Reload Session</b><span id="sessionReloadPercent">0%</span></div><div class="session-reload-bar"><div id="sessionReloadFill"></div></div><div class="session-reload-current" id="sessionReloadCurrent">Подготовка…</div><div class="session-reload-stats" id="sessionReloadStats">0 / 0</div><button id="sessionReloadCancel">Отменить</button></div>
<div id="activityNotifications" class="activity-notifications" aria-live="polite"></div>
<div id="toast" class="toast"></div>
<div id="authProgress" class="auth-progress">
  <div class="auth-progress-head"><span id="authProgressTitle">Авторизация аккаунтов</span><span id="authProgressPercent">0%</span></div>
  <div class="auth-progress-bar"><div id="authProgressFill" class="auth-progress-fill"></div></div>
  <div id="authProgressSub" class="auth-progress-sub">Подготовка...</div>
  <div id="authProgressStage" class="auth-progress-stage">Ожидание</div>
</div>
</div>

<script>
var accounts=[],selectedId=null,currentGame="CS2",contextAccount=null,detailAccount=null,guardTimer=null,guardStarted=0,sortKey="",sortDir=0,authQueueRunning=false,checkedLogins={},levelLoading={};
var guardCodeTimer=null,themeDefaults={bg:"#071013",bg2:"#12252a",panel:"#0b1719",accent:"#3ed8df",text:"#dce8e8",muted:"#7f9195",border:"#29474c",success:"#55d978"};
var themePresets={
 dark:{bg:"#071013",bg2:"#12252a",panel:"#0b1719",accent:"#3ed8df",text:"#dce8e8",muted:"#7f9195",border:"#29474c",success:"#55d978"},
 light:{bg:"#eef5f5",bg2:"#cbdfe2",panel:"#f7fbfb",accent:"#138b96",text:"#203033",muted:"#607579",border:"#b7cdd0",success:"#159447"},
 purple:{bg:"#0d0b17",bg2:"#30204b",panel:"#171225",accent:"#b77cff",text:"#eee8ff",muted:"#978da9",border:"#4b3b62",success:"#68dc9a"},
 green:{bg:"#07120d",bg2:"#163522",panel:"#0b1c13",accent:"#53df93",text:"#e0f3e8",muted:"#809a8c",border:"#315c45",success:"#65e18e"}
};
function applyTheme(t,save){t=t||themeDefaults;var root=document.documentElement;root.style.setProperty("--ui-bg",t.bg);root.style.setProperty("--ui-bg2",t.bg2);root.style.setProperty("--ui-panel",t.panel);root.style.setProperty("--ui-accent",t.accent);root.style.setProperty("--ui-text",t.text);root.style.setProperty("--ui-muted",t.muted);root.style.setProperty("--ui-border",t.border);root.style.setProperty("--ui-success",t.success);document.body.classList.toggle("theme-light",isLightColor(t.bg));var st=document.getElementById("customTheme");if(!st){st=document.createElement("style");st.id="customTheme";document.head.appendChild(st)}st.textContent='html,body{background:'+t.bg+'!important;color:'+t.text+'!important}.app{background:radial-gradient(ellipse at 78% 10%,color-mix(in srgb,'+t.accent+' 18%,transparent),transparent 32%),linear-gradient(135deg,'+t.bg+','+t.bg2+' 52%,'+t.bg+' 100%)!important;color:'+t.text+'!important}.account-panel,.detail-card,.login-card,.file-modal,.history-modal,.theme-modal,.account-context-menu{border-color:'+t.border+'!important}.account-panel,.login-card{background:'+hexAlpha(t.panel,.72)+'!important}.search,.security-value,.history-text,.project-path{background:'+hexAlpha(t.bg,.82)+'!important;color:'+t.text+'!important;border-color:'+t.border+'!important}.mode.active,.game.active{color:'+t.accent+'!important}.game.active{background:'+hexAlpha(t.accent,.22)+'!important}.pill.blue,.pill.refresh-pill,.context-item .ctx-icon,.detail-title,.detail-card h3,.theme-section-title{color:'+t.accent+'!important}.pill.green,.stat.green strong,.guard-title,.guard-demo,.guard-copied,.theme-action.primary{color:'+t.success+'!important}.account-row:hover{background:'+hexAlpha(t.accent,.08)+'!important}.account-row.selected{background:'+hexAlpha(t.accent,.15)+'!important;box-shadow:inset 2px 0 '+t.accent+'!important}.detail-back,.guard-circle{border-color:'+t.border+'!important}.guard-circle{box-shadow:0 0 24px '+hexAlpha(t.success,.12)+',inset 0 0 30px '+hexAlpha(t.success,.05)+'!important}.guard-ring{background:conic-gradient('+t.success+' var(--progress,100%),rgba(54,93,61,.12) 0)!important}.toast{border-color:'+t.border+'!important;background:'+t.panel+'!important;color:'+t.text+'!important}.theme-preset.active{border-color:'+t.accent+'!important}.theme-action:hover,.context-item:hover{border-color:'+t.accent+'!important}.detail-sub,.theme-sub,.theme-hint,.color-info span,.modal-hint{color:'+t.muted+'!important}';if(save){try{localStorage.setItem("shark_theme",JSON.stringify(t))}catch(e){}fetch("/api/settings/theme",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({theme:t})}).catch(function(){})}updateThemeInputs(t)}
function hexAlpha(hex,a){hex=String(hex||"").replace("#","");if(hex.length!==6)return "rgba(0,0,0,"+a+")";return "rgba("+parseInt(hex.slice(0,2),16)+","+parseInt(hex.slice(2,4),16)+","+parseInt(hex.slice(4,6),16)+","+a+")"}
function isLightColor(hex){hex=String(hex||"").replace("#","");if(hex.length!==6)return false;var r=parseInt(hex.slice(0,2),16),g=parseInt(hex.slice(2,4),16),b=parseInt(hex.slice(4,6),16);return (r*299+g*587+b*114)>160000}
function updateThemeInputs(t){["Bg","Bg2","Panel","Accent","Text","Muted","Border","Success"].forEach(function(k){var el=document.getElementById("theme"+k);if(el)el.value=t[k.toLowerCase()]||themeDefaults[k.toLowerCase()]});document.querySelectorAll(".theme-preset").forEach(function(b){b.classList.remove("active")})}
function readThemeInputs(){return{bg:document.getElementById("themeBg").value,bg2:document.getElementById("themeBg2").value,panel:document.getElementById("themePanel").value,accent:document.getElementById("themeAccent").value,text:document.getElementById("themeText").value,muted:document.getElementById("themeMuted").value,border:document.getElementById("themeBorder").value,success:document.getElementById("themeSuccess").value}}
function loadTheme(){var t=null;try{t=JSON.parse(localStorage.getItem("shark_theme")||"null")}catch(e){}applyTheme(t&&typeof t==="object"?t:themeDefaults,false);fetch("/api/settings/theme?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){if(d.theme&&d.theme.bg){try{localStorage.setItem("shark_theme",JSON.stringify(d.theme))}catch(e){}applyTheme(d.theme,false)}}).catch(function(){})}
function openTheme(){document.getElementById("themeModal").classList.add("show");updateThemeInputs(readStoredTheme());}
function readStoredTheme(){try{var t=JSON.parse(localStorage.getItem("shark_theme")||"null");if(t)return t}catch(e){}return themeDefaults}
function closeTheme(){document.getElementById("themeModal").classList.remove("show")}
function generateRandomTheme(){var h=function(){return "#"+Math.floor(Math.random()*16777215).toString(16).padStart(6,"0")};var t={bg:h(),bg2:h(),panel:h(),accent:h(),text:"#f1f5f5",muted:"#9eafb1",border:h(),success:h()};applyTheme(t,false);updateThemeInputs(t)}
function copyGuardCode(){var code=document.getElementById("guardCode").textContent;if(!/^[A-Z2-9]{5}$/.test(String(code).trim()))return;safeCopy(code);document.getElementById("guardCopied").textContent="Код скопирован"}

var gameItems={
"CS2":[["◇","Container"],["◈","Sticker"],["⬢","Case"],["◆","Charm"],["✦","Collection"],["◇","Item"],["⬢","Case"],["◈","Sticker"],["✦","Collection"]],
"TF2":[["♟","Item"],["◉","Badge"],["◆","Crate"],["✦","Tool"],["◇","Token"],["⬢","Crate"],["◈","Item"],["✦","Tool"],["◉","Badge"]],
"Dota 2":[["✦","Treasure"],["◇","Immortal"],["◆","Courier"],["◈","Ward"],["⬢","Set"],["◉","Emblem"],["◇","Immortal"],["✦","Treasure"],["◆","Courier"]],
"Rust":[["◆","Skin"],["◇","Item"],["✦","Skin"],["⬢","Crate"],["◈","Item"],["◆","Skin"],["◇","Item"],["✦","Skin"],["⬢","Crate"]],
"GTA V":[["◈","Item"],["✦","Collectible"],["◆","Token"],["◇","Item"],["⬢","Bundle"],["◉","Badge"],["✦","Collectible"],["◆","Token"],["◇","Item"]]
};
function esc(v){return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
var ACCOUNT_ACTION_ICON_PATHS={
 external:'<path d="M14 4h6v6"/><path d="m20 4-9 9"/><path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5"/>',
 key:'<circle cx="7.5" cy="15.5" r="3.5"/><path d="m10 13 9-9"/><path d="m15 8 2 2"/><path d="m17 4 3 3"/>',
 play:'<path class="action-icon-fill" d="m8 5 11 7-11 7z"/>',
 check:'<path d="m5 12.5 4.2 4.2L19 7"/>',
 gear:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06a1.7 1.7 0 0 0-1.88-.34 1.7 1.7 0 0 0-1.03 1.56V21h-4v-.09A1.7 1.7 0 0 0 9 19.36a1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.63 15 1.7 1.7 0 0 0 3.07 14H3v-4h.09A1.7 1.7 0 0 0 4.64 9a1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.63h.01A1.7 1.7 0 0 0 10 3.07V3h4v.09A1.7 1.7 0 0 0 15 4.64a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.83 2.83-.06.06A1.7 1.7 0 0 0 19.37 9v.01A1.7 1.7 0 0 0 20.93 10H21v4h-.09A1.7 1.7 0 0 0 19.4 15z"/>',
 close:'<path d="m6 6 12 12M18 6 6 18"/>',
 loading:'<path d="M21 12a9 9 0 1 1-6.22-8.56"/>'
};
function actionIcon(name){return '<svg class="action-icon" viewBox="0 0 24 24" aria-hidden="true">'+(ACCOUNT_ACTION_ICON_PATHS[name]||ACCOUNT_ACTION_ICON_PATHS.external)+'</svg>'}
const NATIVE_CURRENCY_SYMBOL={USD:"$",GBP:"£",EUR:"€",CHF:"CHF",RUB:"₽",PLN:"zł",BRL:"R$",JPY:"¥",NOK:"kr",IDR:"Rp",MYR:"RM",PHP:"₱",SGD:"S$",THB:"฿",VND:"₫",KRW:"₩",TRY:"₺",UAH:"₴",MXN:"MX$",CAD:"C$",AUD:"A$",NZD:"NZ$",CNY:"¥",INR:"₹",CLP:"CLP",PEN:"S/",COP:"COP",ZAR:"R",HKD:"HK$",TWD:"NT$",SAR:"﷼",AED:"د.إ",SEK:"kr",ARS:"AR$",ILS:"₪",BYN:"Br",KZT:"₸",KWD:"د.ك",QAR:"﷼",CRC:"₡",UYU:"$U",BGN:"лв",HRK:"kn",CZK:"Kč",DKK:"kr",HUF:"Ft",RON:"lei"};
function formatNativeBalance(value){
 var raw=String(value==null?"":value).trim();
 if(!raw)return raw;
 var m=raw.match(/^([+-]?[0-9][0-9 .]*[.,]?[0-9]*)\s+([A-Z]{3})$/i);
 if(!m)return raw;
 var amount=m[1].replace(/ /g,"");
 var code=m[2].toUpperCase();
 var symbol=NATIVE_CURRENCY_SYMBOL[code];
 return symbol ? amount+symbol : amount+" "+code;
}
function toast(text){var t=document.getElementById("toast");t.textContent=text;t.className="toast show";clearTimeout(window.toastTimer);window.toastTimer=setTimeout(function(){t.className="toast"},1800)}
function notifyActivity(message,kind,title){
 var stack=document.getElementById('activityNotifications');if(!stack)return;var item=document.createElement('div');item.className='activity-notification '+(kind||'info');
 var head=document.createElement('div');head.className='activity-notification-head';var name=document.createElement('span');name.className='activity-notification-title';name.textContent=title||'Steam';var time=document.createElement('span');time.className='activity-notification-time';time.textContent=new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});head.appendChild(name);head.appendChild(time);
 var text=document.createElement('div');text.className='activity-notification-message';text.textContent=String(message||'');item.appendChild(head);item.appendChild(text);item.onclick=function(){if(item.parentNode)item.parentNode.removeChild(item)};stack.appendChild(item);
 while(stack.children.length>5)stack.removeChild(stack.firstChild);setTimeout(function(){if(item.parentNode)item.parentNode.removeChild(item)},kind==='error'?9000:6500)
}
function avatarClass(i){return ["","green","red","purple","blue"][i%5]}
function balanceNumber(a){
var raw=String((a&&a.balance)||"").replace(/\s/g,"").replace(/[^0-9,.-]/g,"");
if(!raw)return -1;
var comma=raw.lastIndexOf(","),dot=raw.lastIndexOf(".");
if(comma>dot){raw=raw.replace(/\./g,"").replace(",",".")}else{raw=raw.replace(/,/g,"")}
var n=parseFloat(raw);return isFinite(n)?n:-1
}
function filtered(){var q=document.getElementById("search").value.toLowerCase().trim();var list=q?accounts.filter(function(a){return a.login.toLowerCase().indexOf(q)!==-1}):accounts.slice();if(sortKey){list.sort(function(a,b){var av,bv;if(sortKey==="balance"){av=balanceNumber(a);bv=balanceNumber(b)}else if(sortKey==="level"||sortKey==="xp"){av=Number(a[sortKey]);bv=Number(b[sortKey]);av=isFinite(av)?av:-1;bv=isFinite(bv)?bv:-1}else{av=String(a.login||"").toLowerCase();bv=String(b.login||"").toLowerCase()}if(av<bv)return -1*sortDir;if(av>bv)return 1*sortDir;return String(a.login||"").localeCompare(String(b.login||""))})}return list}
function updateSortArrows(){var ba=document.getElementById("balanceArrow"),la=document.getElementById("loginArrow"),le=document.getElementById("levelSort"),xe=document.getElementById("xpSort");if(ba){ba.textContent=sortKey==="balance"?(sortDir>0?"↑":"↓"):"↕";ba.classList.toggle("active",sortKey==="balance")}if(la){la.textContent=sortKey==="login"?(sortDir>0?"↑":"↓"):"↕";la.classList.toggle("active",sortKey==="login")}if(le){le.classList.toggle("active",sortKey==="level");document.getElementById("levelArrow").textContent=sortKey==="level"?(sortDir<0?"↓":"↑"):"↕"}if(xe){xe.classList.toggle("active",sortKey==="xp");document.getElementById("xpArrow").textContent=sortKey==="xp"?(sortDir<0?"↓":"↑"):"↕"}}
function setMetricSort(key){if(sortKey!==key){sortKey=key;sortDir=-1}else if(sortDir===-1){sortDir=1}else{sortKey="";sortDir=0}updateSortArrows();renderRows(filtered())}
function setSort(key){if(sortKey!==key){sortKey=key;sortDir=1}else if(sortDir===1){sortDir=-1}else{sortKey="";sortDir=0}updateSortArrows();renderRows(filtered())}
function closeContextMenu(){document.getElementById("accountContextMenu").classList.remove("show")}

var historyLogin="";
function openHistory(){historyLogin="";document.getElementById("historyModal").classList.add("show");loadHistory()}
function openAccountHistory(){var a=selectedAccount();if(!a){toast("Сначала выберите аккаунт");return}historyLogin=a.login;document.getElementById("historyModal").classList.add("show");loadHistory()}
function closeHistory(){document.getElementById("historyModal").classList.remove("show")}
function loadHistory(){fetch("/api/history?ts="+Date.now()+(historyLogin?"&login="+encodeURIComponent(historyLogin):""),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){document.getElementById("historyText").value=d.text||"";document.getElementById("historyInfo").textContent=(historyLogin?"Аккаунт: "+historyLogin:(d.path||"history.log"))+" • "+(d.lines||0)+" строк"}).catch(function(){toast("Не удалось загрузить history.log")})}
function copyHistory(){var el=document.getElementById("historyText");if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(el.value).then(function(){toast("Логи скопированы")}).catch(function(){el.focus();el.select();document.execCommand("copy");toast("Логи скопированы")})}else{el.focus();el.select();document.execCommand("copy");toast("Логи скопированы")}}
function clearHistory(){fetch("/api/history/clear",{method:"POST",cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Ошибка");return d})}).then(function(){loadHistory();toast("История очищена")}).catch(function(e){toast(e.message||"Не удалось очистить историю")})}


var vacPendingLogins=[];
function closeVacCheck(){document.getElementById("vacModal").classList.remove("show")}
function checkVacBans(){
 var targets=markedTargets();if(!targets.length){toast("Сначала выберите аккаунты галочками или нажмите на строку");return}
 vacPendingLogins=targets.map(function(a){return a.login});document.getElementById("vacModal").classList.add("show");runVacCheck();
}
function runVacCheck(){
 var button=document.getElementById("checkVacBtn");button.disabled=true;button.textContent="◌ Check VAC";
 document.getElementById("vacResults").style.display="none";document.getElementById("vacKeySetup").style.display="none";document.getElementById("vacFailed").textContent="";
 document.getElementById("vacStatus").innerHTML="<span class='vac-loading'></span>Проверяю аккаунты через Steam...";
 fetch("/api/bans",{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({logins:vacPendingLogins})})
 .then(function(r){return r.json().then(function(d){if(d.key_required){document.getElementById("vacStatus").textContent="Нужна одноразовая настройка Steam Web API";document.getElementById("vacKeySetup").style.display="block";return null}if(!r.ok)throw new Error(d.message||"Ошибка проверки");return d})})
 .then(function(d){if(!d)return;document.getElementById("vacStatus").textContent="Проверка завершена";document.getElementById("vacCommunityCount").textContent=d.community_banned||0;document.getElementById("vacBanCount").textContent=d.vac_banned||0;document.getElementById("vacGameCount").textContent=d.game_banned||0;document.getElementById("vacLimitedCount").textContent=d.limited_account||0;document.getElementById("vacTradeCount").textContent=d.trade_banned||0;document.getElementById("vacHoldCount").textContent=d.trade_market_hold||0;document.getElementById("vacCheckedCount").textContent=d.checked||0;document.getElementById("vacFailed").textContent=d.failed?("Не проверено: "+d.failed):"";document.getElementById("vacResults").style.display="block";reloadAccountsAfterChange().catch(function(){})})
 .catch(function(e){document.getElementById("vacStatus").textContent=e.message||"Не удалось проверить баны"})
 .finally(function(){button.disabled=false;button.textContent="🛡 Check VAC"});
}
function saveVacKey(){
 var input=document.getElementById("vacApiKey"),key=input.value.trim(),button=document.getElementById("vacSaveKey");if(!key){toast("Вставьте Steam Web API ключ");return}button.disabled=true;
 fetch("/api/bans/key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:key})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось сохранить ключ");return d})}).then(function(){input.value="";runVacCheck()}).catch(function(e){document.getElementById("vacStatus").textContent=e.message||"Ошибка сохранения ключа"}).finally(function(){button.disabled=false});
}

function isChecked(login){return !!checkedLogins[String(login||"")]}
function checkedCount(){return Object.keys(checkedLogins).filter(function(k){return checkedLogins[k] && accounts.some(function(a){return a.login===k})}).length}
function updateSelectionUI(){var count=checkedCount(),el=document.getElementById("selectionCount");if(el)el.textContent=count?count+" выбрано":"0 выбрано";var all=accounts.length>0&&count===accounts.length,head=document.getElementById("selectAllCheck");if(head){head.classList.toggle("checked",all);head.title=all?"Снять все галочки":"Выделить все"}}
function toggleAccountCheck(login){var key=String(login||"");if(!key)return;if(checkedLogins[key])delete checkedLogins[key];else checkedLogins[key]=true;renderRows(filtered())}
function selectAllAccounts(){checkedLogins={};accounts.forEach(function(a){checkedLogins[a.login]=true});renderRows(filtered())}
function clearAllAccounts(){checkedLogins={};renderRows(filtered())}
function markedTargets(){
 var chosen=accounts.filter(function(a){return isChecked(a.login)});
 if(chosen.length)return chosen;
 var selected=selectedAccount();
 return selected?[selected]:[];
}
function updateMarkedButton(){
 var b=document.getElementById("markedBtn");if(!b)return;
 var targets=markedTargets(),allMarked=targets.length>0&&targets.every(function(a){return !!a.marked});
 b.textContent=allMarked?"★ Unmarked":"★ Marked";
 b.title=targets.length?(allMarked?"Снять отметку с выбранных аккаунтов":"Отметить выбранные аккаунты"):"Сначала выберите аккаунты галочками";
}
function toggleMarkedAccounts(){
 var targets=markedTargets();
 if(!targets.length){toast("Сначала выберите аккаунты галочками или нажмите на строку");return}
 var mark=!targets.every(function(a){return !!a.marked}),button=document.getElementById("markedBtn");
 button.disabled=true;
 fetch("/api/accounts/mark",{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({logins:targets.map(function(a){return a.login}),marked:mark})})
 .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось сохранить отметки");return d})})
 .then(function(d){accounts=d.accounts||accounts;renderRows(filtered());updateFarmButton();toast(mark?"Отмечено аккаунтов: "+targets.length:"Отметка снята: "+targets.length)})
 .catch(function(e){toast(e.message||"Ошибка сохранения отметок")})
 .finally(function(){button.disabled=false;updateMarkedButton()});
}


var autoSessionPoller=null,autoSessionWasRunning=false;
function pollAutoSession(){fetch("/api/session/auto-reload?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){var running=!!d.running;if(autoSessionWasRunning&&!running)reloadAccountsAfterChange().catch(function(){});autoSessionWasRunning=running;var toggle=document.getElementById("autoSessionToggle");if(toggle)toggle.checked=!!d.enabled;var box=document.getElementById("sessionReloadProgress"),visible=!!d.running;box.classList.toggle("show",visible);var total=Number(d.total||0),done=Number(d.done||0),percent=total?Math.round(done/total*100):0;document.getElementById("sessionReloadPercent").textContent=percent+"%";document.getElementById("sessionReloadFill").style.width=percent+"%";document.getElementById("sessionReloadCurrent").textContent=(d.current?d.current+" • ":"")+(d.message||"");document.getElementById("sessionReloadStats").textContent="Обработано: "+done+" / "+total+" • восстановлено: "+Number(d.reloaded||0)+" • ошибок: "+Number(d.failed||0);var cancel=document.getElementById("sessionReloadCancel");cancel.disabled=!!d.cancelling;cancel.textContent=d.cancelling?"Отмена после текущего…":"Отменить"}).catch(function(){})}
function startAutoSessionPolling(){pollAutoSession();if(!autoSessionPoller)autoSessionPoller=setInterval(pollAutoSession,3000)}
function changeAutoSession(){var enabled=document.getElementById("autoSessionToggle").checked;fetch("/api/session/auto-reload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled:enabled})}).then(function(r){return r.json().then(function(d){if(!r.ok&&!d.running)throw new Error(d.message||"Не удалось изменить настройку");return d})}).then(function(d){toast(d.message||(enabled?"Auto Reload Session включен":"Auto Reload Session выключен"));pollAutoSession()}).catch(function(e){document.getElementById("autoSessionToggle").checked=!enabled;toast(e.message||"Ошибка настройки")})}
function cancelAutoSession(){var b=document.getElementById("sessionReloadCancel");b.disabled=true;fetch("/api/session/auto-reload",{method:"DELETE"}).then(function(r){return r.json()}).then(function(){pollAutoSession()}).catch(function(){b.disabled=false;toast("Не удалось отменить очередь")})}
function boosterTargets(){return markedTargets()}
function updateBoosterTargets(){var n=boosterTargets().length,el=document.getElementById("boosterTargets");if(el)el.textContent="Выбрано аккаунтов: "+n}
function openBoosterModal(){document.getElementById("boosterModal").classList.add("show");document.getElementById("boosterStatus").textContent="Список AppID сохраняется между перезапусками.";updateBoosterTargets();startBoosterQueuePolling();fetch("/api/booster/settings?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){if(d.app_ids!==undefined)document.getElementById("boosterAppIds").value=d.app_ids||"0"}).catch(function(){})}
function closeBoosterModal(){document.getElementById("boosterModal").classList.remove("show")}
var boosterQueuePoller=null,boosterQueueSnapshot={current:"",done:0,running:false,runtime:{}};
function pollBoosterQueue(){
 fetch('/api/booster/queue?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
  var previous=boosterQueueSnapshot,status=document.getElementById('boosterStatus');
  if(d.current&&(previous.current!==d.current||previous.done!==d.done))notifyActivity(d.current+' start booster '+(Number(d.done||0)+1)+'/'+Number(d.total||0)+' accs','info','Booster');
  if(Number(d.done||0)>Number(previous.done||0)&&d.last_login)notifyActivity(d.last_login+': '+(d.last_message||(d.last_ok?'Booster запущен':'Ошибка запуска')),d.last_ok?'success':'error','Booster '+(d.last_ok?'✓':'✕'));
  var runtime=d.runtime||{};Object.keys(runtime).forEach(function(login){var old=previous.runtime&&previous.runtime[login],current=runtime[login]||{};if(!old||old.status===current.status)return;if(current.status==='running')notifyActivity(login+' booster active • Steam login confirmed','success','Booster');else if(current.status==='error')notifyActivity(login+': '+(current.message||'Booster остановился с ошибкой'),'error','Booster')});
  if(d.running){if(status)status.textContent=(d.current?d.current+' • '+(Number(d.done||0)+1)+'/'+Number(d.total||0)+' • ':'')+(d.message||'Очередь выполняется')}else if(status&&Number(d.total||0)>0)status.textContent='Готово: '+((d.started||[]).length)+' • ошибок: '+Object.keys(d.errors||{}).length+'. Пауза между аккаунтами — 10 с.';
  if(previous.running&&!d.running){notifyActivity('Очередь завершена: '+((d.started||[]).length)+' запущено, '+Object.keys(d.errors||{}).length+' ошибок',Object.keys(d.errors||{}).length?'error':'success','Booster');refreshRuntimeStates()}
  boosterQueueSnapshot={current:d.current||'',done:Number(d.done||0),running:!!d.running,runtime:runtime};boosterQueuePoller=d.running?setTimeout(pollBoosterQueue,1000):null
 }).catch(function(){boosterQueuePoller=boosterQueueSnapshot.running?setTimeout(pollBoosterQueue,2000):null})
}
function startBoosterQueuePolling(){if(!boosterQueuePoller){boosterQueuePoller=-1;pollBoosterQueue()}}
function startBooster(){
 var targets=boosterTargets(),input=document.getElementById("boosterAppIds"),status=document.getElementById("boosterStatus");
 if(!targets.length){toast("Сначала выберите аккаунты галочками");return}
 var buttons=["boosterStartSelected","boosterApplyAll"].map(function(id){return document.getElementById(id)});
 buttons.forEach(function(b){b.disabled=true});status.textContent="Подключение аккаунтов к Steam…";
 fetch("/api/booster/start",{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({logins:targets.map(function(a){return a.login}),app_ids:input.value.trim()||"0",use_account_settings:true})})
 .then(function(r){return r.json().then(function(d){if(!r.ok&&!d.started)throw new Error(d.message||"Не удалось запустить Booster");return d})})
 .then(function(d){
  input.value=d.app_ids||input.value;
  status.textContent=d.message+(d.errors&&Object.keys(d.errors).length?". Подробности в истории.":". Игры запускаются только в Steam-статусе, не на ПК.");
  toast(d.message);notifyActivity(d.message,'info','Booster');startBoosterQueuePolling();setTimeout(refreshRuntimeStates,700);
 })
 .catch(function(e){status.textContent=e.message||"Ошибка Booster";toast(e.message||"Ошибка Booster")})
 .finally(function(){buttons.forEach(function(b){b.disabled=false})});
}
function applyBoosterSettingsToAll(){
 var input=document.getElementById("boosterAppIds"),status=document.getElementById("boosterStatus"),button=document.getElementById("boosterApplyAll");
 button.disabled=true;status.textContent="Сохранение настроек для всех аккаунтов…";
 fetch("/api/booster/settings",{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({app_ids:input.value.trim()||"0",apply_all:true})})
 .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось применить настройки");return d})})
 .then(function(d){input.value=d.app_ids||input.value;status.textContent=d.message;toast(d.message);notifyActivity(d.message,'success','Booster')})
 .catch(function(e){status.textContent=e.message||"Ошибка Booster";toast(e.message||"Ошибка Booster")})
 .finally(function(){button.disabled=false});
}
function stopBoosterSelected(){var targets=boosterTargets(),status=document.getElementById("boosterStatus");if(!targets.length){toast("Сначала выберите аккаунты");return}fetch("/api/booster/stop",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({logins:targets.map(function(a){return a.login})})}).then(function(r){return r.json()}).then(function(d){status.textContent=d.message;toast(d.message);setTimeout(refreshRuntimeStates,400)}).catch(function(){toast("Не удалось остановить Booster")})}
var accountBoosterCurrentLogin="";
function setAccountBoosterBusy(busy){document.getElementById("accountBoosterSave").disabled=busy}
function openAccountBoosterModal(login){
 var acc=accounts.find(function(a){return a.login===login});if(!acc)return;
 accountBoosterCurrentLogin=login;selectedId=acc.id;
 document.getElementById("accountBoosterLogin").textContent=login;
 document.getElementById("accountBoosterAppIds").value="0";
 document.getElementById("accountBoosterStatus").textContent="Загрузка персональных настроек…";
 document.getElementById("accountBoosterModal").classList.add("show");
 fetch("/api/booster/settings?login="+encodeURIComponent(login)+"&ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){if(accountBoosterCurrentLogin!==login)return;if(d.app_ids!==undefined)document.getElementById("accountBoosterAppIds").value=d.app_ids||"0";document.getElementById("accountBoosterStatus").textContent="Настройки применяются только к "+login+"."}).catch(function(){if(accountBoosterCurrentLogin===login)document.getElementById("accountBoosterStatus").textContent="Не удалось загрузить сохранённые игры"})
}
function closeAccountBoosterModal(){document.getElementById("accountBoosterModal").classList.remove("show");accountBoosterCurrentLogin=""}
function saveAccountBooster(){
 var login=accountBoosterCurrentLogin,input=document.getElementById("accountBoosterAppIds"),status=document.getElementById("accountBoosterStatus");if(!login)return;
 setAccountBoosterBusy(true);status.textContent="Сохранение игр…";
 fetch("/api/booster/settings",{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({login:login,app_ids:input.value.trim()||"0"})})
 .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось сохранить настройки");return d})})
 .then(function(d){input.value=d.app_ids||input.value;status.textContent="Сохранено. Запуск — через главное меню Booster.";toast("Настройки Booster сохранены")})
 .catch(function(e){status.textContent=e.message||"Ошибка Booster";toast(e.message||"Ошибка Booster")})
 .finally(function(){setAccountBoosterBusy(false)});
}
function levelWidget(a){
 var key=String(a.login||"");
 if(a.level===null||a.level===undefined||a.level===""){if(levelLoading[key]||a.auth_status==="running")return '<div class="level-loading">◌ Получение уровня и опыта...</div>';return "";}
 var level=Math.max(0,parseInt(a.level,10)||0),xp=Math.max(0,Math.min(5000,parseInt(a.xp,10)||0)),percent=Math.max(0,Math.min(100,xp/50));
 return '<div class="level-widget" title="Уровень '+level+' • '+xp+' / 5000 XP"><div class="level-badge">'+level+'</div><div class="level-info"><div class="level-line"><b>CS2 LEVEL</b><span>'+xp+' / 5000 XP</span></div><div class="xp-track"><div class="xp-fill" style="width:'+percent+'%"></div></div></div></div>';
}
function getSelectedLevels(){
 var targets=markedTargets();if(!targets.length){toast("Сначала выберите аккаунты галочками или нажмите на строку");return}
 var logins=targets.map(function(a){return a.login}),button=document.getElementById("getLevelBtn");
 logins.forEach(function(login){levelLoading[login]=true});button.disabled=true;button.textContent="◌ Get Level";renderRows(filtered());
 fetch("/api/levels",{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({logins:logins})})
 .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось запустить получение уровня");return d})})
 .then(function(d){toast("Получение уровня запущено: "+(d.started||[]).length);pollLevels(logins,Date.now(),button)})
 .catch(function(e){logins.forEach(function(login){delete levelLoading[login]});button.disabled=false;button.textContent="▰ Get Level";renderRows(filtered());toast(e.message||"Ошибка получения уровня")});
}
function pollLevels(logins,started,button){
 fetch("/api/accounts?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
  accounts=d.accounts||accounts;
  var pending=logins.filter(function(login){var a=accounts.find(function(x){return x.login===login});return a&&a.auth_status==="running"});
  logins.forEach(function(login){var a=accounts.find(function(x){return x.login===login});if(a&&a.auth_status!=="running")delete levelLoading[login]});
  renderRows(filtered());
  if(pending.length&&Date.now()-started<120000){setTimeout(function(){pollLevels(logins,started,button)},1200);return}
  logins.forEach(function(login){delete levelLoading[login]});button.disabled=false;button.textContent="▰ Get Level";renderRows(filtered());
  var success=logins.filter(function(login){var a=accounts.find(function(x){return x.login===login});return a&&a.level!==null&&a.level!==undefined&&a.level!==""}).length;
  toast(success?"Уровень получен: "+success+" из "+logins.length:"Steam не вернул уровень. Подробности в истории");
 }).catch(function(){if(Date.now()-started<120000)setTimeout(function(){pollLevels(logins,started,button)},1500);else{button.disabled=false;button.textContent="▰ Get Level"}});
}
function renderRows(list){
var box=document.getElementById("rows");box.innerHTML="";document.getElementById("totalCount").textContent=accounts.length;document.getElementById("authCount").textContent=accounts.filter(function(x){return x.auth_status==="ok"}).length;document.getElementById("markedCount").textContent=accounts.filter(function(x){return !!x.marked}).length;
for(var i=0;i<list.length;i++){var a=list[i],row=document.createElement("div");row.className="account-row"+(selectedId===a.id?" selected login-selected":"")+(a.marked?" marked":"")+(a.steam_running?" steam-running":"");row.dataset.login=a.login||"";var initial=(a.login||"?").charAt(0).toUpperCase();
var avatarHtml=a.avatar_url?'<img class="avatar-img" src="'+esc(a.avatar_url)+'" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'">':'';
var fallbackAvatar='<div class="avatar '+avatarClass(i)+'" style="'+(a.avatar_url?'display:none':'')+'">'+esc(initial)+'</div>';
var balance=a.balance||(a.auth_status==="ok"?"0":"—"),displayLogin=a.login||"";if(displayLogin.length>12)displayLogin=displayLogin.slice(0,12)+"...";var banBadges=(a.vac_banned?'<span class="ban-badge vac" title="VAC Banned">V</span>':"")+(a.game_banned?'<span class="ban-badge game" title="Game Banned">G</span>':"")+(a.community_banned?'<span class="ban-badge" title="Community Banned">C</span>':"")+(a.trade_banned?'<span class="ban-badge trade" title="Trade Ban">T</span>':"")+(a.limited_account?'<span class="ban-badge limited" title="Limited Account">L</span>':"")+((a.trade_hold||a.market_hold)?'<span class="ban-badge hold" title="Trade / Market Hold">H</span>':"");
row.innerHTML='<div class="select-all-wrap"><div class="account-check '+(isChecked(a.login)?'checked':'')+'" data-check="1" title="'+(isChecked(a.login)?'Снять выбор':'Выбрать')+'"><svg viewBox="0 0 24 24"><path d="M5 12l4 4L19 6"/></svg></div></div><div class="number">'+(i+1)+'</div><div class="balance-cell">'+esc(formatNativeBalance(balance))+'</div><div class="login-cell"><div class="account-restrictions">'+banBadges+'</div><div class="avatar-wrap">'+avatarHtml+fallbackAvatar+'</div><div class="account-main"><div class="login-name-wrap"><div class="login-name" title="'+esc(a.login)+'">'+esc(displayLogin)+'</div><span class="session-badge steam-runtime-badge '+(a.steam_running?"online":"offline")+'" title="'+(a.steam_running?"Steam запущен":"Steam закрыт")+'"><span class="session-dot"></span><span class="runtime-label">'+(a.steam_running?"online":"offline")+'</span></span><span class="session-badge booster-badge booster-runtime-badge '+(a.booster_status==="running"?"online":"offline")+'" title="'+(a.booster_status==="running"?"Booster включён":"Booster выключен")+'"><span class="session-dot"></span><span class="runtime-label">booster</span></span></div>'+levelWidget(a)+'</div></div><div class="actions"><span class="action cyan" data-act="open_profile" title="Открыть профиль">'+actionIcon("external")+'</span><span class="action blue" data-act="authorize" title="Авторизация">'+actionIcon("key")+'</span><span class="action steam-launch-action" data-act="steam_launch" title="Запустить Steam">'+actionIcon("play")+'</span><span class="action green" data-act="ok" title="Подтверждения Steam">'+actionIcon("check")+'</span><span class="action yellow" data-act="booster" title="Settings Booster">'+actionIcon("gear")+'</span><span class="action red" data-act="delete" title="Удаление">'+actionIcon("close")+'</span></div>';
row.querySelector('[data-check="1"]').onclick=(function(acc){return function(e){e.stopPropagation();toggleAccountCheck(acc.login)}})(a);
row.addEventListener("click",(function(acc){return function(e){if(e.target.closest&&e.target.closest(".account-check"))return;var actionEl=e.target.closest&&e.target.closest(".action");if(actionEl){var act=actionEl.dataset.act;if(act==="open_profile")openSteamProfile(acc.login);else if(act==="authorize")authorizeAccount(acc.login);else if(act==="steam_launch")launchSteamClient(acc.login,actionEl);else if(act==="ok")openConfirmModal(acc.login);else if(act==="booster")openAccountBoosterModal(acc.login);else if(act==="delete")askDeleteAccount(acc)}else if(e.target.closest&&e.target.closest(".login-cell")){selectedId=acc.id;showTopPage("statistic");renderRows(filtered());renderAccountInventory(acc)}else{selectedId=acc.id;renderRows(filtered());if(document.getElementById("gamesTopTab").classList.contains("active"))loadSelectedGames();else if(document.getElementById("statisticTab").classList.contains("active"))renderAccountInventory(acc)}}})(a));
row.addEventListener("contextmenu",(function(acc){return function(e){var area=e.target.closest(".login-cell")||e.target.closest(".pass");if(!area)return;e.preventDefault();selectedId=acc.id;contextAccount=acc;var menu=document.getElementById("accountContextMenu");menu.classList.add("show");var x=e.clientX+3,y=e.clientY+3;if(x+170>window.innerWidth)x=window.innerWidth-175;if(y+82>window.innerHeight)y=window.innerHeight-87;menu.style.left=x+"px";menu.style.top=y+"px";renderRows(filtered())}})(a));box.appendChild(row)}updateSelectionUI();updateMarkedButton()}


function openAccountDetail(acc){
 if(!acc)return;
 detailAccount=acc;selectedId=acc.id;
 var d=document.getElementById("accountDetail");if(!d){toast("Панель данных аккаунта не найдена");return}
 // Switch the view first. Even if a non-essential field fails, inventory and
 // Games/Functional must never remain visible instead of account details.
 document.body.classList.add("detail-open");
 ["inventory","functionalPanel","gamesPanel"].forEach(function(id){var el=document.getElementById(id);if(el){el.classList.remove("show");el.style.setProperty("display","none","important")}});
 d.classList.remove("collapsed");d.classList.add("show");d.style.setProperty("display","block","important");
 var grid=d.querySelector(".detail-grid");if(grid)grid.style.setProperty("display","grid","important");
 function text(id,value){var el=document.getElementById(id);if(el)el.textContent=value}
 text("detailTitle",acc.login||"Аккаунт");text("safeLogin",acc.login||"—");text("safePassword","••••••••••••");
 text("safeAuthState",acc.auth_status==="ok"?"Авторизован":acc.auth_status==="running"?"Авторизация...":"Готов");
 text("safeSteamId",acc.steamid||"—");text("safeBalance",formatNativeBalance(acc.balance||(acc.auth_status==="ok"?"0":"—")));
 text("safeSessionState",acc.session_status==="active"?"Активна":acc.session_status==="relogin_required"?"Требуется повторный вход":"Сохранена, требуется проверка");
 var relogin=document.getElementById("reloginBtn");if(relogin)relogin.classList.toggle("show",acc.session_status==="relogin_required");
 closeContextMenu();startGuardDemo();
}
function copyCredential(kind){if(!detailAccount)return;var login=detailAccount.login||"";fetch("/api/account-credentials/"+encodeURIComponent(login)+"?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось получить данные");return d})}).then(function(d){var value=kind==="password"?d.password:d.login;if(!value)throw new Error("Данные не найдены");safeCopy(value)}).catch(function(e){toast(e.message||"Не удалось скопировать данные")})}
function closeAccountDetail(){document.body.classList.remove("detail-open");var d=document.getElementById("accountDetail");if(d){d.classList.remove("show");d.style.removeProperty("display")}var grid=d&&d.querySelector(".detail-grid");if(grid)grid.style.removeProperty("display");var gamesActive=document.getElementById("gamesTopTab")&&document.getElementById("gamesTopTab").classList.contains("active");var functionalActive=document.getElementById("functionalTab")&&document.getElementById("functionalTab").classList.contains("active");var inventory=document.getElementById("inventory");inventory.style.removeProperty("display");inventory.style.display=gamesActive||functionalActive?"none":"grid";var fp=document.getElementById("functionalPanel");if(fp){fp.style.removeProperty("display");fp.classList.toggle("show",functionalActive)}var gp=document.getElementById("gamesPanel");if(gp)gp.style.removeProperty("display");if(!gamesActive&&!functionalActive)document.getElementById("inventoryTab").classList.add("active");if(gamesActive)document.getElementById("gamesPanel").classList.add("show");detailAccount=null;if(guardTimer){clearInterval(guardTimer);guardTimer=null}if(guardCodeTimer){clearInterval(guardCodeTimer);guardCodeTimer=null}if(!gamesActive)renderGame(currentGame)}
function fetchGuardCode(){if(!detailAccount)return;fetch("/api/security/"+encodeURIComponent(detailAccount.login)+"?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось получить код");return d})}).then(function(d){if(!detailAccount)return;var code=document.getElementById("guardCode"),time=document.getElementById("guardTime"),ring=document.getElementById("guardRing");if(code)code.textContent=d.code||"••••••";if(time)time.textContent=(d.remaining||0)+" с";if(ring)ring.style.setProperty("--progress",((d.remaining||0)/30*100)+"%");if(d.steamid)document.getElementById("safeSteamId").textContent=d.steamid}).catch(function(e){var code=document.getElementById("guardCode");if(code)code.textContent="—";var time=document.getElementById("guardTime");if(time)time.textContent="—";document.getElementById("guardCopied").textContent=e.message||"Guard недоступен"})}
function startGuardDemo(){if(guardTimer)clearInterval(guardTimer);if(guardCodeTimer)clearInterval(guardCodeTimer);var copied=document.getElementById("guardCopied");if(copied)copied.textContent="";fetchGuardCode();guardCodeTimer=setInterval(fetchGuardCode,1000);guardTimer=setInterval(function(){if(detailAccount)fetchGuardCode()},5000)}
function safeCopy(text){if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(function(){toast("Скопировано")}).catch(function(){toast("Копирование недоступно")})}else toast("Копирование недоступно")}
function showTopPage(page){
  closeBuyTf2();closeInventoryTrade();closeSellItem();
  document.body.classList.remove("detail-open");
  var openDetail=document.getElementById("accountDetail");
  if(openDetail){openDetail.classList.remove("show");openDetail.style.removeProperty("display");var oldGrid=openDetail.querySelector(".detail-grid");if(oldGrid)oldGrid.style.removeProperty("display")}
  detailAccount=null;if(guardTimer){clearInterval(guardTimer);guardTimer=null}if(guardCodeTimer){clearInterval(guardCodeTimer);guardCodeTimer=null}
  ["inventory","functionalPanel","gamesPanel"].forEach(function(id){var el=document.getElementById(id);if(el)el.style.removeProperty("display")});
  var statistic=page==="statistic", functional=page==="functional", games=page==="games";
  document.getElementById("statisticTab").classList.toggle("active",statistic);
  document.getElementById("functionalTab").classList.toggle("active",functional);
  document.getElementById("gamesTopTab").classList.toggle("active",games);
  var inv=document.getElementById("inventory");
  var functionalPanel=document.getElementById("functionalPanel");
  var gamesPanel=document.getElementById("gamesPanel");
  var detail=document.getElementById("accountDetail");
  if(detail)detail.classList.remove("show");
  if(inv)inv.style.display=statistic?(currentGame==="Buy TF2"||marketLotsMode?"block":"grid"):"none";
  if(functionalPanel)functionalPanel.classList.toggle("show",functional);
  if(gamesPanel)gamesPanel.classList.toggle("show",games);
  var rightTabs=document.querySelector(".right-main-tabs");
  var gameTabs=document.querySelector(".game-tabs");
  if(rightTabs)rightTabs.style.display=statistic?"flex":"none";
  if(gameTabs)gameTabs.style.display=statistic?"flex":"none";
  var rightTop=document.querySelector(".right-top");
  if(rightTop)rightTop.style.display=statistic?"flex":"none";
  document.querySelectorAll(".right-main-tabs .mode").forEach(function(x){x.classList.remove("active")});
  document.getElementById("inventoryTab").classList.toggle("active",statistic);
  document.getElementById("itemCount").style.display=statistic?"block":"none";
  if(games)loadSelectedGames();
}

var tradeAccount=null,savedTradeLinks=[];
function tradeLinkName(link,index){
 try{var u=new URL(link);return "Получатель "+(index+1)+" • #"+(u.searchParams.get("partner")||"")}catch(e){return "Ссылка "+(index+1)}
}
function renderSavedTradeLinks(){
 var box=document.getElementById("savedTradeLinks");if(!box)return;box.innerHTML="";
 if(!savedTradeLinks.length){box.innerHTML='<div class="trade-saved-empty">Пока нет сохранённых ссылок.</div>';return}
 savedTradeLinks.forEach(function(link,index){var item=document.createElement("div");item.className="trade-saved-item";var use=document.createElement("button");use.className="trade-saved-use";use.title=link;use.textContent=tradeLinkName(link,index);use.onclick=function(){document.getElementById("tradeLinkInput").value=link;document.getElementById("tradeError").textContent=""};var del=document.createElement("button");del.className="trade-saved-del";del.textContent="×";del.title="Удалить сохранённую ссылку";del.onclick=function(){deleteSavedTradeLink(link)};item.appendChild(use);item.appendChild(del);box.appendChild(item)});
}
function loadSavedTradeLink(fill){
 fetch("/api/trade/saved-link?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){savedTradeLinks=Array.isArray(d.trade_urls)?d.trade_urls:(d.trade_url?[d.trade_url]:[]);var b=document.getElementById("tradePinBtn");if(b)b.classList.toggle("saved",!!savedTradeLinks.length);renderSavedTradeLinks();if(fill&&savedTradeLinks.length)document.getElementById("tradeLinkInput").value=savedTradeLinks[savedTradeLinks.length-1]}).catch(function(){});
}
function pinTradeLink(){
 var input=document.getElementById("tradeLinkInput"),link=input.value.trim(),error=document.getElementById("tradeError");
 if(!validTradeLink(link)){error.textContent="Сначала введите корректный Trade URL.";return}
 fetch("/api/trade/saved-link",{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({trade_url:link})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось сохранить ссылку");return d})}).then(function(d){savedTradeLinks=d.trade_urls||[];document.getElementById("tradePinBtn").classList.add("saved");error.textContent="";renderSavedTradeLinks();toast("Trade URL закреплён")}).catch(function(e){error.textContent=e.message||"Ошибка сохранения ссылки"});
}
function deleteSavedTradeLink(link){
 fetch("/api/trade/saved-link",{method:"DELETE",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({trade_url:link})}).then(function(r){return r.json()}).then(function(d){savedTradeLinks=d.trade_urls||[];renderSavedTradeLinks();document.getElementById("tradePinBtn").classList.toggle("saved",!!savedTradeLinks.length);toast("Ссылка удалена")}).catch(function(){toast("Не удалось удалить ссылку")});
}
function pasteSavedTradeLink(){
 if(savedTradeLinks.length){document.getElementById("tradeLinkInput").value=savedTradeLinks[savedTradeLinks.length-1];document.getElementById("tradeError").textContent="";return}
 loadSavedTradeLink(true);
}
function openTradeDialog(acc){
 if(!acc){toast("Сначала выберите аккаунт");return}
 tradeAccount=acc;closeContextMenu();
 document.getElementById("tradeAccountLabel").textContent="Аккаунт: "+acc.login;
 document.getElementById("tradeLinkInput").value="";document.getElementById("tradeError").textContent="";
 document.getElementById("tradeModal").classList.add("show");loadSavedTradeLink(false);
 setTimeout(function(){document.getElementById("tradeLinkInput").focus()},50);
}
function closeTradeDialog(){document.getElementById("tradeModal").classList.remove("show");tradeAccount=null}
function validTradeLink(value){
 try{var u=new URL(String(value||"").trim());return u.protocol==="https:"&&u.hostname==="steamcommunity.com"&&u.pathname==="/tradeoffer/new/"&&/^\d+$/.test(u.searchParams.get("partner")||"")&&!!(u.searchParams.get("token")||"").trim()}catch(e){return false}
}
function openRealTrade(){
 if(!tradeAccount)return;var input=document.getElementById("tradeLinkInput"),link=input.value.trim(),error=document.getElementById("tradeError"),button=document.getElementById("tradeOpen");
 if(!validTradeLink(link)){error.textContent="Введите корректный Trade URL с параметрами partner и token.";input.focus();return}
 error.textContent="";button.disabled=true;button.textContent="◌ Авторизация...";
 fetch("/api/trade/open/"+encodeURIComponent(tradeAccount.login),{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({trade_url:link})})
 .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось открыть трейд");return d})})
 .then(function(d){var login=tradeAccount.login;closeTradeDialog();toast(d.message||("Окно открыто; авторизация: "+login))})
 .catch(function(e){error.textContent=e.message||"Ошибка открытия трейда"})
 .finally(function(){button.disabled=false;button.textContent="⇄ Открыть трейд"});
}
function closeAllSteam(){
  var b=document.getElementById("closeAllSteamBtn");
  if(!b)return;
  b.disabled=true;b.classList.add("busy");b.textContent="◌ Closing Steam...";
  fetch("/api/steam/close-all",{method:"POST",cache:"no-store"})
    .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось закрыть Steam");return d})})
    .then(function(d){toast(d.message||"Steam закрыт")})
    .catch(function(e){toast(e.message||"Ошибка закрытия Steam")})
    .finally(function(){b.disabled=false;b.classList.remove("busy");b.textContent="✕ Close All Steam"});
}

var gamesAccountLogin=null;
var gamesRequestToken=0;
var gamesFilterText="";
function selectedAccount(){return accounts.find(function(a){return a.id===selectedId})||null}
function gameHours(minutes){var n=Number(minutes||0);if(!isFinite(n)||n<=0)return "0 ч";return (n/60).toFixed(n>=600?0:1)+" ч"}
function setGamesStatus(text,kind){var el=document.getElementById("gamesStatus");if(el){el.textContent=text||"";el.className="games-count"+(kind?" "+kind:"")}}
function renderGamesList(games){
  var box=document.getElementById("gamesList");if(!box)return;box.innerHTML="";
  var q=String(gamesFilterText||"").trim().toLowerCase();
  var list=(games||[]).filter(function(g){return !q||String(g.name||"").toLowerCase().indexOf(q)>=0||String(g.appid||"").indexOf(q)>=0});list.sort(function(a,b){return (Number(b.cards_remaining)||0)-(Number(a.cards_remaining)||0)});
  if(!list.length){box.innerHTML='<div class="games-empty">'+(q?'По запросу ничего не найдено.':'У этого аккаунта нет игр в распознанной библиотеке Steam.')+'</div>';return}
  list.forEach(function(g){var card=document.createElement("div");card.className="game-card";var icon=g.img_icon_url||"";var logo=g.img_logo_url||"";var fallback="https://cdn.cloudflare.steamstatic.com/steam/apps/"+encodeURIComponent(g.appid)+"/header.jpg";var cover;if(icon){cover='<img class="game-cover" src="'+esc(icon)+'" data-fallback="'+esc(logo||fallback)+'" onerror="if(this.dataset.fallback && this.src!==this.dataset.fallback){this.src=this.dataset.fallback}else{this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'}">'}else if(logo){cover='<img class="game-cover" src="'+esc(logo)+'" data-fallback="'+esc(fallback)+'" onerror="if(this.dataset.fallback && this.src!==this.dataset.fallback){this.src=this.dataset.fallback}else{this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'}">'}else{cover='<img class="game-cover" src="'+esc(fallback)+'" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'}">'}cover+='<div class="game-cover-empty" style="display:none">🎮</div>';card.innerHTML=cover+'<div class="game-info"><div class="game-name" title="'+esc(g.name||"")+'">'+esc(g.name||("App "+g.appid))+'</div><div class="game-id">AppID '+esc(String(g.appid))+'</div><div class="game-hours">'+gameHours(g.playtime_forever)+' наиграно</div>'+(Number(g.cards_remaining)>0?'<div class="card-drops-label">Осталось '+Number(g.cards_remaining)+' карточек</div>':'')+'</div><button class="game-open" title="Открыть страницу Steam">↗</button>';card.querySelector(".game-open").onclick=function(){window.open("https://store.steampowered.com/app/"+encodeURIComponent(g.appid)+"/","_blank")};box.appendChild(card)});
}
function loadSelectedGames(){
  var acc=selectedAccount(),label=document.getElementById("gamesAccountLabel"),updated=document.getElementById("gamesUpdated");
  if(!acc){gamesAccountLogin=null;if(label)label.textContent="Выберите аккаунт";if(updated)updated.textContent="";setGamesStatus("Выберите аккаунт");renderGamesList([]);return}
  gamesAccountLogin=acc.login;if(label)label.textContent=acc.login;var token=++gamesRequestToken;setGamesStatus("Загрузка библиотеки после авторизации...");
  fetch("/api/games/"+encodeURIComponent(acc.login)+"?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||d.message||("HTTP "+r.status));return d})}).then(function(d){if(token!==gamesRequestToken)return;var games=(d.games||[]).slice(),cards=d.card_games||[];cards.forEach(function(c){var g=games.find(function(x){return Number(x.appid)===Number(c.appid)});if(g){g.cards_remaining=c.cards_remaining;if(c.name&&!g.name)g.name=c.name}else games.push(c)});renderGamesList(games);setGamesStatus("Игр: "+(d.count||0)+" • с карточками: "+cards.length);if(updated)updated.textContent=d.updated?"Обновлено: "+d.updated:"";updateFarmButton()}).catch(function(e){if(token!==gamesRequestToken)return;renderGamesList([]);setGamesStatus(e.message||"Не удалось загрузить библиотеку");toast(e.message||"Ошибка загрузки игр")});
}
function updateFarmButton(){var b=document.getElementById("farmCardsBtn"),a=selectedAccount();if(!b)return;var running=!!(a&&a.farm_status==="running");b.textContent=running?"■ Остановить фарм":"▶ Запустить фарм карточек";b.classList.toggle("running",running)}
function toggleCardFarm(){var a=selectedAccount();if(!a){toast("Сначала выберите аккаунт");return}var running=a.farm_status==="running";fetch("/api/cards/farm/"+encodeURIComponent(a.login),{method:running?"DELETE":"POST"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Ошибка фарма");toast(d.message);setTimeout(refreshRuntimeStates,500)})}).catch(function(e){toast(e.message||"Не удалось запустить фарм")})}
function addGameToSelected(){
  var acc=selectedAccount(),input=document.getElementById("gameTargetInput"),button=document.getElementById("addGameBtn"),target=(input&&input.value||"").trim();
  if(!acc){toast("Сначала выберите аккаунт");return}
  if(!target){toast("Укажите AppID, SubID или Steam URL");return}

  if(button){button.disabled=true;button.classList.add("busy");button.textContent="◌ Добавление..."}
  setGamesStatus("Авторизация Steam и добавление в фоне...");
  notifyActivity(acc.login+' add game • '+target,'info','Games');

  fetch("/api/games/add/"+encodeURIComponent(acc.login),{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    cache:"no-store",
    body:JSON.stringify({target:target})
  }).then(function(r){
    return r.json().then(function(d){if(!r.ok)throw new Error(d.error||d.message||("HTTP "+r.status));return d})
  }).then(function(d){
    if(d.games)renderGamesList(d.games);
    if(d.action==="added"){
      setGamesStatus("Игра успешно добавилась","success");
      toast("Игра успешно добавилась");notifyActivity(acc.login+': игра добавлена в библиотеку','success','Games');
    }else if(d.action==="already_owned"){
      setGamesStatus("Игра уже есть в библиотеке","success");toast("Игра уже есть в библиотеке");notifyActivity(acc.login+': игра уже есть — пропущено','info','Games');
    }else if(d.games_count!=null){
      setGamesStatus("Игр: "+d.games_count);
      toast(d.message||"Готово: операция выполнена в фоне");
    }else{
      setGamesStatus(d.message||"Готово","success");
      toast(d.message||"Готово: операция выполнена в фоне");
    }
    if(input)input.value="";
  }).catch(function(e){
    setGamesStatus(e.message||"Не удалось добавить игру","error");
    toast(e.message||"Ошибка добавления игры");notifyActivity(acc.login+': '+(e.message||'Ошибка добавления игры'),'error','Games');
  }).finally(function(){
    if(button){button.disabled=false;button.classList.remove("busy");button.textContent="＋ Добавить в библиотеку"}
  });
}
var gamesAllPoller=null,gamesAllSnapshot={current:'',done:0,running:false};
function openAddGamesAllModal(){
 document.getElementById('addGamesAllModal').classList.add('show');var shared=document.getElementById('gameTargetInput'),target=document.getElementById('addGamesAllTarget');if(shared&&shared.value.trim()&&!target.value.trim())target.value=shared.value.trim();document.getElementById('addGamesAllStatus').textContent='Всего аккаунтов: '+accounts.length;startGamesAllPolling()
}
function closeAddGamesAllModal(){document.getElementById('addGamesAllModal').classList.remove('show')}
function pollGamesAll(){
 fetch('/api/games-all/status?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
  var previous=gamesAllSnapshot,status=document.getElementById('addGamesAllStatus');
  if(d.current&&(previous.current!==d.current||previous.done!==d.done))notifyActivity(d.current+' add game '+(Number(d.done||0)+1)+'/'+Number(d.total||0)+' accs','info','Add Games Library');
  if(Number(d.done||0)>Number(previous.done||0)&&d.last_login)notifyActivity(d.last_login+': '+(d.last_message||'Готово'),d.last_action==='added'?'success':(d.last_action==='error'?'error':'info'),'Add Games Library');
  if(status)status.textContent=d.running?((d.current?d.current+' • ':'')+Number(d.done||0)+'/'+Number(d.total||0)+' • '+(d.message||'Выполняется')):('Добавлено: '+Number(d.added||0)+' • уже есть: '+Number(d.skipped||0)+' • ошибок: '+Number(d.failed||0));
  document.getElementById('addGamesAllStart').disabled=!!d.running;document.getElementById('addGamesAllStop').disabled=!d.running;
  if(previous.running&&!d.running){notifyActivity('Add Games Library: '+Number(d.added||0)+' добавлено, '+Number(d.skipped||0)+' пропущено, '+Number(d.failed||0)+' ошибок',Number(d.failed||0)?'error':'success','Games');refreshRuntimeStates();if(document.getElementById('gamesTopTab').classList.contains('active'))loadSelectedGames()}
  gamesAllSnapshot={current:d.current||'',done:Number(d.done||0),running:!!d.running};gamesAllPoller=d.running?setTimeout(pollGamesAll,1200):null
 }).catch(function(){gamesAllPoller=gamesAllSnapshot.running?setTimeout(pollGamesAll,2200):null})
}
function startGamesAllPolling(){if(!gamesAllPoller){gamesAllPoller=-1;pollGamesAll()}}
function startAddGamesAll(){
 var input=document.getElementById('addGamesAllTarget'),target=input.value.trim();if(!target){toast('Укажите AppID, SubID или Steam URL');return}if(!accounts.length){toast('Нет аккаунтов для добавления');return}
 document.getElementById('addGamesAllStart').disabled=true;fetch('/api/games-all/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Не удалось запустить массовое добавление');return d})}).then(function(d){document.getElementById('addGamesAllStatus').textContent=d.message;notifyActivity(d.message,'info','Add Games Library');startGamesAllPolling()}).catch(function(e){document.getElementById('addGamesAllStart').disabled=false;notifyActivity(e.message||'Ошибка Add Games Library','error','Games');toast(e.message||'Ошибка Add Games Library')})
}
function stopAddGamesAll(){var button=document.getElementById('addGamesAllStop');button.disabled=true;fetch('/api/games-all/add',{method:'DELETE'}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Не удалось остановить');notifyActivity(d.message,'info','Add Games Library');startGamesAllPolling()})}).catch(function(e){button.disabled=false;toast(e.message||'Ошибка остановки')})}
function initGamesSearch(){var input=document.getElementById("gamesSearch");if(input)input.oninput=function(){gamesFilterText=input.value||"";var a=selectedAccount();renderGamesList(a&&a.games||[])}}

var inventoryRequestToken=0,inventoryPollTimer=null,inventoryUnlockTimer=null,inventorySortMode='default',inventorySelectedAssets=new Set(),currentInventoryItems=[],currentInventoryData=null,currentInventoryAccount=null,currentInventoryAppid=730,currentInventoryContext="2";
var inventoryGames={"CS2":730,"TF2":440,"Dota 2":570,"Rust":252490,"Steam":753},inventoryContexts={"Steam":6};
var marketLotsMode=false,marketLotsCache={},marketLotsPending={},marketLotsRequests={};
function setMarketLotsCount(value){var count=document.getElementById('marketLotsCount');if(count)count.textContent=String(value===undefined||value===null?0:value)}
function setMarketLotsRemoveAllState(value){var button=document.getElementById('marketLotsRemoveAllBtn');if(button)button.disabled=!marketLotsMode||!(Number(value)>0)}
function updateInventoryViewControls(){
 var lots=marketLotsMode&&currentGame!=="Buy TF2",buy=currentGame==="Buy TF2",sort=document.getElementById('inventorySort');
 if(sort)sort.style.display=lots||buy?'none':'block';
 ['inventoryTradeBtn','inventorySelectAllBtn','inventorySellBtn'].forEach(function(id){var button=document.getElementById(id);if(button)button.style.display=lots||buy?'none':''});
 var lotsButton=document.getElementById('marketLotsBtn');if(lotsButton){lotsButton.style.display=buy?'none':'inline-flex';lotsButton.classList.toggle('active',lots);lotsButton.title=lots?'Вернуться к инвентарю':'Показать активные лоты на продаже'}
 var refresh=document.getElementById('inventoryRefreshBtn');if(refresh)refresh.title=lots?'Обновить активные лоты и баланс':'Обновить инвентарь, баланс и устаревшие цены';
 var removeAll=document.getElementById('marketLotsRemoveAllBtn');if(removeAll){removeAll.classList.toggle('show',lots);if(!lots)removeAll.disabled=true}
}
function updateMarketWalletUI(login,d){
 var acc=accounts.find(function(a){return a.login===login});if(!acc)return;
 if(d.balance)acc.balance=d.balance;if(d.currency_code)acc.currency=d.currency_code;if(d.country)acc.country=d.country;
 if(currentInventoryAccount&&currentInventoryAccount.login===login){if(d.balance)currentInventoryAccount.balance=d.balance;if(d.currency_code)currentInventoryAccount.currency=d.currency_code;if(d.country)currentInventoryAccount.country=d.country}
 if(detailAccount&&detailAccount.login===login){if(d.balance)detailAccount.balance=d.balance;var balance=document.getElementById('safeBalance');if(balance&&d.balance)balance.textContent=formatNativeBalance(d.balance)}
 renderRows(filtered())
}
function renderMarketLotsLoading(acc){
 if(!marketLotsMode||!acc)return;var inv=document.getElementById('inventory');inv.style.display='block';document.getElementById('itemCount').textContent='Активные лоты • '+acc.login;setMarketLotsRemoveAllState(0);
 inv.innerHTML='<div class="buy-active-orders buy-active-main market-lots-panel"><div class="market-lots-heading"><h3>Активные лоты на продаже</h3><span class="market-lots-balance">Баланс продаж: …</span></div><div class="buy-active-empty"><span class="inventory-loading">Загрузка лотов и баланса Steam…</span></div></div>'
}
function renderMarketLotsError(message,acc){
 if(!marketLotsMode||!acc)return;var inv=document.getElementById('inventory');inv.style.display='block';var cachedCount=marketLotsCache[acc.login]?marketLotsCache[acc.login].data.count:0;setMarketLotsCount(cachedCount||'—');setMarketLotsRemoveAllState(cachedCount);
 inv.innerHTML='<div class="buy-active-orders buy-active-main market-lots-panel"><div class="market-lots-heading"><h3>Активные лоты на продаже</h3></div><div class="buy-active-empty">'+esc(message||'Не удалось загрузить лоты')+'</div><button type="button" id="marketLotsRetry" class="market-secondary-btn">Повторить</button></div>';
 document.getElementById('marketLotsRetry').onclick=function(){loadMarketListings(true)}
}
function marketSalesTotalCents(listings){
 return (listings||[]).reduce(function(sum,lot){var value=Number(lot.buyer_cents);return Number.isFinite(value)&&value>=0?sum+Math.round(value):sum},0)
}
function marketLotRow(lot,currency){
 var buyer=orderMoney(lot.buyer_cents,currency),seller=lot.seller_cents===null||lot.seller_cents===undefined?'—':orderMoney(lot.seller_cents,currency);
 return '<div class="buy-active-row market-lot-row"><div class="buy-active-info"><div class="market-lot-icon">'+(lot.icon?'<img loading="lazy" src="'+esc(lot.icon)+'" alt="">':'—')+'</div><div class="buy-active-item"><b title="'+esc(lot.name)+'">'+esc(lot.name)+'</b><span>'+esc(lot.game||('AppID '+lot.appid))+'</span></div></div><div class="market-lot-prices"><b>Покупатель платит: '+esc(buyer)+'</b><span>Вы получаете: '+esc(seller)+'</span></div><button type="button" class="buy-active-cancel market-lot-remove" data-listing-id="'+esc(lot.listing_id)+'">Удалить лот</button></div>'
}
function removeMarketLot(login,listingId,button){
 if(!/^\d+$/.test(String(listingId||''))){toast('Некорректный ID лота');return}if(!window.confirm('Снять этот лот с продажи?'))return;
 button.disabled=true;button.textContent='Удаление…';
 return fetch('/api/market/listings/'+encodeURIComponent(login)+'/remove',{method:'POST',headers:{'Content-Type':'application/json'},cache:'no-store',body:JSON.stringify({listing_id:String(listingId)})}).then(function(r){return r.json().then(function(d){if(!r.ok||!d.ok)throw new Error(d.message||'Steam не снял лот с продажи');return d})}).then(function(d){toast(d.message||'Лот снят с продажи');delete marketLotsCache[login];return loadMarketListings(true)}).catch(function(e){button.disabled=false;button.textContent='Удалить лот';toast(e.message||'Не удалось снять лот с продажи')})
}
function removeAllMarketLots(){
 var acc=selectedAccount(),button=document.getElementById('marketLotsRemoveAllBtn');if(!acc||!marketLotsMode)return;if(!window.confirm('Удалить все активные лоты аккаунта '+acc.login+'?'))return;
 button.disabled=true;button.textContent='Удаление…';notifyActivity(acc.login+': удаление всех активных лотов','info','Market');
 return fetch('/api/market/listings/'+encodeURIComponent(acc.login)+'/remove-all',{method:'POST',cache:'no-store'}).then(function(r){return r.json().then(function(d){if(!r.ok||!d.ok)throw new Error(d.message||'Не удалось удалить активные лоты');return d})}).then(function(d){
  var hasErrors=Number(d.failed||0)>0||d.complete===false;toast(d.message||'Удаление лотов завершено');notifyActivity(acc.login+': '+(d.message||'Удаление лотов завершено'),hasErrors?'error':'success','Market');delete marketLotsCache[acc.login]
 }).catch(function(e){toast(e.message||'Не удалось удалить активные лоты');notifyActivity(acc.login+': '+(e.message||'Ошибка удаления лотов'),'error','Market')}).finally(function(){button.textContent='Удалить все лоты';return loadMarketListings(true)})
}
function renderMarketLots(d,acc){
 if(!marketLotsMode||!acc||currentGame==='Buy TF2')return;var current=selectedAccount();if(!current||current.login!==acc.login)return;
 var listings=d.listings||[],count=Number.isFinite(Number(d.count))?Number(d.count):listings.length,inv=document.getElementById('inventory');setMarketLotsCount(count);setMarketLotsRemoveAllState(count);inv.style.display='block';document.getElementById('itemCount').textContent='Активные лоты: '+count+' • '+acc.login;
 var salesTotal=marketSalesTotalCents(listings),html='<div class="buy-active-orders buy-active-main market-lots-panel"><div class="market-lots-heading"><h3>Активные лоты на продаже</h3><span class="market-lots-balance">Баланс продаж: '+esc(orderMoney(salesTotal,d.currency))+'</span></div>';
 html+=listings.length?listings.map(function(lot){return marketLotRow(lot,d.currency)}).join(''):'<div class="buy-active-empty">Активных лотов на продаже нет</div>';
 if(count>listings.length)html+='<div class="market-lots-footnote">Показано '+listings.length+' из '+count+' лотов • баланс продаж посчитан по показанным лотам</div>';if(d.warning)html+='<div class="market-lots-warning">'+esc(d.warning)+'</div>';inv.innerHTML=html+'</div>';
 inv.querySelectorAll('.market-lot-remove').forEach(function(button){button.onclick=function(){removeMarketLot(acc.login,button.getAttribute('data-listing-id'),button)}})
}
function loadMarketListings(force){
 var acc=selectedAccount();if(!acc){setMarketLotsCount(0);return Promise.resolve(null)}var login=acc.login,cached=marketLotsCache[login];
 if(cached)setMarketLotsCount(cached.data.count);else setMarketLotsCount('…');
 if(!force&&cached&&Date.now()-cached.time<30000){updateMarketWalletUI(login,cached.data);if(marketLotsMode)renderMarketLots(cached.data,acc);return Promise.resolve(cached.data)}
 if(!force&&marketLotsPending[login])return marketLotsPending[login];
 var requestId=(marketLotsRequests[login]||0)+1;marketLotsRequests[login]=requestId;if(marketLotsMode)renderMarketLotsLoading(acc);
 var request=fetch('/api/market/listings/'+encodeURIComponent(login)+'?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json().then(function(d){if(!r.ok||!d.ok)throw new Error(d.message||'Не удалось загрузить активные лоты');return d})}).then(function(d){
  if(marketLotsRequests[login]!==requestId)return d;marketLotsCache[login]={time:Date.now(),data:d};updateMarketWalletUI(login,d);var current=selectedAccount();if(current&&current.login===login){setMarketLotsCount(d.count);if(marketLotsMode&&currentGame!=='Buy TF2')renderMarketLots(d,current)}return d
 }).catch(function(e){
  if(marketLotsRequests[login]!==requestId)return null;var current=selectedAccount();if(current&&current.login===login){if(!marketLotsCache[login])setMarketLotsCount('—');if(marketLotsMode&&currentGame!=='Buy TF2')renderMarketLotsError(e.message,current)}return null
 }).finally(function(){if(marketLotsPending[login]===request)delete marketLotsPending[login]});marketLotsPending[login]=request;return request
}
function showMarketLots(){
 if(currentGame==='Buy TF2')return;var acc=selectedAccount();if(!acc){toast('Сначала выберите аккаунт');return}
 if(marketLotsMode){marketLotsMode=false;loadRealInventory(false);return}
 marketLotsMode=true;inventoryRequestToken++;if(inventoryPollTimer){clearTimeout(inventoryPollTimer);inventoryPollTimer=null}if(inventoryUnlockTimer){clearTimeout(inventoryUnlockTimer);inventoryUnlockTimer=null}inventorySelectedAssets.clear();closeInventoryContextMenu();updateInventoryViewControls();
 var cached=marketLotsCache[acc.login];if(cached)renderMarketLots(cached.data,acc);else renderMarketLotsLoading(acc);loadMarketListings(false)
}
function inventoryTotal(value,currency){if(!Number.isFinite(Number(value)))return "—";var symbols={1:"$",2:"£",3:"€",5:"₽",18:"₴",37:"₸"};return (symbols[currency]||"")+Number(value).toFixed(2)+(symbols[currency]?"":" currency "+currency)}
function inventoryLockDates(it){
 var unlock=Number(it.trade_lock_until||0)*1000;if(!unlock)return null;var date=new Date(unlock),pad=function(v){return String(v).padStart(2,'0')};
 return {short:pad(date.getUTCDate())+'.'+pad(date.getUTCMonth()+1)+' '+pad(date.getUTCHours())+':'+pad(date.getUTCMinutes())+' GMT',full:pad(date.getUTCDate())+'.'+pad(date.getUTCMonth()+1)+'.'+date.getUTCFullYear()+' '+pad(date.getUTCHours())+':'+pad(date.getUTCMinutes())+' GMT',timestamp:unlock}
}
function inventoryLockLabelHtml(it){
 if(it.tradable)return '';var dates=inventoryLockDates(it),now=Date.now();
 if(dates&&dates.timestamp>now)return '<div class="inventory-item-lock" title="Можно будет передать: '+dates.full+'">'+dates.short+'</div>';
 var notice=String(it.trade_lock_notice||'').trim();if(notice)return '<div class="inventory-item-lock" title="Можно будет передать: '+esc(notice)+'">'+esc(notice)+'</div>';
 return ''
}
function inventoryFlagsHtml(it){
 var parts=[];
 if(it.tradable)parts.push('<span class="inventory-flag-tradable" title="Можно передать">T</span>');
 else parts.push('<span class="inventory-flag-locked" title="Нельзя передать">L</span>');
 if(it.marketable)parts.push('<span class="inventory-flag-marketable" title="Можно продать на Торговой площадке">M</span>');
 return '<span class="inventory-item-flags">'+parts.join('<span class="inventory-flag-separator"> / </span>')+'</span>'
}
function scheduleInventoryUnlock(acc,game){
 var next=0,now=Date.now();currentInventoryItems.forEach(function(it){var unlock=Number(it.trade_lock_until||0)*1000;if(!it.tradable&&unlock>now&&(!next||unlock<next))next=unlock});if(!next)return;
 inventoryUnlockTimer=setTimeout(function(){
  inventoryUnlockTimer=null;if(currentGame!==game||!currentInventoryAccount||currentInventoryAccount.id!==acc.id||!currentInventoryData)return;
  var time=Date.now(),expired=currentInventoryItems.some(function(it){var unlock=Number(it.trade_lock_until||0)*1000;return !it.tradable&&unlock&&unlock<=time});
  if(expired){toast('Срок трейд-блокировки истёк — обновляем инвентарь');loadRealInventory(true)}else scheduleInventoryUnlock(acc,game)
 },Math.min(Math.max(1000,next-Date.now()+1000),2147483647))
}
function sortedInventoryItems(items){
 var indexed=(items||[]).map(function(it,index){return {it:it,index:index}}),tradableFirst=function(a,b){return a.it.tradable===b.it.tradable?a.index-b.index:(a.it.tradable?-1:1)};
 if(inventorySortMode==='price-desc'||inventorySortMode==='price-asc'){
  var direction=inventorySortMode==='price-desc'?-1:1,price=function(it){var value=Number(it.price_value);return it.price_value!==null&&it.price_value!==undefined&&it.price_value!==''&&Number.isFinite(value)?value:null};
  indexed.sort(function(a,b){var ap=price(a.it),bp=price(b.it);if(ap===null&&bp===null)return tradableFirst(a,b);if(ap===null)return 1;if(bp===null)return -1;return ap===bp?tradableFirst(a,b):(ap-bp)*direction});
 }else if(inventorySortMode==='lock'){
  var now=Date.now(),info=function(it){var time=Number(it.trade_lock_until||0)*1000,locked=!it.tradable&&time>now;return {time:time,rank:locked?0:(it.tradable?1:2)}};
  indexed.sort(function(a,b){var ai=info(a.it),bi=info(b.it);return ai.rank!==bi.rank?ai.rank-bi.rank:(ai.rank===0&&ai.time!==bi.time?ai.time-bi.time:tradableFirst(a,b))});
 }else indexed.sort(tradableFirst);
 return indexed.map(function(entry){return entry.it})
}
function renderInventoryData(data,acc,game){
 if(marketLotsMode)return;
 currentInventoryData=data;currentInventoryItems=data.items||[];currentInventoryAccount=acc;currentInventoryAppid=inventoryGames[game];currentInventoryContext=String(inventoryContexts[game]||2);if(inventoryUnlockTimer){clearTimeout(inventoryUnlockTimer);inventoryUnlockTimer=null}
 var inv=document.getElementById("inventory");if(!inv)return;inv.innerHTML="";
 currentInventoryItems.forEach(function(it){var unlock=Number(it.trade_lock_until||0)*1000;if(!it.tradable&&unlock&&unlock<=Date.now())it.tradable=true});
 var items=sortedInventoryItems(currentInventoryItems),count=document.getElementById("itemCount");if(count)count.textContent=items.length+" предметов • "+inventoryTotal(data.total_value,data.currency_id)+" • "+acc.login;
 if(!items.length){inv.innerHTML='<div class="inventory-empty">Инвентарь пуст для '+esc(game)+'.</div>';return}
 items.forEach(function(it){var card=document.createElement("div");card.className="inventory-item";var unlock=Number(it.trade_lock_until||0)*1000;if(!it.tradable&&unlock&&unlock<=Date.now())it.tradable=true;var price=it.price||((it.marketable)?"Обновление…":"Не продаётся");if(inventorySelectedAssets.has(String(it.assetid)))card.classList.add('selected');var selectHtml=(it.tradable||it.marketable)?'<label class="inventory-select" title="Выбрать для трейда или продажи"><input type="checkbox" data-asset="'+esc(String(it.assetid))+'" '+(inventorySelectedAssets.has(String(it.assetid))?'checked':'')+'><span class="inventory-checkmark"></span></label>':'';card.innerHTML=selectHtml+(Number(it.amount)>1?'<span class="inventory-amount">×'+Number(it.amount)+'</span>':'')+'<div class="inventory-item-icon">'+(it.icon?'<img loading="lazy" src="'+esc(it.icon)+'" alt="">':'—')+'</div><div class="inventory-item-name" title="'+esc(it.name)+'">'+esc(it.name)+'</div>'+inventoryLockLabelHtml(it)+'<div class="inventory-item-bottom"><span class="inventory-item-price '+(!it.marketable?'unavailable':'')+'" title="'+esc(price)+'">'+esc(price)+'</span>'+inventoryFlagsHtml(it)+'</div>';var checkbox=card.querySelector('[data-asset]');function toggleItem(){if(!it.tradable&&!it.marketable){toast(it.name+' • недоступен для обмена или продажи');return}var id=String(it.assetid);if(inventorySelectedAssets.has(id))inventorySelectedAssets.delete(id);else inventorySelectedAssets.add(id);var selected=inventorySelectedAssets.has(id);if(checkbox)checkbox.checked=selected;card.classList.toggle('selected',selected)}if(checkbox)checkbox.onchange=function(e){e.stopPropagation();var id=String(it.assetid);if(this.checked)inventorySelectedAssets.add(id);else inventorySelectedAssets.delete(id);card.classList.toggle('selected',this.checked)};var selectLabel=card.querySelector('.inventory-select');if(selectLabel)selectLabel.onclick=function(e){e.stopPropagation()};card.oncontextmenu=function(e){e.preventDefault();e.stopPropagation();openInventoryContextMenu(e,it)};card.onclick=toggleItem;inv.appendChild(card)});
 scheduleInventoryUnlock(acc,game);
}
function loadRealInventory(force){
 marketLotsMode=false;updateInventoryViewControls();var inv=document.getElementById("inventory"),acc=selectedAccount(),game=currentGame;if(!inv)return;inv.style.display="grid";inventorySelectedAssets.clear();
 document.querySelectorAll(".game").forEach(function(t){t.classList.toggle("active",t.dataset.game===game)});
 if(inventoryPollTimer){clearTimeout(inventoryPollTimer);inventoryPollTimer=null}
 if(!acc){setMarketLotsCount(0);inv.innerHTML='<div class="inventory-empty">Выберите аккаунт слева, чтобы загрузить его реальный инвентарь.</div>';document.getElementById("itemCount").textContent="Инвентарь не выбран";return}
 if(!inventoryGames[game]){inv.innerHTML='<div class="inventory-empty">Для '+esc(game)+' нет поддерживаемого Steam Community inventory.</div>';document.getElementById("itemCount").textContent=acc.login;return}
 loadMarketListings(!!force);
 var token=++inventoryRequestToken,login=acc.login,appid=inventoryGames[game],context=inventoryContexts[game]||2,button=document.getElementById("inventoryRefreshBtn");if(button)button.disabled=true;
 inv.innerHTML='<div class="inventory-empty"><span class="inventory-loading">Загрузка инвентаря '+esc(game)+'…</span><br>Цены обновляются отдельно и сохраняются в кэш.</div>';
 fetch('/api/inventory/'+encodeURIComponent(login)+'?appid='+appid+'&context='+context+(force?'&refresh=1':'')+'&ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Не удалось загрузить инвентарь');return d})}).then(function(d){
  if(token!==inventoryRequestToken)return;renderInventoryData(d,acc,game);if(d.warning)toast(d.warning);
  var ps=d.price_state||{},count=document.getElementById("itemCount");if(ps.running){if(count)count.textContent=(d.count||0)+' предметов • '+inventoryTotal(d.total_value,d.currency_id)+' • цены '+ps.done+'/'+ps.total;inventoryPollTimer=setTimeout(function(){pollInventoryPrices(token,login,appid,game)},2500)}else if(ps.message)toast(ps.message);
 }).catch(function(e){if(token!==inventoryRequestToken)return;inv.innerHTML='<div class="inventory-empty">'+esc(e.message||'Ошибка загрузки инвентаря')+'</div>';document.getElementById("itemCount").textContent='Ошибка • '+login}).finally(function(){if(token===inventoryRequestToken&&button)button.disabled=false});
}
function pollInventoryPrices(token,login,appid,game){
 if(token!==inventoryRequestToken)return;var acc=accounts.find(function(a){return a.login===login});if(!acc)return;
 fetch('/api/inventory/'+encodeURIComponent(login)+'?appid='+appid+'&context='+(inventoryContexts[game]||2)+'&ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){if(token!==inventoryRequestToken||!d.ok)return;renderInventoryData(d,acc,game);var ps=d.price_state||{};if(ps.running){document.getElementById('itemCount').textContent=(d.count||0)+' предметов • '+inventoryTotal(d.total_value,d.currency_id)+' • цены '+ps.done+'/'+ps.total;inventoryPollTimer=setTimeout(function(){pollInventoryPrices(token,login,appid,game)},2500)}else if(ps.message)toast(ps.message)}).catch(function(){});
}
function renderGame(game){marketLotsMode=false;currentGame=game;updateInventoryViewControls();if(game==="Buy TF2"){renderBuyTF2();return}loadRealInventory(false)}
function renderAccountInventory(acc){
 if(!document.getElementById("statisticTab").classList.contains("active"))return;
 selectedId=acc.id;if(detailAccount)closeAccountDetail();
 document.querySelectorAll(".right-main-tabs .mode").forEach(function(x){x.classList.remove("active")});document.getElementById("inventoryTab").classList.add("active");
 var inv=document.getElementById("inventory");if(inv){inv.style.removeProperty("display");inv.style.display=currentGame==="Buy TF2"||marketLotsMode?"block":"grid"}updateInventoryViewControls();
 if(currentGame==="Buy TF2"){
  marketLotsMode=false;renderBuyTF2();
  if(document.getElementById("buyTf2Modal").classList.contains("show")){document.getElementById("buyTf2PriceLabel").textContent="Моя цена за 1 предмет ("+buyCurrencyCode(acc)+")";updateBuyTf2Total();loadBuyTf2Orders()}
 }else if(marketLotsMode){inventoryRequestToken++;var cached=marketLotsCache[acc.login];if(cached)renderMarketLots(cached.data,acc);else renderMarketLotsLoading(acc);loadMarketListings(false)}else loadRealInventory(false);
}
var inventoryContextItem=null;
function closeInventoryContextMenu(){inventoryContextItem=null;var menu=document.getElementById('inventoryContextMenu');if(menu)menu.classList.remove('show')}
function openInventoryContextMenu(event,item){
 closeContextMenu();inventoryContextItem=item;var menu=document.getElementById('inventoryContextMenu'),button=document.getElementById('inventoryContextSell');document.getElementById('inventoryContextName').textContent=item.name||item.market_hash_name||'Предмет';document.getElementById('inventoryContextName').title=item.name||'';button.disabled=!item.marketable;menu.classList.add('show');var width=menu.offsetWidth||238,height=menu.offsetHeight||100,x=Math.min(event.clientX+4,window.innerWidth-width-8),y=Math.min(event.clientY+4,window.innerHeight-height-8);menu.style.left=Math.max(8,x)+'px';menu.style.top=Math.max(8,y)+'px'
}
var sellItemTarget=null,sellItemOrderData=null,sellItemOrderToken=0,sellItemPriceDirty=false,buyTf2Name="Mann Co. Supply Crate Key",buyTf2Token=0;
function sellItemOrderRows(list,kind,currency){
 var copy=(list||[]).slice();copy.sort(function(a,b){return kind==='buy'?Number(b[0])-Number(a[0]):Number(a[0])-Number(b[0])});copy=copy.slice(0,8);return copy.length?copy.map(function(level){return '<div class="buy-order-row '+kind+'"><b>'+orderMoney(level[0],currency)+'</b><span>'+Number(level[1])+' шт.</span></div>'}).join(''):'<div class="buy-order-row">Нет ордеров</div>'
}
function openSellItem(item,acc,appid,contextid){
 if(!item||!item.marketable){toast('Этот предмет нельзя продать на Торговой площадке');return}if(!acc){toast('Сначала выберите аккаунт');return}
 closeInventoryContextMenu();sellItemTarget={item:item,login:acc.login,appid:appid,contextid:contextid};sellItemOrderData=null;sellItemPriceDirty=false;
 document.getElementById('sellItemName').textContent=item.name||item.market_hash_name||'Предмет';document.getElementById('sellItemAccount').textContent=acc.login+' • '+currentGame;
 var icon=document.getElementById('sellItemIcon');icon.src=item.icon||'';icon.style.display=item.icon?'block':'none';
 document.getElementById('sellItemPrice').value='';document.getElementById('sellItemCurrency').textContent=buyCurrencyCode(acc);document.getElementById('sellItemLowest').textContent='—';document.getElementById('sellItemHighest').textContent='—';document.getElementById('sellItemSellOrders').textContent='Загрузка…';document.getElementById('sellItemBuyOrders').textContent='Загрузка…';updateSellItemNet();
 var saleModal=document.getElementById('sellItemModal');saleModal.classList.add('show');saleModal.style.setProperty('display','flex','important');saleModal.style.setProperty('z-index','1200','important');loadSellItemOrders(true)
}
function loadSellItemOrders(force){
 var target=sellItemTarget;if(!target)return;var acc=accounts.find(function(a){return a.login===target.login})||currentInventoryAccount;if(!acc)return;var token=++sellItemOrderToken,button=document.getElementById('sellItemRefresh'),status=document.getElementById('sellItemOrderStatus'),name=target.item.market_hash_name||target.item.name,currency=buyCurrencyId(acc),country=acc.country||'US';button.disabled=true;button.classList.add('loading');status.textContent='Получаем свежий стакан Steam…';
 fetch('/api/market/listing?appid='+target.appid+'&currency='+currency+'&country='+encodeURIComponent(country)+'&login='+encodeURIComponent(acc.login)+'&name='+encodeURIComponent(name)+'&include_fees=1'+(force?'&force=1':'')+'&ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json().then(function(d){if(!r.ok||!d.ok)throw new Error(d.message||'Ордера недоступны');return d})}).then(function(d){
  if(token!==sellItemOrderToken||sellItemTarget!==target)return;sellItemOrderData=d;document.getElementById('sellItemSellOrders').innerHTML=sellItemOrderRows(d.sell_orders,'sell',d.currency);document.getElementById('sellItemBuyOrders').innerHTML=sellItemOrderRows(d.buy_orders,'buy',d.currency);document.getElementById('sellItemLowest').textContent=orderMoney(d.lowest_sell_order,d.currency);document.getElementById('sellItemHighest').textContent=orderMoney(d.highest_buy_order,d.currency);
  var highest=Math.round(Number(d.highest_buy_order)),minimumBuyer=marketBuyerPaysCents(1,target.appid,d.fee),exactSeller=marketSellerReceivesCents(highest,target.appid,d.fee);if(!sellItemPriceDirty&&Number.isFinite(highest)&&highest>=minimumBuyer&&exactSeller>0)document.getElementById('sellItemPrice').value=(highest/100).toFixed(2);updateSellItemNet();status.textContent=(d.stale?'Сохранённый стакан • ':'Стакан обновлён • ')+(d.warning||'цены в '+buyCurrencyCode(acc))
 }).catch(function(e){if(token!==sellItemOrderToken||sellItemTarget!==target)return;status.textContent='Не удалось обновить стакан: '+(e.message||'ошибка Steam');document.getElementById('sellItemSellOrders').textContent='Ордера недоступны';document.getElementById('sellItemBuyOrders').textContent='Ордера недоступны'}).finally(function(){if(token===sellItemOrderToken){button.disabled=false;button.classList.remove('loading')}})
}
function useSuggestedSellItemPrice(){if(!sellItemOrderData){toast('Сначала дождитесь загрузки стакана');return}var highest=Math.round(Number(sellItemOrderData.highest_buy_order)),minimumBuyer=sellItemTarget?marketBuyerPaysCents(1,sellItemTarget.appid,sellItemOrderData.fee):3,exactSeller=sellItemTarget?marketSellerReceivesCents(highest,sellItemTarget.appid,sellItemOrderData.fee):0;if(!Number.isFinite(highest)||highest<minimumBuyer){toast('Нет ордера покупки, достаточного с учётом комиссий');return}if(!exactSeller){toast('Steam не может выставить ровно эту цену с текущим шагом комиссий валюты');return}document.getElementById('sellItemPrice').value=(highest/100).toFixed(2);sellItemPriceDirty=false;updateSellItemNet();document.getElementById('sellItemPrice').focus()}
function closeSellItem(){sellItemOrderToken++;sellItemTarget=null;sellItemOrderData=null;sellItemPriceDirty=false;var modal=document.getElementById('sellItemModal');modal.classList.remove('show');modal.style.removeProperty('display');var refresh=document.getElementById('sellItemRefresh');refresh.disabled=false;refresh.classList.remove('loading')}
function submitSellItem(){
 if(!sellItemTarget)return;var price=document.getElementById('sellItemPrice').value.trim();if(!price){toast('Укажите цену продажи');return}
 var target=sellItemTarget,button=document.getElementById('sellItemSubmit'),status=document.getElementById('sellItemOrderStatus'),priceCents=Math.round(Number(price.replace(',','.'))*100),exactSeller=marketSellerReceivesCents(priceCents,target.appid,sellItemOrderData&&sellItemOrderData.fee);if(!Number.isFinite(priceCents)||!exactSeller){status.textContent='Steam не может выставить ровно эту цену с текущим шагом комиссий валюты. Измените цену.';toast('Точная цена невозможна для этой валюты');return}button.disabled=true;button.textContent='Отправка в Steam…';status.textContent='Создаём объявление на Торговой площадке…';
 fetch('/api/market/sell/'+encodeURIComponent(target.login),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({appid:target.appid,contextid:target.contextid,assetid:target.item.assetid,buyer_pays:price})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Продажа не выполнена');return d})}).then(function(d){toast(d.message);closeSellItem();if(d.needs_confirmation)setTimeout(function(){openConfirmModal(target.login)},700);loadRealInventory(true)}).catch(function(e){var message=e.message||'Steam отклонил запрос';status.textContent='Ошибка продажи: '+message;toast(message);notifyActivity(target.login+': '+message,'error','Market')}).finally(function(){button.disabled=false;button.textContent='Выставить на продажу'})
}
var buyTf2Cache={},buyTf2Pending={},buyTf2LocalImages={"Mann Co. Supply Crate Key":"data:image/webp;base64,UklGRhYMAABXRUJQVlA4WAoAAAAQAAAAPwEAswAAQUxQSO0CAAABx8AokiTF0aV8LR7fybiIiMDE5Cqu/6NUnCDbtp3IcayOSFE9QoJK/P+n2hQG/HIyOqL/ECTJjdssoAIEUkcVYwQEYD/ggo+e/uPpP57+499giIYOqRDTYiodSlGFl2ZeO+SWYlABpvWVwskg21kbMWyIWFOrjRlyBGSUaLVOsF2NkOSMEQ+HUus848EKpoMlDAdrmA0WMTtUT8ol17PbElSLAmXHWIp5xSZky17XUQlQdjxLQeb+ywbgwZPCQy3hNxNEw264TkRDUOmEnOarp0AI01MMN4r5amF1LtqulVu5UjuD1Llo7PkJP4YtfvhU4gdEafT4+OGDa2VvN2fM5Mh+ZxXebGytPAUNccTgliAc3bU6v4jbV7NWbbfNJo1/HukhUQTHXdGvy4ueur3Ge5gQZMcGxMmdLumhY5AdGxH322pg1QXK/sWmravvP83H8F1VGHUTziRxKGnI0IkdH5oEQ7DHnm5joDR/oh0Y3Hxr4iU+/6tmG6lpaW7dTfQmvNyt59jfRHOxFHNijfuzJTy3NVkvCOWoiXvz0Zp7r4gu0cRJU9ElOA2Rtw3stJjKhLtlpE2FSQGbVqvt4WpBWAvAllK0KHAs8LLZHcs0IyoFkCpHPaBD2qLQSessMZGZscrE5ZuFzEyh1BaLTTDwGCaC1XNw4BFzwMEPvwlQl7n14yq39Jr9rmDQs+/HRHmqH9cfb+ElWnMJjN+k9PyafbwJSaL176bJG2aR8UnbS7SJwrIm795Nttwyiq23ys0DjxeWZcveFRKteRSQX/e8Xxode6cSms+B25ei+ZGd4z2+jL1Tu1yypaZ2Skbc/7OWaP1Pg2ijERETextNDqjdQbbso9mJCVdB5JIJ1qvGh0JZm95BM+xmE7trPMOn1q7dRgWiYduDiqYxAWnYojQriG34tFyauA2fxJYd27DnrTXdgM70dftiCbSblHDe6uCihz2NRyvTz89vF3KsTXs/Pnr6j6f/ePqPv5JxAQBWUDggAgkAALA4AJ0BKkABtAA+PR6NRKIhoRG8LRggA8Sxt3C21xe5AdpfuP1X8VfBBCd435Zvm4tr+p5Cs7ULf9Hb4/njf7l+meWgcrNiGP8e7Rf7n4U+KP1rKJsQfhCI73o6gXsf+/b1lzX+r/7TjR0oOgB5LX9L5DPpj/0+4b/Mv7pvr37VEMqUZypKerS3686G1RjOVJRl150NqjGcqSnq0t+vOhtUUvoCUOQW4OJfcA5JEgBhUkMD5KVmBrK68vxalONnVVKxdwOhT+5kVhIpu8ESEBGg7qi0IjdKM5UlFycoKW2daY3FUvut6P9zhiANsYC/uuZoUt/AOOgbxo6vd4/d1bLtEfz8gzGcqSnq0s0y+6xkXr7pYH3QB///D78WqO19cSA9m2+FWyzUR6G1RjOVJRBAoT8Cx7arA7KB///wJ///eME42XXx9qB76st8vOhtUYzlSUQTPQ1Xp51ZLe3ypB8F605T/HXkEUOUwwC2GfiN0ozlSU9Wlv12Su3KpmyfWscBf+tD1dREehtUYzlSU9Wlv15yEMsWMKkhgfJSswNXn/Q8eMD5Km4ARDHPnXHQCIU6FrvvYcofAYVJDA+SlZgavP+h48YHyUrI4ci5wAD+zaE+z/MwP1Gdb404xITJBEAAC5Tr1zgpj+AAAFXrxO1lX+yyxixCzfN01vnVlJnbt4fs7jn7sEffE2XSOggC4No20qxv//80tAsr/dF6zM60YXuwP1K6Ek/V4WtQCK6rOSlieb2cs4sDdWUGDym+sv2xtuOvlRH18eQ12JMmtuMFzlHQgnTTIKKGR9n/qi/J1xFXORu/JlfXbXnGK7pkoG8j5ukaxFunW6ydgqZ4YJBf5nM7IbGrCCsabbKxC4BVXWSMw9SpNa1z6fvwjFGYr7g1f+GsAFfYRkP7E8U3vsv3xecnxQnJqXcbjyT585sCWxm6GfYGSue3/1KJDZXsddlnVTHBDwhxer7r7qP6Dc66Nw/Zr5ll87eUVOUJe6lRYcYfvPReTkNH+m+g7pnM725PxHXHHHPTEN+h7SMAItONU0OUS4HQSwcC7kTnHUm7NGHWaj0vkgfBLkdcgVXD5dUJpWizk93TWvQ/1euIsi0hAxElNf3IxG89t/oU8/mF/YThC6XzXN/M1hauvuKffNMGA5tjdn9b7hP5nanHJwfcfDsWlaBVqpi41pl15R72wnVtzGivMuAQaCwVpe+z8JuF1hdPkO2+VS2PdmawSCYv1cv91wR0naG9/eoCj9FV5eZhZlS3IA//HpWycIHS3WWuJ17j7hSejkgedhKGr0h92lBfLye6Y1k40jTiGGcOsGotvogfjFmBaiNDEoa/d+qH8AK53+MBus+ndFxN7XDJy/ooX805XKEDhvAI3HnEiaKAGCqVfI5pDs2fAzyhsNvtJPKbC5CoM421ThN0Fp0dzfX2lkNZ/qi9zNK6JKV6QsQnjsqHVpUUGeAMIEcvYO/CKI0hH0Kg+8ckRd2kTyMDz8lVIEwQ7KwfWPkQugPbSC713sqXFdXb+RC43ttOV5T5/4ugAApktapWCg/OSD91dL97cpNSp28FlUzvPc/qaHaXKD8ZNPfzjRBE8Fx4XzzAx9DBYu8dDAE7KZGE/94+dcOoo93L7pmdLbnVThY5T5Xk9/eW86ZjZJAXDw1u7cIWDY1YDWcSzNWLKcU5y8SzI6ZOEjH/aEkx+X3hlQYxrJNovJL0zO8iP/VI8B1xYXZJoFP442VOgC8Q+9DP42mUD0XrAye28hnvOBbmYkMGLtArGm33nzslivH9Ne1mDMWtb8Qzwv2lxWe2B4ruRTAo39/8NyWekTaWlozEvwOc76CxnkXHsAgjsVaROwl/8VMxF97JrxXJ0sfBrYi+evJSe49gzx/Rr9pkmizUaOvQERHtCM6oo6y+8FZF/Of2WcZgbF1Nj1ltFqOOCFab/BJeGVAqOkx2FdIs6zJaTiEzH8wT0pslJxe7LzozJJSZhsvwvmBaD7CWCO5jggkxY8pJ4944T8ysRRU5Crczaf0MlhaTNo/YCKoMe4JvqFH2qCMu8sx61DKQnlsk6PB0BqWiZ2NR2oBGAkljM4t1tYXFssQ4vM2mom+HFGWSNXCRduTpoOC+abgXugZi3cDneARsfbUXShCl4UFaMpoNUyIbX7ZZmybubAx9/ig3GH+njU1qvisLZXX/jIZDTVV8HtXvoDEVmc6x8jFLXoljNu0E2gsIOy4UB5Tjc/+PNdlZNh8PGdJRknYfL7UyfwZSvUO+0thhugwEUNS2PlWNb4XmtQNzpiQQVYS57wt/cTDXRnM/YvugH7S5Qy1l3tgzl3hb8oUNkiNxDQ81Jg6iqwGVfaju8Wc46READyz0kha9E84j0wHfG3v6tAVDQFox5EvOrUfV3zkJPDTwF+rNMiNPJMkhOqXFnWBP/3k3ULvHz8App4uigGv6eLB4DpcvaIYrR7LgNrS7b6xauOxswlyKJ0iz04noRaObWnG1YrX+zD53dars4Y30CIW2tJW5yLmJQTyOPVr+jiesvdBPKg+1tQeZ9gqsVYb2V+gG1xhk3J9wSIVCjFERN8sQvcfp6fy8lJjx6VVqqi8qKd5MWPyXyqDyjD9hsl0CupulvTP44Ej0WOvj4X6ZGS1wqv7JtqS59GBca+29VQjO1eS1dpVl7X2u8wDrY7of7q9vJi7AurVOLVs+GT9yXYDKJB3Rgt5I+f+hm28AcdVf1rPBQ1z19E0XbeBrqUpnzM72ifbwwEcz/JUQSB2O4pFUFrTtkD2cMfiRH4PMZNBmiQb/3ciUdaAIAgdRt37mPWyj5NcaEU5qxIr8cBpk/2UN/qmPGam/oxJbemw69W9aRL4nxzj/ANolPc3wXWBAhfBdudRXrN0ahekQNjmHXN+Efx2rnbfTBpDFpj0B2bEAF7LNRPmso5UrJFwr8IKMDaQAAAADnMgG+GfIbWjAsL39MEuElZ/lZKB543GjjJUSevFIqxpZm0vN9Io0rxZ9TRfGuXiz6fWIlfuGn2+65ddHKhL7ro5UJiGEceDduh/Zb4IMAXt37em8DkF6i+DLuDac347QAAAA","Tour of Duty Ticket":"data:image/webp;base64,UklGRgIvAABXRUJQVlA4WAoAAAAQAAAAPwEAuwAAQUxQSLYHAAABBg/UthmStG1bZGW57Znp6bFt27atnsvG2LZt27ZtT5ujtruqsjLjMjoj48zrZmRETAD7v///7///+/8f0rKVOfXEaGKMGWv98OMf/WH03ectOdXDXDCIMRZYZd2B/YztfYT/9OMqKoZf63aa1npGaEQ4YywW/9XO0XrVweRiZW69pk2esD09J5sxB/67Ez82qgimYiWKV1h25iQ7/Rbn4YRPeFWAq9mrR9eJkfFxb5w4zyeNrcaBzsWN1Z89d/4jhy2XYZk6H08vATTPCqxc40NXL4Vg+R8pAi2O+fYZPHD9hwQtGRPyaB8vjoHJ3bPkrOW7MwRNxCTN2Ll8ZnEP3R8wemmeBpj4tTp596mIiSw+vTa4as3frFF9/L0H12tBg3ft+fknH+9KxyTPSk75XRtm10qDwse34rJdCZLIsGJGfVMRgZGv2bDb1WdhWFltwQiI5najvpsSnZmFFVdY7MUBIH+B2luisFJnnxhcoCDjac6vxZAHYXFYyVPDtGf9eTrTzGXGTNiWnosp8I43jWlFhx27I2JKPOdBX26ddsenY2q8XRNRtdV75LxZ61MlTI8P6yKa9qi/91oqpswtHDVxfL2BGxIxfd6oiDgdRz8u3gOWr3gmiJhCxctLlq74wZ1u+PL1t95PwFRrm+1NLZyerz42Mk3CtJvZiVbcu27Q7kuYeqW0vcWoxFK7zYkETMUpPfwQffKmpvPfZ2JK/lAOUadf0Sn7QjA9JzegjcJ9bkbYME1LFysiVtiHEgz1x2vHczB1XxqvnVjkSgPm8stfYmqPDFI+fb05MRJWazhr0JiFYSKm+Ox5Lorm3+PkLQem+w3uSMH9+5/OwNS/J79iuXgP3J+FAWg/GuzjYVEg97o77yZhIKbeubswQGF05narEzEo7cMVxVhy7tY4DEzbMAXRVZ76SsLQzF3oqxh89fERDgzPpAEGhfAvPucRhmnEpspKUHzo/QgBg/Vq54YWsvGmKmdtGLJSTuK3FoL5FvnkyAMM3vRgcpU5HJeBAZw2glzfSBjC2ZqFXD9gECc1RCoPu1WbWMXOAYldr+NmIFOTLCix0BtjSutI1DgDTIzZw7ro1B2Wu9pAoIaQyvkkiCOPabIdUFmtEIH9nmJAO/cEkugZpJi0p3Xz0qTplQgqJmZlX6lFFvd9GN63anIEcZ2RCTBxpokcrlOzMbylXYGInF9mY4A7hyByFj2DIS4tcydG0F4BZCxrew8PCxGC9mCwv7u1vqD83HoflODGmLSrsNxcJmRi2Itr3ORlnZyFgR/dn5eRrvpnSzIx9OdwSL4Bsx9IGP4LePkEbcaq4NtgnWyq3XTk2iT4sXczR43rbJSFrmr3LsPfqAC/ju8oi1/7vlYJ3naWTeEw6CUvHD+BsUndjHLxmm+DnRDyrRHJ2nuJHYNeWFPUiORdNwWD3rbBH8m9QTbsDgcg2ZdYvmnDlhi4XSwlP06v8W7H4OYYLr9fm47ATRxJButxuDlHEEE3MB5u4jc6AugHv8WAf1GaAPmeYcgnVSZAYAToUpoSwPMg6KTDLvJjZcZMmjAjEmrsji8Bfm29ALb0TwnhchFsbBlHBF3POLjNRiTkekVhmEc+eXG0PAl03eMwsCWRsQcbN6+q6evviUjI90+DU2ZyiqbFTvr4U1ZLr2mImEXiQZR5/y672rdaTcaqGBBpvbbZBIcIGc0Zu3blV/6eXoxDhC48YPCQczBJ+qBpiQ8/GdLWxDFE+iXwEO9dPtioXAVWsRhSRG4pJJw2LW3znElFXTWkoJaNUBDitbjl3Xp28kQKax6dAoLUs6fnlS1ewg0pr+H7dEz7Ym7E7CnDPa0mpMzW/ZjuY8KjdnaqxyMlr59EbeLtPQfWVAos5IkU3vuzUd/tEegr6/3CbyoaTEZEiQU2Oqgq5tnL0+3rWRFVFntNSxLLOLi2gW+AF6LN4alUJKXHTvl0sDePKNT/BKbfkLsP9zWpbEB06rfWRjmSGLa0qqe3G6JVy2IHptrMhJ3DmhkQzXo/wtSac+vK1YtDyvkiyjXPyLTbnBQi2M5/E+Dm7qZD9OvVpVePVTm0IUSN714S0bTPKZoQrp86N7e0AdF1g5fUIOReHxVkdTEiyjaPiaMEKWpWu7KIxkt0r7Q6RPGcN/YdWl7GjOic1zNDyycOJROyH40qbTQzRPXlv3/uUKyoJc0qIgDqC02+7ZSUx3Zy66rKZgREXaXP2E5BURwhY4MD9QYEyvzrJeUQn0+swCF4BkzdEC4KTuIJzuiNM4sZEEg5Y8vgoaMj7UTLuffp8DYmHYIsX27a9UhiPb38aREEYKNb0xVvReJIduH57PKuegRkU6s1dsKknx3Qp64OQdprkYMkaad7BiBw+3w7fRpjkw8KshMj5k4P9uIQ2IO2SfKSYubW4xHs820X5fRyRTkLAn/gzoxceeSkbBjVwIDUwMDGHz/JyXvpt/o08kKqoS5w9K7tjL3KQ7kng/2QusgbmcHY5lXeEN/P+2JkPg6pkq1C8kLU6roWpF622pTwd0WurGVGqqa181bhb0h7t7i5EamefqvEv+rDqdYVXJEa6jduRYhg/11H8oalYYKdOTJ29nJDqqm+cf++v9uvsyvfpH9frV93b/SfQQFWUDggJicAANB/AJ0BKkABvAA+PRyMRCIhoRMrvZAgA8Sm7hb9EIFJ1AlkPD/3P0QOPeyH2n9y86XVd2X5iXT/nU/xn7Gf4D4HfoX/ye4J+wHnhfth7jv71/2vUH/P/8R+3HvX+i7/MeoB/Z/891knoC/uL6b/7vf//5TP7V/2/3P///vbf//2AP//7Y/8A///FHf1D8RveH4RfjPys/db17/GvoP77+XP959tzMH1+/O/qr/Hvtb+q/wv7uexf++/tHjr8HP5f7jPkC/HP5R/if7P+7H99+CX5H/Ad/tZv/leoL64/OP8v/gP3u/xPpfaqHiD/oe4B+sn/N8qnwMPwn+e/ab4AP6P/ff/R7Lf9T/4f8t+Z/t9/Of8z/2v9Z8A38r/qn/J/wH+j9+n2u+iT+x3/gZmXy8IIm1gSy8dUgibWBLLx1SCJtYEsvHVIIms9taIrZzTNZCXQXaTwD/1Mz9O67+gnQS+ZeQK027fmWO1GM8V1fF/6dTbC10eFAifoBQvv7KahuZGK7HjT8o5O0U6mY9ANr/QsP8k6xEUoBRnbaRSB5ep8vvSyJK/YBL9v67X/RUP//v6TuLwJwvmToDNvYPCzzo0FQ0dwYfGgagSQ8L9v/bw+/z6Qbddbs+Jc57y6OUCMtd6ipVz02qzqnIyU2HPT/9KkJJ1P4X+uA99//4qXtPjSxawRtqKoY2eaFTRJ+ggCF1Bpy738ZqVdT9y8aPVz8PVP/yK7SmSUBCkI0JA2tdlRrLs76sFeMkei0HFptESIv6ziEa27Zi3AE1C5MOVNhPy2rLoVZ/YUu2IXkFXpyJv9PjNtFy0f4jDxwur6jCwr39R7dCSjXGiZU8igJU6IRjggnzxjD6FnhH9VY79o5ZFutryxK5nKq6Jmtzd3nxvQBnKs54/qyXunaHAwrVRFKdIQfCgEHBrOv7wJrMyFrOhWbiiYfziV+SDI7Gkv19m4FJJpdsLAoCDmOwNV1aIioIGEdT0o3jnJIV6H5yhKF/GzXaBZ8bVym9/HQFUMNQgDV9X7L9I8lcOxRQH1w/tIwABDM8nvAqj/XRk75zNho9uRhYs6izY1+SZ+IPW6rrkfO8lWS6FEVqSfIhLGvwly5t+Vh4/XW/wj5QbebbT/Y849XMZcJL8RiDv7cv9WpEic20gcWJHeIbTUae3D2yGTIDCWLteq2viLdLGwroWkq7RjjKOZe8z7ThZ59ENEorJ8E0/HwS/YQf7i7/9ruS5pvwFB+gyh0xoMqbInht14pi0GzJVJA6Zh88Qd6X+uj5epxrJFbzvuHnCUk/qLvToR///BPPnWI1NCi8poJPINvLV5IlPpQUnUIm1gS0khRW74PYX7V1YZMtBZr/YWQU//Eij+My+Xg9AAP7/xxoAAACkIGvG7hxO0GyazPLXea+RCc4xCMvX/KDOr+sfGoANKE4X0IxhlgGCGeeMJoH3lAMSTZdBhv9QxKONjyNZjAYrC4eS+eMGFXJZPw1gtPYZ3Vahs2vbuoIbUgt+rOZgDWpneKvcowiWD3uKFM0raW3uVyO1F8KHsQFAzZODhRz66yt5b9Peat0hk1eaTfvShAlY25Nf17m1KNWQNbPrtb0A3mTMH0MS0EzSRRKKSME5I5G9ldbHQ8fMAA5XZ9Pp2vudJiZok+RP+HXb6ejaAsTLyEce3sgJTCPFHVVKJ23VBG0x12AaMT5PbMlmM8CWAZ76EnYIDWOKTC/HZUuQazLAIRjkAijra9yXko96Z7kPMs6r8EOplXjHUogm7kvIM9/wPNYGAiItKfNDWjrLkodg3WJaUnASha9eYHWuvwTcE1TnW8OAG30MY5aSM4O3mZwrTRPZBB0ZDWjWjv0A76x/ehCY2TGmUdgV59Bpj/e9sGkSXRNT/zNhsMveJpJPESwnStJNzTEP1Siuqd6V3+h42UZRpP25xtGV+OjejclakAHH5y8KF7seCXg3qzvBu1TMaytpeEJcufUVi0O09yoShBOe5CuWN5pkTZLDuLxCdxhHksKpzwQkXIqj91UeUTZjLw90KpPytvme5Ouq0dalZwe+qiY37lyZJMtQR565wwjodNunG5CxKPdHvu0sBovzLR0kifluQOemnifnWTAtgdqOoBFkNqXqupZr+8Sk5q6PYjmhUOACNrIK0Uw0vRDFmEtyM40W5r4BpL34Hd5Lo4usG4lPrx+ssEmowBuZxEzOjZzo8wDeJloKvuUtj43uEVzsoZPqsZWWBpkgqMn9RUUZ0URRt71Edo8AX5LdNl2ikXAl7fmR40XDLiZgrsfYqo44gKYlp6PPIXqIld6K6ipr8RhHFoRVUWgqOYu9MRUnF7WAKw1rk+g6kpPMWWdxkzJRdGK1F5i3Gos0AIkuLOwoX59eB5cC+5i6guMjdHMdGUCVEpTyAqgDj2bXQKAxPWpbZI6ENMVpVtX/BiJgRFVnrZrMJo9jCT++6EWMbK1hQ1Ps87jRhdeRljQthg4A/4wgdC4Y1uI97wnsXqFs9eSGUOME8S+++0VDGqmt0zOdWuZb92EFb8LpjFtbY6W4oaT2WR9sjNL7DXPYExJJ3lgngY0TgMBfdpXs0ZfI8Z7P0ReP+WIpT5beRYUHn8OdHzxOKfqEc3SuIYPsmoI+vfUhGAjb5Tl/oNi8OEuQcKwQ1DZQJgLnFIvvqnOAkWb6T400Zf8yQ8Ln5CmSqF1QSPPUT8J1rC6PGgJ2QHzCqjFbbxYk1J5ZCXDIJuYNClzbyvZtWAPpqr0h67F3sra+BNIFpMspv3ddkBc0jGz9rfpJbJ5Tt+nam+jtOOokMR7NtYzs3y9k+bpYSrUEgUXWbZUqaqGCLulJnPqkBbeDcKSatYLXV9cYj9sWm/+M35zmssD6lppjuirLghbMIEuHZsFs6mOKKL1xPdibk/Cx0n9viXhPTkH3z+qzf37dlmBaSJrSxD6g3Np6zcuNAaBVt1Q2zy2blTDObWPY3/+dgGpuwSJLlLYCwqRIi3DlhhU5oA2BDkVCaJ7qbjzA7RXTNx3REXrdhKzbQumZw4MbN9Fx3WjnYiTv67hHHJV+ybCVA5h+4CbK2iVXY10is4Oiej8F7Og9XZ4s1CGlYTFLSc/F/hFnW0y95CnLnWrmM1L0t7/AdDkXe5LRYmOv/cg2915k0zMAxUhlc6d/kKKrlm9UfREBlpFmkWDjdKXjNZWTRACCU3OEF99nInDU3liPnk7aQ1Z6jntMJCfqREGW5AX8GUzre3ueDiUJJgyjAUOyIxT7gYXF9cW3f9FHgeFRpcOwa0RWCbBgp0cpblapvGVtMZPEu5M++5T/42JgID1ATSnzbks0WzDFn46mWLaE3+mF3FuSinyEMp3Ov3htFO24cdgsdSbROozVSTMvw2T4DffsvtpWNqipjfrNw4o6DNt7wgZstISpNDzXubFYIXKSA2wW15XpMRsrXRACL0QiLjpNOSOJQtz3SCTbA1GC9lsC1yB93K8mWip8PUekdSRVqpvwQ6eXeGdh3KWtbBzaHa0FVLRfbgrzgnCF/y9TuZjNCQx+KSnRnkf+Mamuj6CgWDvgJmPjQobyT37MRMGpbZryZ8G6XmiV/MPsOXmBL89f1BA09fFD77OFPFs6pMk1ihK0T872CsDIqKxnJLxDZqW4VGVAZM8nZU12/FIkooo0vCfzse29FnisWPg7cGFqodpCkOa2VyljTh7u/sj5Cyk0OV19mWyp3z8Z649l0ds+S5+1N4CXs869dEbemDRSwy4d6sOOWDDaRl98K9ZiHVEH7iJot2XDScTMXAGqmElYhqnLnBAR2LoW54075Ox4J5FYZRQ1g8rmFuiBDsejCKY92GMRcdPB5gy31xw9SOPRACnkV/YVt9DwhOWinabrxyYUgZ54SDC3saUwQgjbKX8f4y2eA6v7X2y6JDh3Q8ANsX+SFr46s3aA/7S9+jNmWqFQCAgCn9Mg/J/ctqFGkHmUFa+8jemD/Bu9AX/Z1nmkryvzEGlMMj23XniilK6RbWoTUFrKYD91Bvfhn0ww5z8UeN8dRSIS7cRTngKf+m9X1KrnBm9aCtR519/j4JKuBviAqu10Y89DYnWWJxlmGRKq/75oUYNvEgmVxy3Uur9cfSc8xtvByF0WECRYC+Q7GocMNFeDmboDHpYmw/EWQGkc4dQUOJCuqpeh+RMR/TEyeHzHw180IggYcYHWyXLXRzZKTqfP1X9FK0ZS6+/WEU42TBrzNe92aRnJCXu8EDVygGst0v4yUFJArCim4zYQpuVbU/GfxvqGpelJcdcGg8/++g4mg3bvPIJl3uhRiBRTHFRlSImhcx1AFneuWV0AAEfZSVQenqmQKcXn5mzhThpEDYUgt0rrAEQLoRD0rsP4yjdNfVynOfn8j5DJTGwZ1MsScD2AJfdJ9TNW7mLqw77l4Xi5VP+wt43/5F8OXmkZfNJmOK1R1iJtUkTDwlTZNIzv+tlB2pbQdlkzt2+JbztLZ85i8jN+/MO4NYDYinAt/znEJSpshVMI1bTaec1ooFdDzDmmsdzOaq+FDd+9Vt68CpfeJAai2HtQv+LaYuvFR8tjNQ45nrsGhZKy+uDOi5wIHpJeAYeMU1f1gjs+/pNeCwYvVWeqlvnPxJgsAMnT6+kJQrkehjivDdEj3yxBAJ2yrFYe6h3esblmVJnT0daIxS+EsJWhFhVbeEV4uDlz3n+Rlbmd2AGlOnY2xXM2tBoppwrGTsIYIpbI1kUtnnb3McU73BYmWg+31/sqrmu1jLpP08BkcW7jGpF2IJ9UBSx2fVu5GHT26vhzbncPdNFp/pS+zvusV1xHEW1eunyFZoXVASLPozE2Brh5W2tTtz1i9I63eTCQDbeWqZ8yBgSHImcaYgVwr+ED4kYq6bLY7O+o9qNz4Y5U7YkHOIWHhhPTueCi3hV3C1nt+u7TDFNQz9rYebd7u4JQTW6mXXJlWWTuTpSTLWJJO8nIYFDgUdEpCb239rYr8ohKMeG+lOw2SQjgL5Yq3Tl83n6NTuD01rX8Me5fXQqoRRlpKn5Art14HSGq9K3vw58abvP5C5HxhHTQqrMlvZ3ZrfEsMx7i/4ujcxs7VN4y123Thcq3Lg9JcBXJQjaSlkSC98nCZJQN1u+2dmAOcaWL6Kd24zn5bgxU6gBigFavEEzBO1OIIDsGgXxzlvG8UxIYhqbsEo1zQFLNhGSo2FWvdKxP/1YazrBdFU+viKUbv7b0dOIP8U1sxDiS+g0S7ueZMNzMwzYiV054ymHkCKQNTEZiwm/J0YVXitkeyn25CcFoyqs+ba3tRxp3+DzO9aZxa1aOOrZLeZ5MxbIPGL1LxxkQAf0HtYBlcAA7KOUYpy5DdflrRcwImahMn4jf6spmCXx/5YEZX+SjNEosZwlmgvJAU/A2K74/oRAY+aGUYj1R9DUKqZRV57T6nE44HYPki+iCsarMjaLdr36AGF4MQK5sO2rzuKaCGDS3pmERM5rvcifXqFnXE9th7+qOVZxRWcRhQiUxI/4WHVvkfp2GpefDHvxX2TmSc2cvjGymMOjpXZpr2KJI+NKFp6kPP7QfSU9PS/HBcTW5jijNam/u1AHyqzTkbmH3nX5VXmrRSb5Zg5fO4JWC+OcVGIb0PwondSz1VpourKHdAygLppajoQBbePVbfR9llJoodLo8BaG/D+moMa6psbVyMnQfxJ2gPl+1qG+lwRsLVAIaqSLJUbqWIWDUPsLreamQRpgM8iXfvqSxJAFZ67JQq3FJXNPFAkMxkrzP4dkAKIljGLHF1BolQ9L8fOdcTZOwOebjcsEZ9PE9fvLOqngwUWGi6ckhBKINccYXtr5bKlp+nS2XsBjtLWGsYIThI0MULRnpD376yqkDA5wjNrOYEPACoK7QkC08DLjJI7rr1io3SCEZ50o3dBlohhocLrreiJnc1AKFi6dDxoyqmELFFGrQLDax3U/oxCUi8un2R8YVDBwpGeT3ltlZlfIbLGF3C7QKKIHlDF+5j7TfXHXmBYrQPZP+Bz1OWkLmmslaM3x8be2dEVfk1BhlFbrJD4KO9Y/nlt4pZ5Oa81N10cbc6EdJffVB+PIudPCnyk2VG58alRTlsdhjq5l4xPbEn4HMaTQRKlCb4MQJDIn5gOdLcQA5vxTJ7y4r4mI9fHVEuEsomsOVzMgv8K6ayH9AnjkS51fQpoWUrGX15syFYCrL+tUgLotKC1qhjX+yeWTn0tEjCinFA0LU/ByyHt72iMLILoaaG34kw76h+eWB+Ivo04V3S19Sp/DLsJ+S8CLbzBpbUi0AZUA3tXEc3enmTSrtwdVb+wEztbtgCAmGJTkd/Yj4/cZJKo2XFOb4UGFizGdmQhZ7KeWh8XCo2vPAu5AXK/trd5UhYdlb8l86Y4R6rPUttaLJTd0J4CGnAqP12yGK/XOQcKygOgveQe7Lne+pGa90gfKHbF/JlV1oHaQSrYg3eFF2+vRy27q749blqgXDW2M4B2FXWr8Ysb1PCcX6LqMutQXu5sp6Y1icOCiiUAtZj2FINz5EGxfcaVGLmZ2h2YR8CLp9f2qqTB7Ung6sba0/RaSQFWqAoamxSs30BsyWyqnrsrBCXtB/z21HaNlUwjyKyAzPcqBLTlx9bUYdjQBwcS84d7wAWk0gLRlA3rv4kB/MA0QLQ/71RoOaT570yRsNFAn5SSs1/YF07/V3oP9PJmUOiYgMRKqK9ETvSAIH+TEJOOOKG2LOJy+/zhlSqiNO3f2iUVUfjMjbaXrqE6h1Eqh1a3TI7zOIi69EKgtj3xgvW8Xa1n/k7Yw+F6DEBPCqo2XCF5+IqdTMghH0s80yFjAfw/WVM9MEQloPCyYMh6meFXvc8o1XTx5u8J3ZO7rNAmdzz4Ibwd3hThUO5xVDST3gTB6esuOEZkOlOwb+nyFEY92IosJh3/FBHEKvUd8wAyjAqhq3ImgMHdb1ZQaK3gu038rvN54AtCa3yyEBeCGHKHdaIVF7gAr0LeK7OFM/3mhE0m4avWph7rx8k8WLArUybxvpXipetUaoTtoe8mZ8fsdKUKahP2XS9Iu+uv1Ywjms9tgKiY6e8lynEPNRHQ7ogMvJ3CHv38RhpR3kHw56MlzuDsxxhxdr3nTjc18tBsahhy5Kbqa5KVwb/QxinWSiQE9uE2ZD/SzCmfuShdRv+c2ULq/A/Xw6tbKZu2074pkOmZ4xCNR7y6oyesRSpV0MzPyxspL2BPGwo/Tey4CSOQyCAX8mFft1GWJ9hCtkF65/p6HfbYBYL/oaM1WGi6vVPGFq9KRUtMoI6wBC2NX5Zecw+jRRweB8tJfLczMsvtGaEXnCPZthzSomCFNuhkXvIgqN4LOMg9hw1+Q69rv/bUXzgcCS45UV38jMr6fkn8QTb4cqsNV072vv4Pclw4wZtAy0DPee+W478IDgnRsEjaf8V3cPeQfK04grV3sx83zxiTNKUIrW2BYSqwlbaCLJ5ye+To5rltu1U/2wqSDTx/FperD6Q71MwCPAb+kOiuzqiaz+7vcG3nn/ixVabukoxu+jDrvYjY6sZAMr8Fvi5xdTYSj81htNTykevheDgfGITbJe0LalxmpOj0pWIL01ljZTFEgnlRRuzQDYVlbXM7wzvh4nSgYRRfeCaOX7FiN/C6bP3EX1VbsG5yBjwPoOPWcX5S5LnKuyfXrppUVJXDn9jFLJOPXAhTj4/6UPgklahpdn2lkVd8CUlJvpIoJRA+n5vR0DLC+Z4LnWloVuT4YjmNZYlO83QkyDQotJ60kJTrD3bULjZkB9NOaWYVejEGBV0XAmds3LoQRCppTHXIohH2OMNleeQIYuSe0advcgr13vwb2Ty2yUoNooRGHZrxySsuWDHVy2OTw0GUcaxWKHAmdmrW8wPj8mfV3QalGXJEBNM2ByITOgKV0bY891NgvfKceboew05jNM4LCwKUOqkE0rfONa3WI34RC86DwXU+slFgLpzSLhoOQuirXq1AVayapIuQ+O1K20mrYPBThLqrB8ZLBgcM+nJ12l2uKW3wd4YN9/uVCASi+NBFPRGn5n+++cWMZDqtvRUwyU5zUC/jveQCNst8/s4LURbHfDEpDiHqaL5UdsS0iEBATNwy6I9aKynxdqRr+zcI9GqUVGWDWRmA3uLxSpzDpvPkofXmEkYV50aaLCNq1kDywVoef0HYy4UaU5qyoDRjxC3+8/QNZO2XDhTRShXCMM4Ps2RlcHkG7B5klnffanAamt1Pi+RbEEnlrfGn6DcVfHMDab8IhLghMAxaghyRxNqoQARE8vMG6i6zgwtoApL37uy6oaWTOqpH7EG/FP47jwGhNmqh8fPhwTlIvsLafhrO5wb2Jp1Iw8r4IY3N3zGgHdu2DJog7Z+HtxOxGre9sRdCIv0RVHXojj5DsPx44Ub1R5veIcHT+V4t1Ehu3BA+zUw1ZyraXfnZ2EinDOR81sGOP8Lohg28QFWKeqBu51iDuS5Ns7bDYNUN2mc/hGBpERDmRCzsfeYlqofdCmzXJha8QFF0DtxXbJMoOQU07dEo40Va0UARm3irUOqngwmisU5t5EWM0q2YNdCK5jLM1qDNImo6WHqGeQ+9J/oL4cPxX52c7SZCY2kPDS7onS29S3lyukfnJw4DQEnBvSLbIni7ULrhCpLEZnusIzR3VimUaVNdBRbAuXxdTGf2ZNT51NJEcbZY/eXiAu076hdtkCoOgFUnxEGGtD+IH8RNRShzJXPjl+2fEzBetUVaxzR55jCNFwXrvxPwAvn8APpvvlywxXT4CBt0UtR/HHEMZ44cOVKs9AdJzZqUmNqF96twTTiirPvzOrGjMPJVN11dvhjdk0Q5TsoA/t5Vu+M/o6cfkmoNC03o/NWKiXQT755obuC1dceT8VJL4DEkiSWcHsf3rQuo/8Esw8yRoKdz0FlVmxh5Hs8cmzLsvBMa9MIlAtp9S6ofY0WZD1XQ3+HJjoBwt7v97W5+bfTrlZNOWVKtFbUwRufi09PTf6tKEJYEEUv+mkW5gKS+PHvCbaXV+OqT1coK983DiBw65X5pgxbMIEWbxk3ke+TKHpP7WLUxtPpmsCc3phPMIrDV/iZ3EAPDsxpOgxILYH1LuOWyd2Msbq2XASAVjmR6b/dUKyyeKBDNtZ9ueLORxrDZ8fBcdcj97B5uweQJQVtQtdXbea3BI+zxbYUFTs7qTxNxHXCgIUwAlKucYmtGjf9r+g3K1BxAv4mjRx7n5HXaXH78UT0qf2bzL1ms7ZFb0TioBPWdaqi/ab8LJzxPFRZmOHuVLEy7OvVkjJzyT4eS7NQQHbxDMUr6tsSHZCJJ1p3kw4Yl7iCM22NbfxgeD0yf8RQUvUNnYY5tNzd095axmJDZSXrng5CtKmOTmw5CZRPU+Bj43qtrSCpz+yXuOfgXtUGiGO+P21il3tkqZvI+nH89TI53ItDT5DrbzCFNPnAuE/jWiIhzHc1wMG6FNXg05ZyQjISnc6WDZHKY77FVU+S9oeR8oI1+YZWQBXYqt7WPwX9P/8R5jdMv/7Oqty31FwLrsEWZwHPBRFMZZ19YsOFfFwISNdJloCXmJI9mqPRSLVL+Ifxadwcc+FrnVu8pLtI/pY1uvFxhPfMaVsyM9WD14OcrKzm/GO65oz8MB1ZQJnIl68+xKKLASamloMYV9bP906sjBKSgztxvn+UyhJ8cN7x6tCGnFmrmtmlMyKvizXTHJ/1/A6MDkp5/ttyf2tIGS5tc5nPwZstZeTBbQfoXSz8emVBKlLBU8rO9srr8CL7dvB4SRY/24oVf+hFP3tMY7vqChnaxchixQxlYnlEUjhBq640ceK9ZW9r68TaVLNa9zSP+iSBjaDcrgcKSgYTJmRST2Tb3S/QJY1zKlxdfVK0C1b7iInGmSIqqPdkPIB5k20Y6wUUnXK3euRAhIppvVI66z33w7bAqbRYzcJ3ZUOJ9SnWUY29Fl9f4mWQqnRiBPxoVlNsBnaU+9ZQPn12f2gTYCF2qnVmdDVQmdfGBYf1ZfhY92HIvzxWl+Aa7TOYR4a+cF+iHP67ZcvJoujJKmbf9lSJPJNLswogyjYg/2VJIKNfWHHN5Xtx6Tpl0jdJC7EpN6JKTSRzpQsWNabh/bYT9QelkVfyTNFllvRMXXG5TMVYvlDW4KG1kG8XWyEOhCGEgBAT0uy0CYNGXZL1ZUt3xNLumSez5Em8bAsmQSgIDT2t1H5gOqT4Q5IBmfHK4L7Sd8fHmCvYSYXy3SHoPiVkq1g0RLlBUhJ2k9L+emzO5b25Mp+4letI7744EaJf2U53dpQftNwn/X6n8/l5CRscducbY31FkXcDIm0Jbl/LXSmXa2dJXKwmp52NzUVzhnndqXmuexsOVTI74wegyK6i76mVp0HC1M4pXJOPX5GNMHYPXTtAbSJM8rtsmgO8tEH619tg3sFjRdz8zBv9yURTWpnftcnCe4cpCllGcnckLbHAcT9uElvsu0kEyF1iR86SwIZ0s3i61PFoA6B4cyUi/r2vFctriDUWMmkZ3XDH3EcmFGWoCr9+R/vsfBdN80tgRx997uxt022pXWKQ8LNF2ud1L9+C4M9P2PabJPUuil4+RHKv0SJ4nwOwBSYRRsRagx3uBr39W9sekMxiEL4E37VnfAytwBrEl4hgpD5ZzgEN6Ag6qOi7Kj1Uz5pGAFIc+XKrpOcTNxPXHUjVcTSX44mWZJVnPzzw/mIR0CKs+Fn/BWUyYqOwpQDCtj0G13slo9axptX1u2gf1gAPe/hf+b8tDyCMyniyCT5mrKfxKStgi6J8PpykzpZCFGCuYY+PRvEyPszGGylRJKBYX8+NxrajUNaGH2HREpIxIbVFNy6MjL5/L12qI6UKhoXhHg/606sHJ5pTSDop1y9WdNxrhG61nSccgYlqHQd+ZfFceEZlha1/Su2z0of6FEWLTeq7imy/bqyC3xPURsiFpg3UmC/glNkioKy8qa9QyRZaedAOkwdMMtAtFdjILSGm+4pGjt2S2LDLatGfAEV8RtP5YAChnzcijrXFbb1kP+EcOgwtDCUa1s2tW+3kZR6DP4wHOwNclO9q2WzRC/0pZX8Ec5xvtcPFfcCHBfDZ+mvONsXdvqcaemNgpY7x7okPoPKIdULKhL0zDHWnqVkVXYoSYlec07N7dhF6cuDrERwIGLBl52YjEzFeQKVODwIgUEh2KCgn+WKtq4jfuzAVxehvA01rOWQoa7TsYiEc+9dC/AAy3sX9lvAQ6fGlRmLz4zOKUlanzH88Jqc8GxRIWCJ/wiVXxLeQZOiJQ5/4HLkRG1b7K8CcCPEUfTbybU0z/TEi2dQZFynNzxMLIH0LrJ5W8oKE7rapGRUvlXKBvGF930Nm5TJ8YqeoZkFTi9nbqPNbXXJ/kj0VMTAxYW7J95BN9aooEwC0KtcO2Q30cx+Lni/wvicou7cDxQG6JkgLXdgfyM8TUOlEpG6wWVT0Tnxm1qqjrSThy2w0RlnWjR8fp33yeEpxEZKVZIv/Pde0IswVQYw5yE0TSQypprh/JJKH+2xXtAr2MQPUTW3Vw0WLiZmP99lmCgpZpCK0RhXSKeCkAMbQ1wGgZBGQkR6mlx5bl6ZKwKLzdOYP82QSwUdYg7rIQVJSu0igR3YZJLUMjRxtpIM39R739WdDYiT6xTYiU3mMuX062bXhnf2qtIkVPwW4Ra0JA26vnPQmZWBVAtc69u9dZME5R4tw9vBa7cOjmlPd9Np4rFP4WmYETBC5tjGcqoK+8r9oVW43dr6i/j6BcnVTsWXOfFASYNok23w8SjIpNLIloDy4607BzJbqpUIWRXS/Mtuvg1VhDozCWm04GFo5uh/f/3cbWvRQgphEriaAf7fiB4wjDGkIfZqG21+V3eFhSsFa1iMCxc0jd3Lk+/VmB9HTDgFQbf6ADq5APQL2agdkHMgU4E2tghMOpQF/JWIwconhKsxzQw6DQ4NYRB6Z+ZxkrZdRxddy9Ze2HJYpOaBQxQ4rmUquAjM2ks8AdduMR/IFqUo8YDYi1RTClpGDb/PvJ89l0RhVPdPkOS68VUvhT6NqbTOVOASYdKnVGobkPBmCdw6qSrTwKh3qGFl5fAxMU5wLPr6Sq8NkbEGua9KRdwajsPr3JRgqK8biqfXTQ/65kEF9XV6IoJcWM3Mhw10/6p+u4Z67H5VDFZuzQwhqg2HJEa15Vm3M2HHny1lFkdpI+CLgnKuxV4S1aSI2p8GYBC0Xjl/sSPa//tXODtxl3QxQjQ4MgAADdErgH7unFB79Eo3bz1Z85ne4/Mqv/LFQ3BkjpBaFeyiRzgoBQWT77H7TBKe9fXPeKnVtnQQCQ6ohvVu1djZUp9FNIq63XnqytSLb9rx0epvBjt6QV5Puvtcc0KSxHLZ15Pm5EKrD1XGzrpVC4Xa5Qkr/nm2na3b3BJHJTj9n23HpmcgjUcJOObbGflC0Ro5QChhzkhJxwJ72ftIkGWVan9nepSizmfe36PwHhWy1H8pinvj46N04ow/6HCSruuWO14mFQ9VXfbmPrbUycurkEi0JPiLyhkRX6ZUrYflFUgLGYgkvyoFQwJ5QnhfsFecsoqemcQV64ml9rROvOQZmXv7wlkB5XNAdt+/4y9Gr9qydHN0dguPjGRv2YnJDsuS8bJr4pN85vPVJCnvelSnsqJywZwz6YfTWW7r43sHTSvzTOlohgUmHwXztGk4cwPmflPMfls1jQ/0Uv5TDv7iZQicdKty+QIqYcCOmsqEu3pazCHDa8DuQD4SB4l1+bxZnO2aKffLFQXG/1f53ZimRgHxXxa5TakpzHJUS3EL8zl4doLSqceZi+4ie5+5m96IFC+R1ejv4GXRZZfd//mW1+mXAgs2v0BcJM9+kE3IrosGdhF22yfGRnTtGoTN1aDzhCjzNA0OrUi9sN/SXkc1dMsmWAKtV3JTkfvXfAm+MxIZyGwJ+dJf7BajDyHlZyeGxPYKoQSpMUZhroeD1OHuoBRJSwyjH3DDFVS9Iedk71hF5+fjLcsjFVis0/0qPFVVAGnEUgo5GJgpYiuqfy5zGEVNsMHlUmBzOx1N/i/6u4JOp0c3HyBDelEkaSAGn5vI91D/6hIDWSEEAAAAmRec+irMQuiaO7DXt6//0mTl5kYE72m4w4+Qk/94/+C/LWF7gp7PS1zxEKGwZoA63u98nuygCF8PAkAkpLvURKRddY0Z/BSYYYRgcYLyDXHJ5/Fj2tm/D3UX6R6S3Gf4wiQPwAC1axRCmsMu+4i6MYNZuZNmOArKfWDPMN2ADgS22FvYJfUXYixTvnyQGTGpqFXXjOvw1TIWhtNPWIgFaarfDK184bACoIftGw+lobPfreEKAU51exOL83W8c9L+F/EIxYQvT6jBPd0U4GI0jlRX/9u/lVPIAAAAAAAA"};
function buyCurrencyCode(acc){var codes={USD:1,GBP:2,EUR:3,CHF:4,RUB:5,PLN:6,BRL:7,JPY:8,NOK:9,IDR:10,MYR:11,PHP:12,SGD:13,THB:14,VND:15,KRW:16,TRY:17,UAH:18,MXN:19,CAD:20,AUD:21,NZD:22,CNY:23,INR:24,CLP:25,PEN:26,COP:27,ZAR:28,HKD:29,TWD:30,SAR:31,AED:32,ARS:34,ILS:35,KZT:37},code=String(acc&&(acc.currency||acc.original_currency)||'').toUpperCase();if(codes[code])return code;var balance=String(acc&&acc.balance||'').toUpperCase(),match=balance.match(/\b(USD|GBP|EUR|CHF|RUB|PLN|BRL|JPY|NOK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|CLP|PEN|COP|ZAR|HKD|TWD|SAR|AED|ARS|ILS|KZT)\b/);return match?match[1]:'USD'}
function buyCurrencyId(acc){var codes={USD:1,GBP:2,EUR:3,CHF:4,RUB:5,PLN:6,BRL:7,JPY:8,NOK:9,IDR:10,MYR:11,PHP:12,SGD:13,THB:14,VND:15,KRW:16,TRY:17,UAH:18,MXN:19,CAD:20,AUD:21,NZD:22,CNY:23,INR:24,CLP:25,PEN:26,COP:27,ZAR:28,HKD:29,TWD:30,SAR:31,AED:32,ARS:34,ILS:35,KZT:37};return codes[buyCurrencyCode(acc)]||1}
function updateBuyTf2Total(){var priceText=document.getElementById('buyTf2Price').value.trim().replace(/\s+/g,'').replace(',','.'),price=Number(priceText),quantity=parseInt(document.getElementById('buyTf2Quantity').value,10),total=Number.isFinite(price)&&price>0&&Number.isFinite(quantity)&&quantity>0?price*quantity:0;document.getElementById('buyTf2Total').textContent='Покупка на: '+total.toFixed(2)+' '+buyCurrencyCode(selectedAccount())}
function marketFeeConfig(appid,fee){
 var rates={730:0.10,440:0.10,570:0.10,252490:0.10,753:0.10},fallback=rates[Number(appid)]===undefined?0.10:rates[Number(appid)];fee=fee||{};
 return {minimum:Math.max(1,parseInt(fee.minimum||1,10)),base:Math.max(0,parseInt(fee.base||0,10)),publisherMinimum:Math.max(1,parseInt(fee.publisher_minimum||1,10)),steamRate:Number(fee.steam_rate===undefined?0.05:fee.steam_rate),publisherRate:Number(fee.publisher_rate===undefined?fallback:fee.publisher_rate)}
}
function marketBuyerPaysCents(sellerCents,appid,fee){fee=marketFeeConfig(appid,fee);var steamFee=Math.floor(Math.max(sellerCents*fee.steamRate,fee.minimum)+fee.base),publisherFee=fee.publisherRate>0?Math.floor(Math.max(sellerCents*fee.publisherRate,fee.publisherMinimum)):0;return Math.round(sellerCents)+steamFee+publisherFee}
function marketSellerReceivesCents(buyerTargetCents,appid,fee){
 fee=marketFeeConfig(appid,fee);var target=Math.round(Number(buyerTargetCents));if(!Number.isFinite(target)||target<marketBuyerPaysCents(1,appid,fee))return 0;
 var low=1,high=target,best=0;while(low<=high){var middle=Math.floor((low+high)/2);if(marketBuyerPaysCents(middle,appid,fee)<=target){best=middle;low=middle+1}else{high=middle-1}}
 return best>0&&marketBuyerPaysCents(best,appid,fee)===target?best:0
}
function updateSellItemNet(){
 var field=document.getElementById('sellItemNet'),target=sellItemTarget;if(!field)return;if(!target){field.textContent='Вы получите после комиссий: —';return}
 var value=Number(document.getElementById('sellItemPrice').value.trim().replace(',','.')),fee=sellItemOrderData&&sellItemOrderData.fee,sellerCents=marketSellerReceivesCents(Math.round(value*100),target.appid,fee),acc=accounts.find(function(a){return a.login===target.login})||currentInventoryAccount;
 field.innerHTML=sellerCents>0?'Вы получите после комиссий: <b>'+esc(orderMoney(sellerCents,buyCurrencyId(acc)))+'</b>':'Вы получите после комиссий: —'
}
function orderMoney(cents,currency){if(cents===null||cents===undefined||cents==='')return '—';var n=Number(cents)/100,symbols={1:'$',2:'£',3:'€',5:'₽',18:'₴',37:'₸'};return (symbols[currency]||'')+n.toFixed(2)+(symbols[currency]?'':' c'+currency)}
function fetchBuyTf2Product(name,previewOnly,force){
 var acc=selectedAccount(),currency=buyCurrencyId(acc),country=acc&&acc.country||'US',key=name+':'+currency+':'+country;
 if(!force&&buyTf2Cache[key]&&Date.now()-(buyTf2Cache[key]._fetchedAt||0)<600000)return Promise.resolve(buyTf2Cache[key]);if(!force&&buyTf2Pending[key])return buyTf2Pending[key];
 buyTf2Pending[key]=fetch('/api/market/listing?appid=440&currency='+currency+'&country='+encodeURIComponent(country)+'&login='+encodeURIComponent(acc?acc.login:'')+'&name='+encodeURIComponent(name)+(previewOnly?'&cached=1':'')+(force?'&force=1':'')+'&ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Ордера недоступны');d._fetchedAt=Date.now();buyTf2Cache[key]=d;return d})}).finally(function(){delete buyTf2Pending[key]});return buyTf2Pending[key];
}
function renderBuyTF2(force){
 marketLotsMode=false;updateInventoryViewControls();var inv=document.getElementById('inventory');inv.style.display='block';document.querySelectorAll('.game').forEach(function(t){t.classList.toggle('active',t.dataset.game==='Buy TF2')});
 var products=['Mann Co. Supply Crate Key','Tour of Duty Ticket'];document.getElementById('itemCount').textContent='Buy TF2 • выберите предмет';
 inv.innerHTML='<div class="buy-tf2"><div class="buy-product-grid">'+products.map(function(name){var short=name==='Mann Co. Supply Crate Key'?'Mann Co. Supply Crate Key':'Tour of Duty Ticket';return '<div class="buy-product-card" data-product="'+esc(name)+'"><div class="buy-product-image" data-image="'+esc(name)+'"><img src="'+buyTf2LocalImages[name]+'" alt=""></div><div class="buy-product-name">'+esc(short)+'</div><div class="buy-product-price" data-price="'+esc(name)+'">Нажмите, чтобы загрузить цены</div><button class="market-primary-btn buy-product-open">Купить / ордера</button></div>'}).join('')+'</div><div class="buy-active-orders buy-active-main"><h3>Мои активные ордера</h3><div id="tf2ActiveOrdersMain"><div class="buy-active-empty">Загрузка активных ордеров…</div></div></div></div>';
 inv.querySelectorAll('.buy-product-card').forEach(function(card){card.querySelector('.buy-product-open').onclick=function(){openBuyTf2Dialog(card.dataset.product)}});
 products.forEach(function(name){fetchBuyTf2Product(name,!force,!!force).then(function(d){if(currentGame!=='Buy TF2')return;var img=inv.querySelector('[data-image="'+CSS.escape(name)+'"]'),price=inv.querySelector('[data-price="'+CSS.escape(name)+'"]');if(img&&d.icon)img.innerHTML='<img src="'+esc(d.icon)+'" alt="">';if(price)price.textContent='Продажа '+orderMoney(d.lowest_sell_order,d.currency)+' • Скупка '+orderMoney(d.highest_buy_order,d.currency)}).catch(function(){})});
 loadBuyTf2ActiveOrders(!!force);
}
function openBuyTf2Dialog(name){buyTf2Name=name;var acc=selectedAccount();document.getElementById('buyTf2Balance').textContent='Мой баланс: '+String(acc&&acc.balance||'—');document.getElementById('buyTf2PriceLabel').textContent='Моя цена за 1 предмет ('+buyCurrencyCode(acc)+')';document.getElementById('buyTf2ModalTitle').textContent=name;var localIcon=document.getElementById('buyTf2ModalIcon');localIcon.src=buyTf2LocalImages[name]||'';localIcon.style.display='block';document.getElementById('buyTf2Price').value='';document.getElementById('buyTf2Quantity').value='1';updateBuyTf2Total();document.getElementById('buyTf2Modal').classList.add('show');loadBuyTf2Orders()}
function closeBuyTf2(){document.getElementById('buyTf2Modal').classList.remove('show')}
var buyTf2ActiveToken=0,buyTf2ActiveCache=null,buyTf2ActivePendingLogin='';
function bindBuyTf2CancelButtons(box){box.querySelectorAll('[data-cancel-order]').forEach(function(button){button.onclick=function(){cancelBuyTf2Order(button.dataset.cancelOrder,button)}})}
function buyTf2ActiveRow(o,currency){
 var quantity=Number(o.quantity||0),details=orderMoney(o.unit_cents,currency)+' • '+(quantity?quantity+' шт.':'Количество —')+(o.total_cents!==null&&o.total_cents!==undefined?' • Всего '+orderMoney(o.total_cents,currency):'');
 return '<div class="buy-active-row"><div class="buy-active-info"><div class="buy-active-item"><b>'+esc(o.name)+'</b><span>'+details+'</span></div></div><button type="button" class="buy-active-cancel" data-cancel-order="'+esc(o.buy_orderid)+'">Отменить</button></div>'
}
function renderBuyTf2ActiveOrders(d){
 var main=document.getElementById('tf2ActiveOrdersMain'),orders=d.orders||[];if(!main||currentGame!=='Buy TF2')return;
 main.innerHTML=orders.length?orders.map(function(o){return buyTf2ActiveRow(o,d.currency)}).join(''):'<div class="buy-active-empty">Активных ордеров нет</div>';bindBuyTf2CancelButtons(main)
}
function loadBuyTf2ActiveOrders(force){
 var acc=selectedAccount(),main=document.getElementById('tf2ActiveOrdersMain'),token;if(!main)return;
 if(!acc){main.innerHTML='<div class="buy-active-empty">Выберите аккаунт</div>';return}
 if(!force&&buyTf2ActiveCache&&buyTf2ActiveCache.login===acc.login&&Date.now()-buyTf2ActiveCache.time<30000){renderBuyTf2ActiveOrders(buyTf2ActiveCache.data);return}
 if(!force&&buyTf2ActivePendingLogin===acc.login)return;
 token=++buyTf2ActiveToken;main.innerHTML='<div class="buy-active-empty">Загрузка активных ордеров…</div>';buyTf2ActivePendingLogin=acc.login;
 fetch('/api/market/buy-orders/'+encodeURIComponent(acc.login)+'?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Не удалось загрузить активные ордера');return d})}).then(function(d){
  if(token!==buyTf2ActiveToken||!selectedAccount()||selectedAccount().login!==acc.login)return;buyTf2ActiveCache={login:acc.login,time:Date.now(),data:d};renderBuyTf2ActiveOrders(d)
 }).catch(function(e){
  if(token!==buyTf2ActiveToken||!selectedAccount()||selectedAccount().login!==acc.login)return;
  var currentMain=document.getElementById('tf2ActiveOrdersMain');if(currentMain)currentMain.innerHTML='<div class="buy-active-empty">'+esc(e.message||'Ошибка загрузки ордеров')+'</div>'
 }).finally(function(){if(token===buyTf2ActiveToken&&buyTf2ActivePendingLogin===acc.login)buyTf2ActivePendingLogin=''});
}
function cancelBuyTf2Order(orderId,button){
 var acc=selectedAccount();if(!acc||!/^\d+$/.test(String(orderId)))return;
 if(!confirm('Отменить этот ордер? Зарезервированные средства вернутся на кошелёк Steam.'))return;
 button.disabled=true;button.textContent='Отмена…';
 fetch('/api/market/buy-orders/'+encodeURIComponent(acc.login)+'/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({buy_orderid:String(orderId)})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Steam не отменил ордер');return d})}).then(function(d){toast(d.message);loadBuyTf2ActiveOrders(true)}).catch(function(e){toast(e.message||'Ошибка отмены ордера');button.disabled=false;button.textContent='Отменить'});
}
function loadBuyTf2Orders(){
 var acc=selectedAccount(),status=document.getElementById('buyTf2Status');document.getElementById('buyTf2Balance').textContent='Мой баланс: '+String(acc&&acc.balance||'—');document.getElementById('tf2BuyOrders').textContent='Загрузка…';document.getElementById('tf2SellOrders').textContent='Загрузка…';if(status)status.textContent='Загрузка ордеров Steam…';
 fetchBuyTf2Product(buyTf2Name).then(function(d){
  function rows(list,kind){var copy=(list||[]).slice();copy.sort(function(a,b){return kind==='buy'?Number(b[0])-Number(a[0]):Number(a[0])-Number(b[0])});copy=copy.slice(0,8);return copy.length?copy.map(function(x){return '<div class="buy-order-row '+kind+'"><b>'+orderMoney(x[0],d.currency)+'</b><span>'+Number(x[1])+' шт.</span></div>'}).join(''):'<div class="buy-order-row">Нет ордеров</div>'}
  document.getElementById('tf2BuyOrders').innerHTML=rows(d.buy_orders,'buy');document.getElementById('tf2SellOrders').innerHTML=rows(d.sell_orders,'sell');
  var icon=document.getElementById('buyTf2ModalIcon');if(d.icon){icon.src=d.icon;icon.style.display='block'}
  if(status){var currencyCode=buyCurrencyCode(acc);status.textContent=(d.stale?'Сохранённые ордера • ':'')+'Продажа: '+orderMoney(d.lowest_sell_order,d.currency)+' '+currencyCode+' • Скупка: '+orderMoney(d.highest_buy_order,d.currency)+' '+currencyCode+' • '+(acc?acc.login:'выберите аккаунт');}
 }).catch(function(e){if(status)status.textContent='Список ордеров не обновлён: '+(e.message||'ошибка Steam')+'. Это не результат создания ордера.';toast(e.message||'Не удалось загрузить ордера')});
}
var buyTf2Refreshing=false;
async function refreshBuyTf2Prices(){
 if(buyTf2Refreshing)return;var button=document.getElementById('buyTf2Refresh'),status=document.getElementById('buyTf2Status');buyTf2Refreshing=true;button.disabled=true;button.classList.add('loading');if(status)status.textContent='Получаем новые цены ключа и билета…';
 try{
  var products=['Mann Co. Supply Crate Key','Tour of Duty Ticket'];await Promise.all(products.map(function(name){return fetchBuyTf2Product(name,false,true)}));
  if(currentGame==='Buy TF2')renderBuyTF2(false);loadBuyTf2Orders(false);toast('Цены ключа и билета обновлены')
 }catch(e){if(status)status.textContent='Не удалось обновить цены: '+(e.message||'ошибка Steam');toast(e.message||'Не удалось обновить цены TF2')}finally{buyTf2Refreshing=false;button.disabled=false;button.classList.remove('loading')}
}
function submitBuyTf2Order(){
 var acc=selectedAccount();if(!acc){toast('Сначала выберите аккаунт');return}var price=document.getElementById('buyTf2Price').value.trim(),quantity=parseInt(document.getElementById('buyTf2Quantity').value,10)||1,status=document.getElementById('buyTf2Status');if(!price){toast('Укажите цену ордера');return}
 var priceNumber=Number(price.replace(/\s/g,'').replace(',','.')),totalPrice=priceNumber*quantity,availableBalance=balanceNumber(acc);
 if(isFinite(priceNumber)&&availableBalance>=0&&totalPrice>availableBalance+0.000001){var message='Недостаточно средств: нужно '+totalPrice.toFixed(2)+' '+buyCurrencyCode(acc)+', доступно '+availableBalance.toFixed(2)+' '+buyCurrencyCode(acc)+'. Ордер не отправлен';if(status)status.textContent='✕ '+message;toast(message);return}
 var button=document.getElementById('buyTf2Submit');button.disabled=true;button.textContent='Создание ордера…';if(status)status.textContent='Отправляем ордер в Steam • '+buyCurrencyCode(acc)+' • '+acc.login;
 var waitingTimer=setTimeout(function(){if(status)status.textContent='Steam обрабатывает ордер. Если требуется Mobile Guard, подтверждение выполняется автоматически…'},3500);
 fetch('/api/market/buy/'+encodeURIComponent(acc.login),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:buyTf2Name,price:price,quantity:quantity})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Ордер не создан');return d})}).then(function(d){
  // Do not refresh the order book here: that is two unrelated Market GETs and
  // its 429 must never overwrite the successful result of order creation.
  if(status)status.textContent=d.message;toast(d.message);if(d.needs_confirmation)setTimeout(function(){openConfirmModal(acc.login)},700);setTimeout(function(){loadBuyTf2ActiveOrders(true)},700);
 }).catch(function(e){if(status)status.textContent='✕ Ошибка создания: '+(e.message||'Ордер не создан');toast(e.message||'Ошибка создания ордера')}).finally(function(){clearTimeout(waitingTimer);button.disabled=false;button.textContent='Выставить ордер на покупку'});
}
var calendarData={entries:[],history:[],loaded:{}},calendarLoading=false,calendarCancel=false,calendarView='active';
function inventoryScopesForGame(game){
 var names=game&&game!=='all'?[game]:['CS2','TF2','Dota 2','Rust','Steam'];
 return names.filter(function(name){return inventoryGames[name]}).map(function(name){return {game:name,appid:inventoryGames[name],context:String(inventoryContexts[name]||2)}})
}
function calendarFilterEntries(source,history){
 var game=document.getElementById('calendarGame').value,now=Date.now();return (source||[]).filter(function(item){var unlock=Number(item.trade_lock_until||0)*1000;return (history?unlock>0&&unlock<=now:unlock>now)&&(game==='all'||item.game===game)})
}
function calendarVisibleEntries(){return calendarFilterEntries(calendarData.entries,false)}
function calendarHistoryEntries(){return calendarFilterEntries(calendarData.history,true)}
function calendarDate(timestamp){var d=new Date(Number(timestamp)*1000),pad=function(n){return String(n).padStart(2,'0')};return pad(d.getUTCDate())+'.'+pad(d.getUTCMonth()+1)+'.'+d.getUTCFullYear()+' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+' GMT'}
function renderTradeBanCalendar(){
 var active=calendarVisibleEntries(),history=calendarHistoryEntries(),isHistory=calendarView==='history',entries=isHistory?history:active,list=document.getElementById('calendarList'),status=document.getElementById('calendarStatus');
 document.getElementById('calendarActiveTab').classList.toggle('active',!isHistory);document.getElementById('calendarHistoryTab').classList.toggle('active',isHistory);document.getElementById('calendarActiveCount').textContent=active.length;document.getElementById('calendarHistoryCount').textContent=history.length;
 list.innerHTML=entries.length?entries.map(function(item){return '<div class="lock-calendar-row'+(isHistory?' history':'')+'"><div class="lock-calendar-login" title="'+esc(item.login)+'">'+esc(item.login)+'</div><div class="lock-calendar-item">'+(item.icon?'<img loading="lazy" src="'+esc(item.icon)+'" alt="">':'<span>—</span>')+'<div class="lock-calendar-item-text"><div class="lock-calendar-item-name" title="'+esc(item.name)+'">'+esc(item.name)+(Number(item.amount||1)>1?' ×'+Number(item.amount):'')+'</div><div class="lock-calendar-game">'+esc(item.game)+'</div></div></div><div class="lock-calendar-date">'+calendarDate(item.trade_lock_until)+'<small>'+(isHistory?'вышел из трейд-бана':'до разблокировки')+'</small></div></div>'}).join(''):'<div class="lock-calendar-empty">'+(isHistory?'История разблокировок пока пуста.<br>Предметы сохраняются здесь после истечения обнаруженного трейд-бана.':'Нет активных трейд-банов в загруженных данных.<br>Нажмите «Загрузить / обновить», чтобы проверить выбранную игру.')+'</div>';
 if(!calendarLoading){var locked=new Set(active.map(function(item){return item.login})),unlocked=new Set(history.map(function(item){return item.login}));status.textContent='Активных: '+active.length+' ('+locked.size+' акк.) • вышли из ТБ: '+history.length+' ('+unlocked.size+' акк.) • выделено слева: '+checkedCount()}
}
function loadCalendarCache(){return fetch('/api/inventory/locks?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){if(!d.ok)throw new Error(d.message||'Не удалось прочитать кэш');calendarData=d;renderTradeBanCalendar()})}
function openTradeBanCalendar(){document.getElementById('tradeBanCalendarModal').classList.add('show');renderTradeBanCalendar();loadCalendarCache().catch(function(e){document.getElementById('calendarStatus').textContent=e.message||'Ошибка чтения инвентарного кэша'})}
function closeTradeBanCalendar(){if(calendarLoading)calendarCancel=true;document.getElementById('tradeBanCalendarModal').classList.remove('show')}
function selectCalendarAccounts(entries,kind){
 var logins=new Set(entries.map(function(item){return item.login})),targets=accounts.filter(function(a){return logins.has(a.login)});checkedLogins={};targets.forEach(function(a){checkedLogins[a.login]=true});renderRows(filtered());renderTradeBanCalendar();toast(targets.length?'Выделено аккаунтов '+kind+': '+targets.length:'Нет аккаунтов '+kind+' для выбранной игры')
}
function selectCalendarLocked(){selectCalendarAccounts(calendarVisibleEntries(),'с активным ТБ')}
function selectCalendarUnlocked(){selectCalendarAccounts(calendarHistoryEntries(),'с завершившимся ТБ')}
function setCalendarView(view){calendarView=view==='history'?'history':'active';renderTradeBanCalendar()}
async function loadTradeBanCalendar(){
 if(calendarLoading)return;var targets=accounts.filter(function(a){return isChecked(a.login)});if(!targets.length)targets=accounts.slice();if(!targets.length){toast('Нет аккаунтов для загрузки');return}
 var scopes=inventoryScopesForGame(document.getElementById('calendarGame').value),total=targets.length*scopes.length,done=0,errors=0,status=document.getElementById('calendarStatus'),button=document.getElementById('calendarLoadBtn');calendarLoading=true;calendarCancel=false;button.disabled=true;button.textContent='Загрузка…';
 try{
  for(var i=0;i<targets.length;i++){for(var j=0;j<scopes.length;j++){if(calendarCancel)break;var acc=targets[i],scope=scopes[j];done++;status.textContent='Загрузка '+done+'/'+total+' • '+acc.login+' • '+scope.game;try{var r=await fetch('/api/inventory/'+encodeURIComponent(acc.login)+'?appid='+scope.appid+'&context='+scope.context+'&refresh=1&prices=0&ts='+Date.now(),{cache:'no-store'}),d=await r.json();if(!r.ok||!d.ok)throw new Error(d.message||'Ошибка инвентаря');if(d.warning)throw new Error(d.warning)}catch(e){errors++}}if(calendarCancel)break}
  await loadCalendarCache();status.textContent=(calendarCancel?'Загрузка остановлена':'Загрузка завершена')+' • проверено '+done+'/'+total+(errors?' • ошибок: '+errors:'')+' • выделено слева: '+checkedCount()
 }catch(e){status.textContent=e.message||'Ошибка загрузки календаря'}finally{calendarLoading=false;button.disabled=false;button.textContent='↻ Загрузить / обновить'}
}
var bulkTradeRunning=false,bulkTradeStopRequested=false,bulkTradeTimer=null,bulkTradeWake=null;
function bulkTradeTargets(){return accounts.filter(function(a){return isChecked(a.login)})}
function loadBulkTradeLinks(){fetch('/api/trade/saved-link?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){var select=document.getElementById('bulkTradeSaved'),old=select.value;select.innerHTML='<option value="">Сохранённые Trade URL</option>'+(d.trade_urls||[]).map(function(url,index){return '<option value="'+esc(url)+'">Получатель '+String(index+1)+'</option>'}).join('');select.value=old}).catch(function(){})}
function openBulkTrade(){document.getElementById('bulkTradeModal').classList.add('show');if(!bulkTradeRunning)document.getElementById('bulkTradeStatus').textContent='Выделено аккаунтов: '+bulkTradeTargets().length+'. Выберите ссылку и игру.';loadBulkTradeLinks()}
function closeBulkTrade(){if(bulkTradeRunning){toast('Сначала остановите массовую отправку');return}document.getElementById('bulkTradeModal').classList.remove('show')}
function bulkTradeLog(index,login,message,state){var row=document.querySelector('[data-bulk-index="'+index+'"]');if(!row)return;row.className='bulk-trade-log-row '+(state||'');row.querySelector('.bulk-trade-log-message').textContent=message}
function bulkTradeRandomDelay(){return (20+Math.floor(Math.random()*11))*1000}
function bulkTradeWait(){var milliseconds=bulkTradeRandomDelay(),seconds=Math.round(milliseconds/1000);document.getElementById('bulkTradeStatus').textContent='Следующий аккаунт через '+seconds+' сек. Можно остановить очередь.';return new Promise(function(resolve){bulkTradeWake=resolve;bulkTradeTimer=setTimeout(function(){bulkTradeTimer=null;bulkTradeWake=null;resolve()},milliseconds)})}
function stopBulkTrade(){if(!bulkTradeRunning)return;bulkTradeStopRequested=true;document.getElementById('bulkTradeStop').disabled=true;document.getElementById('bulkTradeStatus').textContent='Остановка после текущего запроса…';if(bulkTradeTimer){clearTimeout(bulkTradeTimer);bulkTradeTimer=null}if(bulkTradeWake){var wake=bulkTradeWake;bulkTradeWake=null;wake()}}
async function bulkTradeRequest(url,options){var response=await fetch(url,options),data=await response.json();if(!response.ok||!data.ok)throw new Error(data.message||'Steam не выполнил запрос');return data}
async function startBulkTrade(){
 if(bulkTradeRunning)return;var targets=bulkTradeTargets(),url=document.getElementById('bulkTradeUrl').value.trim(),game=document.getElementById('bulkTradeGame').value;if(!targets.length){toast('Выделите аккаунты галочками слева');return}if(!/[?&]partner=\d+/.test(url)||!/[?&]token=.+/.test(url)){toast('Укажите корректную Trade URL с partner и token');return}
 if(!confirm('Отправить все передаваемые предметы '+game+' с '+targets.length+' аккаунтов на указанную ссылку? Между аккаунтами будет пауза 20–30 секунд.'))return;
 var scope={appid:inventoryGames[game],context:String(inventoryContexts[game]||2)},log=document.getElementById('bulkTradeLog'),status=document.getElementById('bulkTradeStatus'),start=document.getElementById('bulkTradeStart'),stop=document.getElementById('bulkTradeStop'),completed=0,failed=0,skipped=0;
 bulkTradeRunning=true;bulkTradeStopRequested=false;start.disabled=true;stop.disabled=false;document.getElementById('bulkTradeUrl').disabled=true;document.getElementById('bulkTradeGame').disabled=true;document.getElementById('bulkTradeSaved').disabled=true;log.innerHTML=targets.map(function(a,index){return '<div class="bulk-trade-log-row waiting" data-bulk-index="'+index+'"><div class="bulk-trade-log-login">'+esc(a.login)+'</div><div class="bulk-trade-log-message">Ожидание</div></div>'}).join('');
 try{
  for(var i=0;i<targets.length;i++){if(bulkTradeStopRequested)break;var acc=targets[i];status.textContent=(i+1)+'/'+targets.length+' • '+acc.login+' • загрузка '+game;bulkTradeLog(i,acc.login,'Загрузка свежего инвентаря…','waiting');try{
   var inventory=await bulkTradeRequest('/api/inventory/'+encodeURIComponent(acc.login)+'?appid='+scope.appid+'&context='+scope.context+'&refresh=1&prices=0&ts='+Date.now(),{cache:'no-store'});if(inventory.warning)throw new Error('Инвентарь не обновлён: '+inventory.warning);
   var items=(inventory.items||[]).filter(function(item){var unlock=Number(item.trade_lock_until||0)*1000;return String(item.assetid||'').match(/^\d+$/)&&(item.tradable||(unlock&&unlock<=Date.now()))});
   if(!items.length){skipped++;bulkTradeLog(i,acc.login,'Нет передаваемых предметов '+game+' — пропущено','waiting')}else{
    var chunks=[];for(var offset=0;offset<items.length;offset+=100)chunks.push(items.slice(offset,offset+100));var sent=0,offers=0;
    for(var chunkIndex=0;chunkIndex<chunks.length;chunkIndex++){if(bulkTradeStopRequested)break;var chunk=chunks[chunkIndex];status.textContent=(i+1)+'/'+targets.length+' • '+acc.login+' • отправка '+(chunkIndex+1)+'/'+chunks.length;bulkTradeLog(i,acc.login,'Отправка '+chunk.length+' предметов • трейд '+(chunkIndex+1)+'/'+chunks.length,'waiting');var result=await bulkTradeRequest('/api/inventory/trade/'+encodeURIComponent(acc.login),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({trade_url:url,appid:scope.appid,contextid:scope.context,assetids:chunk.map(function(item){return String(item.assetid)}),preserve_cache:chunkIndex<chunks.length-1,full_amount:true})});sent+=Number(result.items_sent||chunk.length);offers++}
    if(offers){completed++;bulkTradeLog(i,acc.login,'Отправлено предметов: '+sent+' • трейдов: '+offers,'success')}else if(bulkTradeStopRequested)bulkTradeLog(i,acc.login,'Остановлено до отправки','waiting')
   }
  }catch(e){failed++;bulkTradeLog(i,acc.login,e.message||'Ошибка отправки','error')}
  if(i+1<targets.length&&!bulkTradeStopRequested)await bulkTradeWait()
  }
  status.textContent=bulkTradeStopRequested?'Очередь остановлена. Выполненный запрос не отменяется.':'Готово • аккаунтов с трейдами: '+completed+' • пропущено: '+skipped+' • ошибок: '+failed
 }finally{bulkTradeRunning=false;bulkTradeStopRequested=false;start.disabled=false;stop.disabled=true;document.getElementById('bulkTradeUrl').disabled=false;document.getElementById('bulkTradeGame').disabled=false;document.getElementById('bulkTradeSaved').disabled=false}
}
function operationTargets(){var selected=accounts.filter(function(a){return isChecked(a.login)});return selected.length?selected:accounts.slice()}
function operationScope(game){return {appid:inventoryGames[game],context:String(inventoryContexts[game]||2)}}
function operationInventory(login,scope){return bulkTradeRequest('/api/inventory/'+encodeURIComponent(login)+'?appid='+scope.appid+'&context='+scope.context+'&refresh=1&prices=0&ts='+Date.now(),{cache:'no-store'}).then(function(data){if(data.warning)throw new Error('Инвентарь не обновлён: '+data.warning);return data})}
function operationItemAvailable(item){var unlock=Number(item.trade_lock_until||0)*1000;return String(item.assetid||'').match(/^\d+$/)&&(item.tradable||(unlock&&unlock<=Date.now()))}
function operationWaitable(ms,state,status,text){return new Promise(function(resolve){state.wake=resolve;state.timer=setTimeout(function(){state.timer=null;state.wake=null;resolve()},ms);if(status)status.textContent=text})}
function operationStopWait(state){if(state.timer){clearTimeout(state.timer);state.timer=null}if(state.wake){var wake=state.wake;state.wake=null;wake()}}
var collectorItems=[],collectorLoading=false,collectorRunning=false,collectorStopRequested=false,collectorWaitState={timer:null,wake:null};
function openItemCollector(){document.getElementById('itemCollectorModal').classList.add('show');loadCollectorLinks();renderCollectorItems()}
function closeItemCollector(){if(collectorRunning||collectorLoading){toast('Сначала остановите текущую операцию');return}document.getElementById('itemCollectorModal').classList.remove('show')}
function loadCollectorLinks(){fetch('/api/trade/saved-link?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){var select=document.getElementById('collectorSaved'),old=select.value;select.innerHTML='<option value="">Сохранённые Trade URL</option>'+(d.trade_urls||[]).map(function(url,index){return '<option value="'+esc(url)+'">Получатель '+String(index+1)+'</option>'}).join('');select.value=old}).catch(function(){})}
function collectorSelected(){return collectorItems.filter(function(item){return item.selected})}
function toggleCollectorAll(){var select=!collectorItems.length||!collectorItems.every(function(item){return item.selected});collectorItems.forEach(function(item){item.selected=select});renderCollectorItems()}
function renderCollectorItems(){
 var list=document.getElementById('collectorList'),selected=collectorSelected();document.getElementById('collectorCount').textContent=collectorItems.length?'Найдено: '+collectorItems.length+' • выбрано: '+selected.length:'Предметы не найдены';document.getElementById('collectorStart').disabled=collectorRunning||!selected.length;document.getElementById('collectorToggleAll').textContent=selected.length&&selected.length===collectorItems.length?'Снять выделение':'Выбрать всё';
 list.innerHTML=collectorItems.length?collectorItems.map(function(item,index){return '<div class="bulk-operation-row"><input type="checkbox" data-collector-index="'+index+'" '+(item.selected?'checked':'')+'><div>'+(item.icon?'<img loading="lazy" src="'+esc(item.icon)+'" alt="">':'')+'</div><div><div class="bulk-operation-name" title="'+esc(item.name)+'">'+esc(item.name)+(Number(item.amount||1)>1?' ×'+Number(item.amount):'')+'</div><div class="bulk-operation-account">'+esc(item.login)+' • '+esc(item.game)+'</div></div><div class="bulk-operation-price">Доступен для трейда<small>asset '+esc(item.assetid)+'</small></div></div>'}).join(''):'<div class="bulk-operation-empty">Введите название и нажмите «Найти предметы».</div>';
 list.querySelectorAll('[data-collector-index]').forEach(function(box){box.onchange=function(){var item=collectorItems[Number(box.dataset.collectorIndex)];if(item)item.selected=box.checked;renderCollectorItems()}})
}
async function loadCollectorItems(){
 if(collectorLoading||collectorRunning)return;var query=document.getElementById('collectorQuery').value.trim().toLowerCase();if(!query){toast('Введите название предмета, например Kilowatt Case');return}var targets=operationTargets(),game=document.getElementById('collectorGame').value,scope=operationScope(game);if(!targets.length){toast('Нет аккаунтов');return}
 collectorLoading=true;collectorStopRequested=false;collectorItems=[];renderCollectorItems();var button=document.getElementById('collectorLoad'),status=document.getElementById('collectorStatus'),stop=document.getElementById('collectorStop');button.disabled=true;button.textContent='Поиск…';stop.disabled=false;var errors=0;
 try{for(var i=0;i<targets.length;i++){if(collectorStopRequested)break;var acc=targets[i];status.textContent='Инвентарь '+(i+1)+'/'+targets.length+' • '+acc.login;try{var data=await operationInventory(acc.login,scope);(data.items||[]).forEach(function(item){var name=String(item.market_hash_name||item.name||'');if(name.toLowerCase().indexOf(query)===-1||!operationItemAvailable(item))return;collectorItems.push({login:acc.login,appid:scope.appid,contextid:scope.context,assetid:String(item.assetid),name:String(item.name||name),market_hash_name:name,icon:item.icon||'',amount:Math.max(1,Number(item.amount||1)),game:game,selected:true})})}catch(e){errors++}status.textContent='Проверено '+(i+1)+'/'+targets.length+' • найдено '+collectorItems.length+(errors?' • ошибок: '+errors:'')}}finally{collectorLoading=false;button.disabled=false;button.textContent='Найти предметы';stop.disabled=true;renderCollectorItems()}
}
function collectorLog(index,login,message,state){var row=document.querySelector('[data-collector-log="'+index+'"]');if(!row)return;row.className='bulk-trade-log-row '+(state||'');row.querySelector('.bulk-trade-log-message').textContent=message}
function stopCollector(){if(!collectorRunning&&!collectorLoading)return;collectorStopRequested=true;document.getElementById('collectorStop').disabled=true;document.getElementById('collectorStatus').textContent='Остановка после текущего запроса…';operationStopWait(collectorWaitState)}
async function startCollector(){
 if(collectorRunning)return;var selected=collectorSelected(),url=document.getElementById('collectorUrl').value.trim();if(!selected.length){toast('Выберите предметы');return}if(!/[?&]partner=\d+/.test(url)||!/[?&]token=.+/.test(url)){toast('Укажите корректную Trade URL');return}if(!confirm('Отправить '+selected.length+' предметов на указанную Trade URL? Инвентарь будет повторно проверен перед каждым аккаунтом.'))return;
 var groups=[];selected.forEach(function(item){var group=groups.find(function(g){return g.login===item.login});if(!group){group={login:item.login,items:[]};groups.push(group)}group.items.push(item)});collectorRunning=true;collectorStopRequested=false;var start=document.getElementById('collectorStart'),stop=document.getElementById('collectorStop'),status=document.getElementById('collectorStatus'),log=document.getElementById('collectorLog');start.disabled=true;stop.disabled=false;document.getElementById('collectorLoad').disabled=true;log.innerHTML=groups.map(function(g,i){return '<div class="bulk-trade-log-row waiting" data-collector-log="'+i+'"><div class="bulk-trade-log-login">'+esc(g.login)+'</div><div class="bulk-trade-log-message">Ожидание</div></div>'}).join('');var completed=0;
 try{for(var i=0;i<groups.length;i++){if(collectorStopRequested)break;var group=groups[i],scope={appid:group.items[0].appid,context:group.items[0].contextid};collectorLog(i,group.login,'Повторная проверка инвентаря…','waiting');try{var fresh=await operationInventory(group.login,scope),byId={};(fresh.items||[]).forEach(function(item){byId[String(item.assetid)]=item});var available=group.items.filter(function(item){var current=byId[item.assetid];return current&&operationItemAvailable(current)&&String(current.market_hash_name||current.name||'')===item.market_hash_name});if(!available.length){collectorLog(i,group.login,'Выбранные предметы уже недоступны','error');continue}var sentIds=[];for(var offset=0;offset<available.length;offset+=100){if(collectorStopRequested)break;var chunk=available.slice(offset,offset+100);status.textContent=group.login+' • отправка '+chunk.length+' предметов';var result=await bulkTradeRequest('/api/inventory/trade/'+encodeURIComponent(group.login),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({trade_url:url,appid:scope.appid,contextid:scope.context,assetids:chunk.map(function(item){return item.assetid}),preserve_cache:offset+100<available.length,full_amount:true})});sentIds=sentIds.concat(chunk.map(function(item){return item.assetid}))}if(sentIds.length){completed++;var sentSet=new Set(sentIds);collectorItems=collectorItems.filter(function(item){return !(item.login===group.login&&sentSet.has(item.assetid))});collectorLog(i,group.login,'Трейдов создано: '+Math.ceil(sentIds.length/100)+' • предметов: '+sentIds.length,'success')}}catch(e){collectorLog(i,group.login,e.message||'Ошибка отправки','error')}renderCollectorItems();if(i+1<groups.length&&!collectorStopRequested){var ms=bulkTradeRandomDelay();await operationWaitable(ms,collectorWaitState,status,'Следующий аккаунт через '+Math.round(ms/1000)+' сек.')}}status.textContent=collectorStopRequested?'Очередь остановлена. Созданный трейд не отменяется.':'Готово • аккаунтов с трейдами: '+completed+'. Оставшиеся в списке предметы не отправлялись.'}finally{collectorRunning=false;collectorStopRequested=false;start.disabled=!collectorSelected().length;stop.disabled=true;document.getElementById('collectorLoad').disabled=false}
}
var bulkSellItems=[],bulkSellLoading=false,bulkSellQuoting=false,bulkSellRunning=false,bulkSellStopRequested=false,bulkSellWaitState={timer:null,wake:null};
function bulkSellBusy(){return bulkSellLoading||bulkSellQuoting||bulkSellRunning}
function openBulkSell(){document.getElementById('bulkSellModal').classList.add('show');renderBulkSellItems()}
function closeBulkSell(){if(bulkSellBusy()){toast('Сначала остановите текущую операцию');return}document.getElementById('bulkSellModal').classList.remove('show')}
function bulkSellSellerCents(item){return item.saleCents>0?marketSellerReceivesCents(item.saleCents,item.appid,item.fee):0}
function bulkSellPriceValid(item){return item.saleCents>0&&bulkSellSellerCents(item)>0}
function bulkSellSelected(){return bulkSellItems.filter(function(item){return item.selected&&bulkSellPriceValid(item)})}
function toggleBulkSellAll(){var available=bulkSellItems.filter(bulkSellPriceValid),select=available.some(function(item){return !item.selected});available.forEach(function(item){item.selected=select});renderBulkSellItems()}
function changeBulkSellPrice(index,value){
 var item=bulkSellItems[index];if(!item||bulkSellBusy())return;var text=String(value||'').trim();item.manualPrice=true;item.manualText=text;item.priceError='';
 if(!/^\d+(?:[.,]\d{1,2})?$/.test(text)){item.saleCents=0;item.selected=false;item.priceError='Введите цену, например 53.40';renderBulkSellItems();return}
 var cents=Math.round(Number(text.replace(',','.'))*100),seller=cents>0?marketSellerReceivesCents(cents,item.appid,item.fee):0;
 if(!cents||!seller){item.saleCents=0;item.selected=false;item.priceError='Steam не может выставить ровно эту цену';renderBulkSellItems();return}
 item.saleCents=cents;item.selected=true;renderBulkSellItems()
}
function bulkSellAccount(item){return accounts.find(function(acc){return acc.login===item.login})}
function bulkSellBookRows(list,kind,currency){
 var copy=(list||[]).slice();copy.sort(function(a,b){return kind==='buy'?Number(b[0])-Number(a[0]):Number(a[0])-Number(b[0])});copy=copy.slice(0,5);
 return copy.length?copy.map(function(level){return '<div class="bulk-sell-book-row"><b>'+orderMoney(level[0],currency)+'</b><span>'+Number(level[1])+' шт.</span></div>'}).join(''):'<div class="bulk-sell-book-row"><span>Нет ордеров</span></div>'
}
function renderBulkSellItems(){
 var list=document.getElementById('bulkSellList'),selected=bulkSellSelected(),busy=bulkSellBusy(),available=bulkSellItems.filter(bulkSellPriceValid),priced=available.length;
 document.getElementById('bulkSellCount').textContent=bulkSellItems.length?'Позиций: '+bulkSellItems.length+' • с ценой: '+priced+' • выбрано: '+selected.length:'Предметы не найдены';
 document.getElementById('bulkSellStart').disabled=busy||!selected.length;
 document.getElementById('bulkSellLoad').disabled=busy;
 document.getElementById('bulkSellQuote').disabled=busy||!bulkSellItems.length;
 var refresh=document.getElementById('bulkSellRefresh');refresh.disabled=busy||!bulkSellItems.length;refresh.classList.toggle('loading',bulkSellQuoting);
 document.getElementById('bulkSellToggleAll').disabled=busy||!available.length;
 document.getElementById('bulkSellToggleAll').textContent=available.length&&selected.length===available.length?'Снять выделение':'Выбрать всё';
 list.innerHTML=bulkSellItems.length?bulkSellItems.map(function(item,index){
  var sellerCents=bulkSellSellerCents(item),valid=sellerCents>0,priceValue=item.manualPrice?String(item.manualText||''):(item.saleCents>0?(item.saleCents/100).toFixed(2):'');
  var details=valid?(item.manualPrice?'Ручная цена • вы получите '+orderMoney(sellerCents,item.currency):'Вы получите '+orderMoney(sellerCents,item.currency)+' • макс. ордер '+orderMoney(item.highestBuy,item.currency)):(item.priceError||'Введите свою цену или нажмите «Рассчитать цены»');
  var price='<span class="bulk-sell-price-label">Покупатель платит</span><div class="bulk-sell-price-editor"><input class="bulk-sell-price-input" type="text" inputmode="decimal" data-bulk-sell-price="'+index+'" value="'+esc(priceValue)+'" placeholder="0.00" autocomplete="off" '+(busy?'disabled':'')+'><span>'+esc(item.currencyCode)+'</span></div><small class="'+(!valid&&item.priceError?'bulk-sell-price-error':(item.manualPrice&&valid?'bulk-sell-manual':''))+'">'+esc(details)+'</small>';
  var book=item.quotedAt?'<div class="bulk-sell-book-side sell"><div class="bulk-sell-book-title">Цена на продажу</div>'+bulkSellBookRows(item.sellOrders,'sell',item.currency)+'</div><div class="bulk-sell-book-side buy"><div class="bulk-sell-book-title">Ордера на скупку</div>'+bulkSellBookRows(item.buyOrders,'buy',item.currency)+'</div>':'<div class="bulk-sell-book-empty">Стакан появится после расчёта.<br>Ручную цену можно ввести сразу.</div>';
  var disabled=!valid||busy?' disabled':'';
  return '<div class="bulk-operation-row bulk-sell-row'+(!valid&&item.priceError?' error':'')+'"><input type="checkbox" data-bulk-sell-index="'+index+'" '+(item.selected&&valid?'checked':'')+disabled+'><div class="bulk-sell-item"><div class="bulk-sell-icon">'+(item.icon?'<img loading="lazy" src="'+esc(item.icon)+'" alt="">':'—')+'</div><div class="bulk-sell-item-copy"><div class="bulk-operation-name" title="'+esc(item.name)+'">'+esc(item.name)+'</div><div class="bulk-operation-account">'+esc(item.login)+' • '+esc(item.game)+' • '+esc(item.currencyCode)+'</div></div></div><div class="bulk-sell-price">'+price+'</div><div class="bulk-sell-book">'+book+'</div></div>'
 }).join(''):'<div class="bulk-operation-empty">Загрузите рыночные предметы выбранной игры.<br>Можно оставить название пустым, чтобы загрузить все.</div>';
 list.querySelectorAll('[data-bulk-sell-index]').forEach(function(box){box.onchange=function(){var item=bulkSellItems[Number(box.dataset.bulkSellIndex)];if(item)item.selected=box.checked;renderBulkSellItems()}});
 list.querySelectorAll('[data-bulk-sell-price]').forEach(function(field){field.onchange=function(){changeBulkSellPrice(Number(field.dataset.bulkSellPrice),field.value)};field.onkeydown=function(e){if(e.key==='Enter'){e.preventDefault();field.blur()}}})
}
async function bulkSellQuote(item,acc,quotes){
 var currency=buyCurrencyId(acc),country=acc.country||'US',key=item.appid+':'+item.market_hash_name+':'+currency+':'+country;item.currency=currency;item.currencyCode=buyCurrencyCode(acc);item.country=country;if(quotes[key])return quotes[key];
 var promise=bulkTradeRequest('/api/market/listing?appid='+item.appid+'&currency='+currency+'&country='+encodeURIComponent(country)+'&login='+encodeURIComponent(acc.login)+'&name='+encodeURIComponent(item.market_hash_name)+'&include_fees=1&force=1&ts='+Date.now(),{cache:'no-store'}).then(function(data){if(data.cached||data.stale||data.warning)throw new Error(data.warning||'Ордера устарели');var highest=Math.round(Number(data.highest_buy_order)),minimumBuyer=marketBuyerPaysCents(1,item.appid,data.fee);if(!Number.isFinite(highest)||highest<minimumBuyer)throw new Error('Нет ордера покупки, достаточного с учётом комиссий');var exactSeller=marketSellerReceivesCents(highest,item.appid,data.fee);if(!exactSeller)throw new Error('Steam не может выставить ровно эту цену с текущим шагом комиссий валюты');return {highest:highest,saleCents:highest,fee:data.fee||null,buyOrders:data.buy_orders||[],sellOrders:data.sell_orders||[]}});quotes[key]=promise;return promise
}
async function loadBulkSellItems(){
 if(bulkSellBusy())return;var targets=operationTargets(),game=document.getElementById('bulkSellGame').value,scope=operationScope(game),query=document.getElementById('bulkSellQuery').value.trim().toLowerCase();if(!targets.length){toast('Нет аккаунтов');return}
 bulkSellLoading=true;bulkSellStopRequested=false;bulkSellItems=[];var stop=document.getElementById('bulkSellStop'),status=document.getElementById('bulkSellStatus'),errors=0;stop.disabled=false;renderBulkSellItems();
 try{
  for(var i=0;i<targets.length;i++){
   if(bulkSellStopRequested)break;var acc=targets[i];status.textContent='Инвентарь '+(i+1)+'/'+targets.length+' • '+acc.login;
   try{
    var data=await operationInventory(acc.login,scope);(data.items||[]).forEach(function(item){var marketName=String(item.market_hash_name||item.name||'');if(!item.marketable||!marketName||!String(item.assetid||'').match(/^\d+$/)||(query&&marketName.toLowerCase().indexOf(query)===-1))return;bulkSellItems.push({login:acc.login,appid:scope.appid,contextid:scope.context,assetid:String(item.assetid),name:String(item.name||marketName),market_hash_name:marketName,icon:item.icon||'',game:game,selected:false,manualPrice:false,manualText:'',saleCents:0,highestBuy:0,currency:buyCurrencyId(acc),currencyCode:buyCurrencyCode(acc),quotedAt:0,fee:null,priceError:'',buyOrders:[],sellOrders:[]})});renderBulkSellItems()
   }catch(e){errors++;status.textContent=acc.login+': '+(e.message||'ошибка инвентаря')}
  }
  status.textContent=(bulkSellStopRequested?'Загрузка остановлена':'Предметы загружены')+' • позиций: '+bulkSellItems.length+(errors?' • ошибок: '+errors:'')+'. Введите цены вручную или нажмите «Рассчитать цены».'
 }finally{bulkSellLoading=false;stop.disabled=true;renderBulkSellItems()}
}
async function calculateBulkSellPrices(){
 if(bulkSellBusy())return;if(!bulkSellItems.length){toast('Сначала загрузите предметы');return}
 bulkSellQuoting=true;bulkSellStopRequested=false;var stop=document.getElementById('bulkSellStop'),status=document.getElementById('bulkSellStatus'),errors=0,quotes={};stop.disabled=false;renderBulkSellItems();
 try{
  for(var i=0;i<bulkSellItems.length;i++){
   if(bulkSellStopRequested)break;var item=bulkSellItems[i],acc=bulkSellAccount(item);status.textContent='Стакан '+(i+1)+'/'+bulkSellItems.length+' • '+item.login+' • '+item.name;
   try{
    if(!acc)throw new Error('Аккаунт не найден');var quote=await bulkSellQuote(item,acc,quotes);item.highestBuy=quote.highest;if(!item.manualPrice)item.saleCents=quote.saleCents;item.fee=quote.fee;item.buyOrders=quote.buyOrders;item.sellOrders=quote.sellOrders;item.selected=bulkSellPriceValid(item);item.quotedAt=Date.now();if(!item.manualPrice||bulkSellPriceValid(item))item.priceError=''
   }catch(e){if(!item.manualPrice){item.saleCents=0;item.selected=false;item.priceError=e.message||'Ордера недоступны'}else item.selected=bulkSellPriceValid(item);item.highestBuy=0;item.quotedAt=0;item.buyOrders=[];item.sellOrders=[];errors++}
   renderBulkSellItems()
  }
  status.textContent=(bulkSellStopRequested?'Расчёт остановлен':'Стакан обновлён')+' • готовы: '+bulkSellSelected().length+' • ошибок: '+errors+'. Проверьте цены перед продажей.'
 }finally{bulkSellQuoting=false;stop.disabled=true;renderBulkSellItems()}
}
function stopBulkSell(){if(!bulkSellBusy())return;bulkSellStopRequested=true;document.getElementById('bulkSellStop').disabled=true;document.getElementById('bulkSellStatus').textContent='Остановка после текущего запроса…';operationStopWait(bulkSellWaitState)}
function bulkSellErrorLog(item,message){var log=document.getElementById('bulkSellLog'),row=document.createElement('div');row.className='bulk-trade-log-row error';row.innerHTML='<div class="bulk-trade-log-login">'+esc(item.login)+'</div><div class="bulk-trade-log-message">'+esc(item.name)+': '+esc(message)+'</div>';log.appendChild(row)}
async function startBulkSell(){
 if(bulkSellBusy())return;var selected=bulkSellSelected();if(!selected.length){toast('Нет выбранных предметов с корректной ценой');return}if(selected.some(function(item){return !item.manualPrice&&Date.now()-item.quotedAt>120000})){toast('Расчёт цен старше 2 минут. Обновите стакан кнопкой ↻');return}if(!confirm('Выставить '+selected.length+' позиций на продажу? Для каждой покупатель платит указанную вручную или рассчитанную сумму, а сумма продавца рассчитывается после комиссий. Продажа выполняется по очереди.'))return;
 bulkSellRunning=true;bulkSellStopRequested=false;var stop=document.getElementById('bulkSellStop'),status=document.getElementById('bulkSellStatus');stop.disabled=false;document.getElementById('bulkSellLog').innerHTML='';renderBulkSellItems();var remaining={};selected.forEach(function(item){var key=item.login+':'+item.appid+':'+item.contextid;remaining[key]=(remaining[key]||0)+1});var created=0,confirmed=0,pending=0,failed=0;
 try{
  for(var i=0;i<selected.length;i++){
   if(bulkSellStopRequested)break;var item=selected[i],key=item.login+':'+item.appid+':'+item.contextid;status.textContent='Продажа '+(i+1)+'/'+selected.length+' • '+item.login+' • '+item.name;
   try{var result=await bulkTradeRequest('/api/market/sell/'+encodeURIComponent(item.login),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({appid:item.appid,contextid:item.contextid,assetid:item.assetid,buyer_pays:(item.saleCents/100).toFixed(2),expected_buyer_price_cents:item.saleCents,auto_confirm:true,preserve_cache:remaining[key]>1})});created++;if(result.needs_confirmation){if(result.confirmed)confirmed++;else pending++}bulkSellItems=bulkSellItems.filter(function(x){return x!==item});renderBulkSellItems()}catch(e){failed++;bulkSellErrorLog(item,e.message||'Ошибка продажи')}
   remaining[key]--;if(i+1<selected.length&&!bulkSellStopRequested)await operationWaitable(1000,bulkSellWaitState,null,'')
  }
  status.textContent=bulkSellStopRequested?'Очередь остановлена после текущего запроса. Созданные объявления не отменяются.':'Готово • создано: '+created+' • подтверждено: '+confirmed+' • ждут подтверждения: '+pending+' • ошибок: '+failed
 }finally{bulkSellRunning=false;bulkSellStopRequested=false;stop.disabled=true;renderBulkSellItems()}
}
function selectedInventoryItems(){var ids=inventorySelectedAssets;return currentInventoryItems.filter(function(x){return x.tradable&&ids.has(String(x.assetid))})}
function updateInventoryTradeDialog(){var items=selectedInventoryItems();document.getElementById('inventoryTradeCount').textContent=items.length+' предметов';document.getElementById('inventoryTradeItems').innerHTML=items.length?items.map(function(x){return '<div class="inventory-trade-thumb" data-remove-asset="'+esc(String(x.assetid))+'" title="Нажмите, чтобы убрать из трейда: '+esc(x.name)+'">'+(x.icon?'<img src="'+esc(x.icon)+'" alt="">':'<span>—</span>')+'<div>'+esc(x.name)+'</div></div>'}).join(''):'<div class="inventory-trade-empty">Выберите предметы в инвентаре</div>'}
function removeAssetFromTrade(assetid){inventorySelectedAssets.delete(String(assetid));var box=document.querySelector('#inventory [data-asset="'+String(assetid)+'"]');if(box){box.checked=false;var card=box.closest('.inventory-item');if(card)card.classList.remove('selected')}updateInventoryTradeDialog();bindInventoryTradeRemovals()}
function bindInventoryTradeRemovals(){document.querySelectorAll('#inventoryTradeItems [data-remove-asset]').forEach(function(card){card.onclick=function(){removeAssetFromTrade(card.dataset.removeAsset)}})}
function toggleWholeInventorySelection(){var tradable=currentInventoryItems.filter(function(x){return x.tradable||x.marketable});if(!tradable.length){toast("Нет предметов, доступных для обмена или продажи");return}var all=tradable.every(function(x){return inventorySelectedAssets.has(String(x.assetid))});inventorySelectedAssets=new Set(all?[]:tradable.map(function(x){return String(x.assetid)}));document.querySelectorAll("#inventory [data-asset]").forEach(function(box){box.checked=inventorySelectedAssets.has(String(box.dataset.asset));var card=box.closest(".inventory-item");if(card)card.classList.toggle("selected",box.checked)});toast(all?"Выделение снято":"Выбрано предметов: "+tradable.length)}
function selectedInventorySellItems(){var ids=inventorySelectedAssets;return currentInventoryItems.filter(function(x){return x.marketable&&ids.has(String(x.assetid))})}
function openInventorySellSelected(){
 if(!currentInventoryAccount||currentGame==='Buy TF2'){toast('Сначала откройте инвентарь аккаунта');return}if(bulkSellBusy()){toast('Дождитесь завершения текущей массовой продажи');return}var items=selectedInventorySellItems();if(!items.length){toast('Выделите предметы, которые можно продать');return}
 bulkSellItems=items.map(function(item){var marketName=String(item.market_hash_name||item.name||'');return {login:currentInventoryAccount.login,appid:currentInventoryAppid,contextid:currentInventoryContext,assetid:String(item.assetid),name:String(item.name||marketName),market_hash_name:marketName,icon:item.icon||'',game:currentGame,selected:false,saleCents:0,highestBuy:0,currency:buyCurrencyId(currentInventoryAccount),currencyCode:buyCurrencyCode(currentInventoryAccount),quotedAt:0,fee:null,priceError:'',buyOrders:[],sellOrders:[]}});bulkSellStopRequested=false;document.getElementById('bulkSellGame').value=currentGame;document.getElementById('bulkSellQuery').value='';document.getElementById('bulkSellLog').innerHTML='';document.getElementById('bulkSellStop').disabled=true;document.getElementById('bulkSellStatus').textContent='Из инвентаря выбрано позиций: '+items.length+'. Рассчитайте цены, проверьте их и нажмите «Выставить выбранное».';document.getElementById('bulkSellModal').classList.add('show');renderBulkSellItems()
}
function openInventoryTrade(){
 if(!currentInventoryAccount||currentGame==='Buy TF2'){toast('Сначала откройте инвентарь аккаунта');return}
 document.getElementById('inventoryTradeModal').classList.add('show');document.getElementById('inventoryTradeStatus').textContent='';updateInventoryTradeDialog();bindInventoryTradeRemovals();
 var select=document.getElementById('inventoryTradeUrl');select.innerHTML='<option value="">Загрузка ссылок…</option>';
 fetch('/api/trade/saved-link?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){var links=d.trade_urls||[];select.innerHTML=links.length?links.map(function(x,i){return '<option value="'+esc(x)+'">Получатель '+(i+1)+' • '+esc(x)+'</option>'}).join(''):'<option value="">Нет сохранённых Trade URL</option>'}).catch(function(){select.innerHTML='<option value="">Не удалось загрузить ссылки</option>'});
}
function closeInventoryTrade(){document.getElementById('inventoryTradeModal').classList.remove('show')}
function selectWholeInventoryForTrade(){inventorySelectedAssets=new Set(currentInventoryItems.filter(function(x){return x.tradable}).map(function(x){return String(x.assetid)}));document.querySelectorAll('#inventory [data-asset]').forEach(function(box){box.checked=inventorySelectedAssets.has(box.dataset.asset);var card=box.closest('.inventory-item');if(card)card.classList.toggle('selected',box.checked)});updateInventoryTradeDialog();bindInventoryTradeRemovals()}
function submitInventoryTrade(){
 var items=selectedInventoryItems(),url=document.getElementById('inventoryTradeUrl').value;if(!items.length){toast('Выберите предметы для трейда');return}if(!url){toast('Сначала сохраните Trade URL через правый клик → Отправить трейд');return}
 var button=document.getElementById('inventoryTradeSubmit'),status=document.getElementById('inventoryTradeStatus');button.disabled=true;status.textContent='Создание трейда и автоматическое подтверждение…';
 fetch('/api/inventory/trade/'+encodeURIComponent(currentInventoryAccount.login),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({trade_url:url,appid:currentInventoryAppid,contextid:currentInventoryContext,assetids:items.map(function(x){return String(x.assetid)})})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'Трейд не отправлен');return d})}).then(function(d){status.textContent=d.message;toast(d.message);inventorySelectedAssets.clear();setTimeout(function(){closeInventoryTrade();loadRealInventory(true)},900)}).catch(function(e){status.textContent='Ошибка: '+(e.message||'Трейд не отправлен');toast(e.message||'Ошибка трейда')}).finally(function(){button.disabled=false});
}
function accountConfirmationAction(acc,action){
 if(!acc)return;var label=action==="accept"?"Подтверждение":"Отмена";toast(label+" трейдов: "+acc.login+"...");
 fetch("/api/confirmations/"+encodeURIComponent(acc.login),{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({action:action})})
 .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Операция не выполнена");return d})})
 .then(function(d){toast(d.message||"Готово")}).catch(function(e){toast(e.message||"Ошибка обработки подтверждений")});
}
var deleteAccountTarget=null;
function askDeleteAccount(acc){if(!acc)return;deleteAccountTarget=acc;document.getElementById("deleteText").textContent="Вы хотите удалить "+acc.login+"?";document.getElementById("deleteModal").classList.add("show")}
function closeDeleteAccount(){deleteAccountTarget=null;document.getElementById("deleteModal").classList.remove("show")}
function confirmDeleteAccount(){
 if(!deleteAccountTarget)return;var login=deleteAccountTarget.login,button=document.getElementById("deleteYes");button.disabled=true;
 fetch("/api/accounts/"+encodeURIComponent(login),{method:"DELETE",cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось удалить аккаунт");return d})}).then(function(d){accounts=d.accounts||[];delete checkedLogins[login];delete levelLoading[login];selectedId=null;closeDeleteAccount();renderRows(filtered());toast("Аккаунт удалён: "+login)}).catch(function(e){toast(e.message||"Ошибка удаления")}).finally(function(){button.disabled=false});
}
function openSteamProfile(login){toast("Поиск SteamID для "+login+"...");fetch("/api/profile/"+encodeURIComponent(login)+"?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||("HTTP "+r.status));return d})}).then(function(d){if(d.url){window.open(d.url,"_blank");toast("Открыт профиль: "+login)}}).catch(function(e){toast(e.message||"Не удалось открыть Steam-профиль")})}

function loadSteamPathSettings(){fetch('/api/settings/steam-path?ts='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){var input=document.getElementById('steamPathInput'),status=document.getElementById('steamPathStatus');if(input&&d.steam_path)input.value=d.steam_path;if(status){status.className='steam-path-status '+(d.valid?'success':'');status.textContent=d.valid?'steam.exe найден. Этот путь используется для запуска аккаунтов.':'Путь не проверен или steam.exe не найден. Укажите файл и нажмите «Проверить и сохранить».'}}).catch(function(){})}
function browseSteamPath(){
 var input=document.getElementById('steamPathInput'),status=document.getElementById('steamPathStatus'),button=document.getElementById('steamPathBrowseBtn');
 if(!window.pywebview||!window.pywebview.api||typeof window.pywebview.api.choose_steam_path!=='function'){status.className='steam-path-status error';status.textContent='Системный выбор файла недоступен. Перезапустите менеджер.';return}
 button.disabled=true;status.className='steam-path-status';status.textContent='Выберите папку, в которой находится steam.exe…';
 window.pywebview.api.choose_steam_path().then(function(d){
  if(!d||d.ok===false)throw new Error((d&&d.message)||'Не удалось выбрать steam.exe');
  if(d.cancelled){status.className='steam-path-status';status.textContent='Выбор файла отменён.';return null}
  input.value=d.steam_path||'';status.className='steam-path-status';status.textContent='Путь выбран. Проверка и сохранение…';
  return fetch('/api/settings/steam-path',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({steam_path:d.steam_path||''})}).then(function(r){return r.json().then(function(saved){if(!r.ok)throw new Error(saved.message||'steam.exe не найден');return saved})})
 }).then(function(saved){
  if(!saved)return;input.value=saved.steam_path||'';status.className='steam-path-status success';status.textContent=saved.message||'Путь к steam.exe сохранён.';notifyActivity(saved.message||'Путь к steam.exe сохранён','success','Steam')
 }).catch(function(e){status.className='steam-path-status error';status.textContent=e.message||'Не удалось выбрать steam.exe';notifyActivity(e.message||'Не удалось сохранить путь к steam.exe','error','Steam')}).finally(function(){button.disabled=false})
}
function saveSteamPathSettings(){var input=document.getElementById('steamPathInput'),status=document.getElementById('steamPathStatus'),button=document.getElementById('steamPathSaveBtn'),path=input.value.trim();button.disabled=true;status.className='steam-path-status';status.textContent='Проверка steam.exe…';fetch('/api/settings/steam-path',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({steam_path:path})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||'steam.exe не найден');return d})}).then(function(d){input.value=d.steam_path;status.className='steam-path-status success';status.textContent=d.message;notifyActivity(d.message,'success','Steam')}).catch(function(e){status.className='steam-path-status error';status.textContent=e.message||'steam.exe не найден';notifyActivity(e.message||'steam.exe не найден','error','Steam')}).finally(function(){button.disabled=false})}
function startLaunchQueue(){var targets=markedTargets();if(!targets.length){toast("Выберите аккаунты");return}var delay=5;notifyActivity('Запуск выделенных аккаунтов: '+targets.length+' • изолированные Steam-клиенты','info','Steam');fetch("/api/steam/queue",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({logins:targets.map(function(a){return a.login}),delay:delay})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message);toast(d.message);setTimeout(refreshRuntimeStates,800)})}).catch(function(e){toast(e.message||"Ошибка очереди")})}
function closeSelectedSteam(){var targets=markedTargets();if(!targets.length){toast("Выберите запущенные аккаунты");return}fetch("/api/steam/close-selected",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({logins:targets.map(function(a){return a.login})})}).then(function(r){return r.json().then(function(d){toast(d.message);refreshRuntimeStates()})}).catch(function(e){toast(e.message||"Ошибка закрытия")})}
var runtimeStatesRequest=null;
function updateRuntimeBadge(badge,active,activeTitle,inactiveTitle,activeLabel,inactiveLabel){
 if(!badge)return;badge.classList.toggle("online",active);badge.classList.toggle("offline",!active);badge.title=active?activeTitle:inactiveTitle;var label=badge.querySelector(".runtime-label");if(label)label.textContent=active?(activeLabel||"online"):(inactiveLabel||"offline")
}
function applyRuntimeStates(runtime){
 accounts.forEach(function(a){var state=runtime[a.login];if(!state)return;a.steam_running=!!state.steam_running;a.booster_status=state.booster_status||"idle";a.farm_status=state.farm_status||"idle"});
 document.querySelectorAll("#rows .account-row").forEach(function(row){
  var state=runtime[row.dataset.login];if(!state)return;var steamRunning=!!state.steam_running,boosterRunning=state.booster_status==="running";
  row.classList.toggle("steam-running",steamRunning);
  updateRuntimeBadge(row.querySelector(".steam-runtime-badge"),steamRunning,"Steam запущен","Steam закрыт");
  updateRuntimeBadge(row.querySelector(".booster-runtime-badge"),boosterRunning,"Booster включён","Booster выключен","booster","booster")
 })
}
function refreshRuntimeStates(){
 if(runtimeStatesRequest)return runtimeStatesRequest;
 var logins=accounts.map(function(a){return a.login}).filter(function(login){return !!login});
 if(!logins.length)return Promise.resolve();
 runtimeStatesRequest=fetch("/api/accounts/runtime?ts="+Date.now(),{method:"POST",headers:{"Content-Type":"application/json"},cache:"no-store",body:JSON.stringify({logins:logins})})
 .then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);return r.json()})
 .then(function(d){applyRuntimeStates(d.runtime||{})})
 .catch(function(){})
 .finally(function(){runtimeStatesRequest=null});
 return runtimeStatesRequest
}
function reloadAccountsAfterChange(){
 return fetch("/api/accounts?ts="+Date.now(),{cache:"no-store"}).then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);return r.json()}).then(function(d){
  accounts=d.accounts||[];var valid={};accounts.forEach(function(a){if(checkedLogins[a.login])valid[a.login]=true});checkedLogins=valid;renderRows(filtered());
  if(detailAccount){var current=accounts.find(function(a){return a.login===detailAccount.login});if(current)openAccountDetail(current)}
  return d
 })
}

function launchSteamClient(login,button){
if(!login)return;
if(button){button.classList.add("busy");button.title="Steam запускается...";button.innerHTML=actionIcon("loading");button.style.pointerEvents="none";}
toast("Запуск Steam: "+login+"...");
fetch("/api/steam/launch/"+encodeURIComponent(login),{method:"POST",cache:"no-store"})
.then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось запустить Steam");return d})})
.then(function(){pollSteamLaunch(login,button)})
.catch(function(e){if(button){button.classList.remove("busy");button.title="Запустить Steam";button.innerHTML=actionIcon("play");button.style.pointerEvents="";}toast(e.message||"Ошибка запуска Steam")});
}
function pollSteamLaunch(login,button){
fetch("/api/steam/status/"+encodeURIComponent(login)+"?ts="+Date.now(),{cache:"no-store"})
.then(function(r){return r.json()})
.then(function(d){
var state=d.status||"idle";
if(button){
button.classList.toggle("busy",state==="queued"||state==="starting"||state==="login"||state==="working");
button.classList.toggle("running",state==="running");
if(state==="running"){button.innerHTML=actionIcon("play");button.title="Steam запущен";button.style.pointerEvents="";}
else if(state==="error"){button.innerHTML=actionIcon("play");button.title="Запустить Steam";button.style.pointerEvents="";button.classList.remove("busy");button.classList.remove("running");}
else {button.innerHTML=actionIcon("loading");button.title=state==="login"?"Вход в Steam...":"Подготовка Steam...";}
}
if(state==="running"){toast("Steam запущен: "+login);return;}
if(state==="error"){toast(d.message||("Ошибка Steam: "+login));return;}
setTimeout(function(){pollSteamLaunch(login,button)},1000);
})
.catch(function(){setTimeout(function(){pollSteamLaunch(login,button)},1500)});
}
function authorizeAccount(login){
toast("Авторизация: "+login+"...");
fetch("/api/authorize/"+encodeURIComponent(login),{method:"POST",cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось запустить авторизацию");return d})}).then(function(){pollAccount(login)}).catch(function(e){toast(e.message||"Ошибка авторизации")});
}
function mergeAccountSnapshot(snapshot,redraw){
 if(!snapshot||!snapshot.login)return null;var index=accounts.findIndex(function(a){return a.login===snapshot.login});if(index<0)return null;
 var merged=Object.assign({},accounts[index],snapshot,{id:accounts[index].id});accounts[index]=merged;if(redraw)renderRows(filtered());return merged
}
function pollAccount(login){
fetch("/api/accounts/"+encodeURIComponent(login)+"/status?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"HTTP "+r.status);return d})}).then(function(d){
var a=mergeAccountSnapshot(d.account,false);if(!a)return;
if(a.auth_status==="running"){setTimeout(function(){pollAccount(login)},1200);return}
if(a.auth_status==="ok")selectedId=a.id;renderRows(filtered());
if(a.auth_status==="ok"){toast("Готово: "+login+(a.balance?" • "+a.balance:""));if(document.getElementById("gamesTopTab").classList.contains("active"))loadSelectedGames();else if(document.getElementById("statisticTab").classList.contains("active"))renderAccountInventory(a)}
else if(a.auth_status==="error"){toast(a.auth_error||("Не удалось авторизовать "+login))}
}).catch(function(){});
}
function nodeStatus(){
fetch("/api/node/status?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
var b=document.getElementById("nodeDownloadBtn");
if(!b)return;
if(d.status==="ready"){b.textContent="↓ Скачать Node.js";b.className="node-download ready";}
else if(d.status==="installing"){b.textContent="↓ Установка...";b.className="node-download installing";setTimeout(nodeStatus,1200);}
else {b.textContent="↓ Скачать Node.js";b.className="node-download";}
}).catch(function(){});
}
function installNode(){
var b=document.getElementById("nodeDownloadBtn");
if(!b)return;
b.textContent="↓ Установка...";b.className="node-download installing";b.disabled=true;
toast("Скачивание Node.js и установка зависимостей...");
fetch("/api/node/install",{method:"POST",cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось установить Node.js");return d})}).then(function(d){toast(d.message||"Node.js установлен");nodeStatus()}).catch(function(e){toast(e.message||"Ошибка установки Node.js");nodeStatus()}).finally(function(){b.disabled=false});
}

function loadAccounts(retry){retry=retry||0;fetch("/api/accounts?ts="+Date.now(),{cache:"no-store"}).then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);return r.json()}).then(function(d){accounts=d.accounts||[];selectedId=null;renderRows(filtered());if(!d.file_exists){if(retry<12)setTimeout(function(){loadAccounts(retry+1)},500);else toast("logpass.txt не найден рядом с app.py")}else if(!accounts.length){if(retry<12)setTimeout(function(){loadAccounts(retry+1)},500);else toast("В logpass.txt нет строк login:password")}}).catch(function(){if(retry<12)setTimeout(function(){loadAccounts(retry+1)},500);else{accounts=[];renderRows([]);toast("Ошибка загрузки logpass.txt")}})}

var modal=document.getElementById("importModal");
function openModal(){modal.classList.add("show");fetch("/api/project?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){document.getElementById("projectPath").textContent=d.project}).catch(function(){document.getElementById("projectPath").textContent="Не удалось определить путь"})}
function closeModal(){modal.classList.remove("show")}
function openLocal(target){fetch("/api/open/"+target+"?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){toast(d.ok?(target==="mafiles"?"Папка maFile открыта":target==="logpass"?"logpass.txt открыт":"Папка проекта открыта"):"Не удалось открыть: "+d.message)}).catch(function(){toast("Не удалось открыть выбранный путь")})}
document.getElementById("balanceSort").onclick=function(){setSort("balance")};
document.getElementById("loginSort").onclick=function(){setSort("login")};
updateSortArrows();
document.getElementById("search").addEventListener("input",function(){renderRows(filtered())});
document.getElementById("importBtn").onclick=openModal;document.getElementById("modalClose").onclick=closeModal;modal.onclick=function(e){if(e.target===modal)closeModal()};
document.getElementById("openProject").onclick=function(){openLocal("project")};document.getElementById("openMaFiles").onclick=function(){openLocal("mafiles")};document.getElementById("openLogpass").onclick=function(){openLocal("logpass")};document.getElementById("modalRefresh").onclick=function(){closeModal();refreshAccounts()};
function refreshAccounts(){var b=document.getElementById("refreshBtn");sortKey="";sortDir=0;updateSortArrows();b.textContent="↻ Загрузка...";fetch("/api/accounts?refresh=1&ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){accounts=d.accounts||[];selectedId=null;var valid={};accounts.forEach(function(a){if(checkedLogins[a.login])valid[a.login]=true});checkedLogins=valid;renderRows(filtered());toast(d.file_exists?"Список обновлён: "+accounts.length+" аккаунтов":"logpass.txt не найден")}).catch(function(){toast("Ошибка чтения logpass.txt")}).finally(function(){b.textContent="↻ Обновить"})}
var bulkRefreshPolling=false;
function refreshSelectedAccountData(){
 var chosen=accounts.filter(function(a){return isChecked(a.login)});
 if(!chosen.length){toast("Сначала выберите аккаунты галочками");return}
 var button=document.getElementById("refreshDataBtn");button.disabled=true;
 fetch("/api/accounts/refresh-data",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({logins:chosen.map(function(a){return a.login})})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Не удалось начать обновление");pollBulkRefresh()})}).catch(function(e){button.disabled=false;toast(e.message||"Ошибка обновления")});
}
function pollBulkRefresh(){
 if(bulkRefreshPolling)return;bulkRefreshPolling=true;
 function tick(){fetch("/api/accounts/refresh-data?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
  var text=d.running?("Обновление "+d.done+"/"+d.total+(d.current?": "+d.current:"")):("Готово: "+d.updated+" • ошибок: "+d.failed);
  document.getElementById("refreshDataProgress").textContent=text;
  return fetch("/api/accounts?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json()}).then(function(data){
   accounts=data.accounts||[];renderRows(filtered());
   if(detailAccount){var current=accounts.find(function(a){return a.login===detailAccount.login});if(current)openAccountDetail(current)}
   if(d.running)setTimeout(tick,2000);else{bulkRefreshPolling=false;document.getElementById("refreshDataBtn").disabled=false;toast(text)}
  })
 }).catch(function(){bulkRefreshPolling=false;document.getElementById("refreshDataBtn").disabled=false;toast("Не удалось получить прогресс обновления")})}
 tick();
}
function reloginDetailAccount(){if(!detailAccount)return;var login=detailAccount.login;closeAccountDetail();authorizeAccount(login)}
document.getElementById("refreshBtn").onclick=refreshAccounts;document.getElementById("inventorySort").onchange=function(){inventorySortMode=this.value;if(!marketLotsMode&&currentInventoryData&&currentInventoryAccount&&currentGame!=="Buy TF2")renderInventoryData(currentInventoryData,currentInventoryAccount,currentGame)};document.getElementById("inventoryRefreshBtn").onclick=function(){if(currentGame==="Buy TF2"){renderBuyTF2(true)}else if(marketLotsMode){loadMarketListings(true)}else{loadRealInventory(true)}};document.getElementById("marketLotsBtn").onclick=showMarketLots;document.getElementById("marketLotsRemoveAllBtn").onclick=removeAllMarketLots;document.getElementById("inventoryTradeBtn").onclick=openInventoryTrade;document.getElementById("inventorySelectAllBtn").onclick=toggleWholeInventorySelection;document.getElementById("inventoryTradeClose").onclick=closeInventoryTrade;document.getElementById("inventoryTradeSelectAll").onclick=selectWholeInventoryForTrade;document.getElementById("inventoryTradeSubmit").onclick=submitInventoryTrade;document.getElementById("buyTf2Close").onclick=closeBuyTf2;document.getElementById("buyTf2Refresh").onclick=refreshBuyTf2Prices;document.getElementById("buyTf2Submit").onclick=submitBuyTf2Order;document.getElementById("buyTf2Price").oninput=updateBuyTf2Total;document.getElementById("buyTf2Quantity").oninput=updateBuyTf2Total;document.getElementById("sellItemClose").onclick=closeSellItem;document.getElementById("sellItemSubmit").onclick=submitSellItem;
document.getElementById("inventorySellBtn").onclick=openInventorySellSelected;
document.getElementById("inventoryContextSell").onclick=function(){var item=inventoryContextItem;if(item&&currentInventoryAccount)openSellItem(item,currentInventoryAccount,currentInventoryAppid,currentInventoryContext)};
document.getElementById("sellItemRefresh").onclick=function(){loadSellItemOrders(true)};document.getElementById("sellItemUseSuggested").onclick=useSuggestedSellItemPrice;document.getElementById("sellItemPrice").oninput=function(){sellItemPriceDirty=true;updateSellItemNet()};document.getElementById("sellItemPrice").addEventListener('keydown',function(e){if(e.key==='Enter')submitSellItem()});
document.getElementById("authBtn").onclick=function(){
if(authQueueRunning){toast("Очередь авторизации уже выполняется");return}if(!accounts.length){toast("Нет аккаунтов для авторизации");return}
var chosen=checkedCount(),queue=chosen?accounts.filter(function(a){return isChecked(a.login)}):accounts.slice();if(!queue.length){toast("Выбранных аккаунтов нет");return}
authQueueRunning=true;var button=document.getElementById("authBtn"),index=0,progress=document.getElementById("authProgress"),progressTitle=document.getElementById("authProgressTitle"),progressPercent=document.getElementById("authProgressPercent"),progressFill=document.getElementById("authProgressFill"),progressSub=document.getElementById("authProgressSub"),progressStage=document.getElementById("authProgressStage");progress.classList.add("show");button.disabled=true;
function setProgress(done,login,stage){var pct=queue.length?Math.round(done*100/queue.length):0;progressTitle.textContent="Авторизация аккаунтов • "+done+"/"+queue.length;progressPercent.textContent=pct+"%";progressFill.style.width=pct+"%";progressSub.textContent=login||"Завершение очереди...";progressStage.textContent=stage||"Ожидание...";button.textContent="⇥ Auth "+done+"/"+queue.length}
function finishQueue(){authQueueRunning=false;button.disabled=false;button.textContent="⇥ Auth All";setProgress(queue.length,"Готово","Авторизация выбранных аккаунтов завершена");toast("Авторизация завершена: "+queue.length+" аккаунтов");setTimeout(function(){progress.classList.remove("show")},5000)}
function waitForResult(login,started,done){
 fetch("/api/accounts/"+encodeURIComponent(login)+"/status?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"HTTP "+r.status);return d})}).then(function(d){
  var a=mergeAccountSnapshot(d.account,false),elapsed=Math.round((Date.now()-started)/1000);if(!a){done(false,"Аккаунт исчез из списка");return}
  if(a.auth_status==="running"){var stage=elapsed<4?"Подключение к Steam...":elapsed<15?"Авторизация и получение профиля...":elapsed<30?"Получение баланса и аватара...":"Получение всех игр из Steam Community...";setProgress(index,login,stage+" • "+elapsed+" c");if(elapsed>=90){done(false,"Тайм-аут 90 c — аккаунт пропущен");return}setTimeout(function(){waitForResult(login,started,done)},1000);return}
  if(a.auth_status==="ok"){renderRows(filtered());done(true,"Готово: баланс и профиль получены");return}
  if(a.auth_status==="error"){renderRows(filtered());done(false,"Ошибка: "+(a.auth_error||"авторизация не удалась"));return}
  setProgress(index,login,"Сервер ещё не завершил авторизацию... • "+elapsed+" c");if(elapsed>=90){done(false,"Нет финального статуса за 90 c — аккаунт пропущен");return}setTimeout(function(){waitForResult(login,started,done)},1000)
 }).catch(function(){if(Date.now()-started>=90000){done(false,"Нет ответа сервера 90 c — аккаунт пропущен");return}setProgress(index,login,"Ожидание ответа сервера...");setTimeout(function(){waitForResult(login,started,done)},1200)})
}
function next(){if(index>=queue.length){finishQueue();return}var acc=queue[index],login=acc.login,number=index+1;setProgress(index,login,"Запуск авторизации "+number+" из "+queue.length+"...");toast("Авторизация "+number+"/"+queue.length+": "+login);var started=Date.now();fetch("/api/authorize/"+encodeURIComponent(login),{method:"POST",cache:"no-store"}).then(function(r){return r.json().then(function(d){return{ok:r.ok,data:d,status:r.status}})}).then(function(res){if(!res.ok&&res.status!==409)throw new Error(res.data.message||"Ошибка запуска");setProgress(index,login,res.status===409?"Аккаунт уже авторизуется — ожидаем его завершения...":"Авторизация запущена, ожидаем финальный статус...");waitForResult(login,started,function(success,message){if(success)setProgress(index+1,login,message);else toast(login+": "+message);index++;setTimeout(next,350)})}).catch(function(e){toast(login+": "+(e.message||"ошибка запуска"));setProgress(index+1,login,"Ошибка запуска — следующий аккаунт");index++;setTimeout(next,350)})}next()};
document.getElementById("selectAllCheck").onclick=function(){if(checkedCount()===accounts.length)clearAllAccounts();else selectAllAccounts()};
var confirmModal=document.getElementById("confirmModal"),confirmPreferredLogin="",confirmCurrentItems=[],confirmLoading=false;
function closeConfirmModal(){confirmModal.classList.remove("show")}
function openConfirmModal(login){confirmPreferredLogin=typeof login==="string"?login:"";confirmModal.classList.add("show");populateConfirmAccounts()}
function populateConfirmAccounts(){var select=document.getElementById("confirmAccountSelect");select.innerHTML="";accounts.forEach(function(a){var o=document.createElement("option");o.value=a.login;o.textContent=a.login;select.appendChild(o)});var preferred=confirmPreferredLogin||(detailAccount&&detailAccount.login)||(selectedAccount()&&selectedAccount().login);if(preferred&&accounts.some(function(a){return a.login===preferred}))select.value=preferred;loadConfirmations()}
function loadConfirmations(){
    if(confirmLoading)return Promise.resolve();
    var login=document.getElementById("confirmAccountSelect").value,box=document.getElementById("confirmList"),reload=document.getElementById("confirmReload");
    if(!login){box.innerHTML='<div class="confirm-empty">Нет аккаунтов</div>';return Promise.resolve()}
    confirmLoading=true;reload.disabled=true;reload.classList.add("loading");
    box.innerHTML='<div class="confirmation-loading"><span class="confirmation-loading-spinner"></span><div><b>Загружаем подтверждения</b><small>Получаем обе стороны и точные названия предметов…</small></div></div>';
    return fetch("/api/confirmations/"+encodeURIComponent(login)+"?ts="+Date.now(),{cache:"no-store"}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.message||"Ошибка Steam");return d})}).then(function(d){confirmCurrentItems=d.confirmations||[];renderConfirmList()}).catch(function(e){confirmCurrentItems=[];box.innerHTML='<div class="confirm-empty">'+esc(e.message||"Не удалось загрузить")+'</div>'}).finally(function(){confirmLoading=false;reload.disabled=false;reload.classList.remove("loading")})
}
function confirmationItemDisplay(name){
    var full=String(name||"Предмет"),match=full.match(/\s*\((Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred|FN|MW|FT|WW|BS)\)\s*$/i);
    if(!match)return{base:full,wear:""};
    var labels={"factory new":"FN","minimal wear":"MW","field-tested":"FT","well-worn":"WW","battle-scarred":"BS"},key=match[1].toLowerCase();
    return{base:full.slice(0,match.index),wear:labels[key]||match[1].toUpperCase()}
}
function confirmationItemGallery(images){
    if(!images.length)return '<div class="confirmation-side-empty">Ничего</div>';
    return '<div class="confirmation-item-gallery">'+images.map(function(x){
        var icon=String(x.icon||""),name=String(x.name||"Предмет"),display=confirmationItemDisplay(name);
        var wear=display.wear?'<b class="confirmation-wear wear-'+display.wear.toLowerCase()+'">'+display.wear+'</b>':'';
        return '<div class="confirmation-item-image">'+(icon?'<img loading="lazy" src="'+esc(icon)+'" alt="'+esc(name)+'" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'">':'')+'<div class="confirmation-image-empty" style="display:'+(icon?'none':'flex')+'">▣</div>'+wear+'<span title="'+esc(name)+'">'+esc(display.base)+'</span></div>'
    }).join("")+'</div>'
}
function confirmationTradeAmount(images){
    return images.reduce(function(total,item){var amount=Number(item.amount||1);return total+(isFinite(amount)&&amount>0?Math.floor(amount):1)},0)
}
function confirmationTradeRarity(item){
    var rarity=String(item.rarity||"").toLowerCase(),allowed=["consumer","industrial","milspec","restricted","classified","covert","exceedingly","contraband"];
    if(allowed.indexOf(rarity)>=0)return rarity;
    var type=String(item.type||"").toLowerCase();
    if(type.indexOf("contraband")>=0)return"contraband";
    if(type.indexOf("exceedingly rare")>=0||type.indexOf("extraordinary")>=0)return"exceedingly";
    if(/\bcovert\b|тайн(ое|ый|ая)/.test(type))return"covert";
    if(/\bclassified\b|засекреч/.test(type))return"classified";
    if(/\brestricted\b|запрещ/.test(type))return"restricted";
    if(/\bmil[ -]?spec\b|армейск/.test(type))return"milspec";
    if(/\bindustrial grade\b|промышленн/.test(type))return"industrial";
    if(/\bconsumer grade\b|\bbase grade\b|ширпотреб|базов(ый|ое|ая)/.test(type))return"consumer";
    return"unknown"
}
function confirmationTradeItems(images){
    if(!images.length)return '<div class="confirmation-side-empty">Ничего</div>';
    var rows=[];
    images.forEach(function(x){
        var amount=Number(x.amount||1),count=isFinite(amount)&&amount>1?Math.floor(amount):1;
        for(var index=0;index<count;index++)rows.push(x)
    });
    return '<div class="confirmation-trade-item-list'+(rows.length>4?' collapsed':'')+'">'+rows.map(function(x,rowIndex){
        var name=String(x.name||"Предмет"),summary=name.match(/^(\d+)\s*(items?|предмет(а|ов)?)$/i);
        if(summary)name='Названия не получены';
        var rarity=confirmationTradeRarity(x),type=String(x.type||""),icon=String(x.icon||"");
        var thumb=icon?'<img class="confirmation-trade-item-thumb" loading="lazy" src="'+esc(icon)+'" alt="" onerror="this.style.display=\'none\'">':'';
        return '<div class="confirmation-trade-item rarity-'+rarity+'" title="'+esc(name+(type?' • '+type:''))+'"><span class="confirmation-trade-item-index">'+(rowIndex+1)+'</span>'+thumb+'<span class="confirmation-trade-item-name">'+esc(name)+'</span></div>'
    }).join("")+'</div>'
}
function confirmationTradeSide(kind,title,images){
    var total=confirmationTradeAmount(images),remaining=Math.max(0,total-4);
    var expander=remaining?'<button type="button" class="confirmation-trade-expand" data-remaining="'+remaining+'" aria-expanded="false"><span class="confirmation-trade-expand-label">Ещё '+remaining+'</span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg></button>':'';
    return '<div class="confirmation-trade-side '+kind+'"><div class="confirmation-side-title"><span>'+title+'</span><b>'+total+'</b></div>'+confirmationTradeItems(images)+expander+'</div>'
}
function bindConfirmationTradeExpanders(card){
    card.querySelectorAll(".confirmation-trade-expand").forEach(function(button){
        button.onclick=function(){
            var side=button.closest(".confirmation-trade-side"),list=side.querySelector(".confirmation-trade-item-list"),expanded=!button.classList.contains("expanded");
            button.classList.toggle("expanded",expanded);side.classList.toggle("expanded",expanded);list.classList.toggle("collapsed",!expanded);
            button.setAttribute("aria-expanded",expanded?"true":"false");
            button.querySelector(".confirmation-trade-expand-label").textContent=expanded?"Свернуть":"Ещё "+button.dataset.remaining
        }
    })
}
function confirmationFallbackText(value){
    var text=String(value||""),match=text.match(/^You will give up(?:\s+your)?\s+(.+)$/i);
    if(match)return 'Вы передаёте: '+match[1];
    match=text.match(/^For their:\s*(.+)$/i);
    if(match)return 'Вы получаете: '+match[1];
    match=text.match(/^You will receive(?:\s+their)?\s+(.+)$/i);
    return match?'Вы получаете: '+match[1]:text
}
function renderConfirmList(){
    var box=document.getElementById("confirmList");box.innerHTML="";
    if(!confirmCurrentItems.length){box.innerHTML='<div class="confirm-empty">Нет ожидающих трейдов или операций Market</div>';return}
    confirmCurrentItems.forEach(function(item){
        var incoming=item.kind==="trade"&&item.incoming_only===true,card=document.createElement("div");
        card.className="confirmation-card "+(item.kind==="trade"?"trade-confirmation":"market-confirmation")+(incoming?" incoming-only":"");
        var date=item.created?new Date(item.created*1000).toLocaleString():"—",images=item.item_images||[];
        if(!images.length&&item.kind==="market"&&item.icon)images=[{name:(item.items||[])[0]||"Предмет",icon:item.icon}];
        var outgoing=item.outgoing_items||[],receiving=item.incoming_items||[],hasTradeSides=item.kind==="trade"&&(outgoing.length>0||receiving.length>0);
        var items;
        if(hasTradeSides){
            items='<div class="confirmation-trade-sides">'+confirmationTradeSide('outgoing','↑ Вы передаёте',outgoing)+confirmationTradeSide('incoming','↓ Вы получаете',receiving)+'</div>'
        }else if(images.length){
            items=confirmationItemGallery(images)
        }else{
            items='<div class="confirmation-items">'+(item.items||[]).map(function(x){return '<div class="confirmation-item">'+esc(confirmationFallbackText(x))+'</div>'}).join("")+'</div>'
        }
        var count=hasTradeSides?confirmationTradeAmount(outgoing)+confirmationTradeAmount(receiving):Number(item.items_count||0);
        var direction=incoming?'Вам отправляют предметы • вы ничего не отдаёте':item.outgoing_only===true?'Вы отправляете предметы • ничего не получаете':item.kind==='trade'?'Сверьте предметы в обеих сторонах предложения':'Операция Steam Community Market • предметов: '+count;
        var sender='<div class="confirmation-sender">'+(item.avatar?'<img class="confirmation-avatar" src="'+esc(item.avatar)+'" alt="">':'')+'<div><div class="confirmation-recipient" title="'+esc(item.recipient||"Steam")+'">'+esc(item.recipient||"Steam")+'</div><div class="confirmation-direction">'+direction+'</div></div></div>';
        var countHtml=item.kind==='trade'?'<div class="confirmation-count">Всего предметов: '+count+'</div>':'';
        card.innerHTML='<div class="confirmation-top"><span class="confirmation-kind '+esc(incoming?"incoming":item.kind)+'">'+esc(incoming?"Входящий • только получение":item.kind==="trade"?"Трейд":"Market")+'</span><span class="confirmation-date">'+esc(date)+'</span></div>'+sender+countHtml+items+'<div class="confirmation-actions"><button class="confirmation-reject">✕ Отклонить</button><button class="confirmation-accept">✓ Принять</button></div>';
        bindConfirmationTradeExpanders(card);
        card.querySelector(".confirmation-accept").onclick=function(){respondConfirmations([item.id],"accept")};
        card.querySelector(".confirmation-reject").onclick=function(){respondConfirmations([item.id],"cancel")};
        box.appendChild(card)
    })
}
async function respondConfirmations(ids,action){var login=document.getElementById("confirmAccountSelect").value;if(!login||!ids.length)return;var buttons=confirmModal.querySelectorAll("button");buttons.forEach(function(b){b.disabled=true});try{var r=await fetch("/api/confirmations/"+encodeURIComponent(login),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:action,confirmation_ids:ids})}),d=await r.json();if(!r.ok)throw new Error(d.message||"Steam отклонил операцию");toast(d.message||"Готово");await loadConfirmations()}catch(e){toast(e.message||"Ошибка подтверждения")}finally{buttons.forEach(function(b){b.disabled=false})}}
function respondAllConfirmations(action){var ids=confirmCurrentItems.map(function(x){return x.id}).filter(Boolean);if(!ids.length){toast("Нет ожидающих операций");return}respondConfirmations(ids,action)}
document.getElementById("confirmClose").onclick=closeConfirmModal;document.getElementById("confirmClose2").onclick=closeConfirmModal;confirmModal.onclick=function(e){if(e.target===this)closeConfirmModal()};document.getElementById("confirmReload").onclick=loadConfirmations;document.getElementById("confirmAccountSelect").onchange=loadConfirmations;document.getElementById("confirmAcceptAll").onclick=function(){respondAllConfirmations("accept")};document.getElementById("confirmRejectAll").onclick=function(){respondAllConfirmations("cancel")};document.getElementById("guardConfirmBtn").onclick=function(){openConfirmModal(detailAccount?detailAccount.login:"")};
document.getElementById("historyBtn").onclick=openHistory;document.getElementById("historyClose").onclick=closeHistory;document.getElementById("historyModal").onclick=function(e){if(e.target===this)closeHistory()};document.getElementById("historyRefresh").onclick=loadHistory;document.getElementById("historyCopy").onclick=copyHistory;document.getElementById("historyClear").onclick=clearHistory;
document.getElementById("nodeDownloadBtn").onclick=installNode;
document.getElementById("autoSessionToggle").onchange=changeAutoSession;document.getElementById("sessionReloadCancel").onclick=cancelAutoSession;
document.getElementById("boosterFunctionalBtn").onclick=openBoosterModal;document.getElementById("boosterClose").onclick=closeBoosterModal;document.getElementById("boosterStartSelected").onclick=startBooster;document.getElementById("boosterApplyAll").onclick=applyBoosterSettingsToAll;document.getElementById("boosterStopSelected").onclick=stopBoosterSelected;document.getElementById("boosterModal").onclick=function(e){if(e.target===this)closeBoosterModal()};document.getElementById("accountBoosterClose").onclick=closeAccountBoosterModal;document.getElementById("accountBoosterSave").onclick=saveAccountBooster;document.getElementById("accountBoosterModal").onclick=function(e){if(e.target===this)closeAccountBoosterModal()};
document.getElementById("statisticTab").onclick=function(){showTopPage("statistic")};
document.getElementById("functionalTab").onclick=function(){showTopPage("functional");loadSteamPathSettings()};
document.getElementById("gamesTopTab").onclick=function(){showTopPage("games")};
document.getElementById("addGameBtn").onclick=addGameToSelected;document.getElementById("addGamesAllBtn").onclick=openAddGamesAllModal;document.getElementById("addGamesAllClose").onclick=closeAddGamesAllModal;document.getElementById("addGamesAllStart").onclick=startAddGamesAll;document.getElementById("addGamesAllStop").onclick=stopAddGamesAll;document.getElementById("addGamesAllModal").onclick=function(e){if(e.target===this)closeAddGamesAllModal()};document.getElementById("addGamesAllTarget").addEventListener('keydown',function(e){if(e.key==='Enter')startAddGamesAll()});
document.getElementById("refreshGamesBtn").onclick=loadSelectedGames;document.getElementById("farmCardsBtn").onclick=toggleCardFarm;
document.getElementById("gameTargetInput").addEventListener("keydown",function(e){if(e.key==="Enter")addGameToSelected()});
document.getElementById("closeAllSteamBtn").onclick=closeAllSteam;
document.getElementById("markedBtn").onclick=toggleMarkedAccounts;
document.getElementById("getLevelBtn").onclick=getSelectedLevels;
document.getElementById("launchSelectedSteamBtn").onclick=startLaunchQueue;document.getElementById("closeSelectedSteamBtn").onclick=closeSelectedSteam;document.getElementById("steamPathBrowseBtn").onclick=browseSteamPath;document.getElementById("steamPathSaveBtn").onclick=saveSteamPathSettings;document.getElementById("steamPathInput").addEventListener('keydown',function(e){if(e.key==='Enter')saveSteamPathSettings()});document.getElementById("accountHistoryBtn").onclick=openAccountHistory;setInterval(refreshRuntimeStates,5000);
document.getElementById("checkVacBtn").onclick=checkVacBans;document.getElementById("vacClose").onclick=closeVacCheck;document.getElementById("vacModal").onclick=function(e){if(e.target===this)closeVacCheck()};document.getElementById("vacSaveKey").onclick=saveVacKey;document.getElementById("vacGetKey").onclick=function(){window.open("https://steamcommunity.com/dev/apikey","_blank")};document.getElementById("levelSort").onclick=function(){setMetricSort("level")};document.getElementById("xpSort").onclick=function(){setMetricSort("xp")};
document.getElementById("deleteNo").onclick=closeDeleteAccount;document.getElementById("deleteYes").onclick=confirmDeleteAccount;document.getElementById("deleteModal").onclick=function(e){if(e.target===this)closeDeleteAccount()};
document.getElementById("tradeClose").onclick=closeTradeDialog;document.getElementById("tradeCancel").onclick=closeTradeDialog;document.getElementById("tradeOpen").onclick=openRealTrade;document.getElementById("tradePinBtn").onclick=pinTradeLink;document.getElementById("tradePasteBtn").onclick=pasteSavedTradeLink;
document.getElementById("tradeModal").onclick=function(e){if(e.target===this)closeTradeDialog()};
document.getElementById("tradeLinkInput").addEventListener("keydown",function(e){if(e.key==="Enter")openRealTrade()});
document.getElementById("inventoryTab").onclick=function(){
  closeAccountDetail();
  document.getElementById("inventoryTab").classList.add("active");
};document.getElementById("craftTab").onclick=openTheme;
document.querySelectorAll(".game").forEach(function(b){b.onclick=function(){renderGame(this.dataset.game)}});

document.getElementById("sendTradeContext").onclick=function(){if(contextAccount)openTradeDialog(contextAccount)};document.getElementById("securityContext").onclick=function(){if(contextAccount)openAccountDetail(contextAccount);closeContextMenu()};document.getElementById("detailBack").onclick=closeAccountDetail;document.getElementById("reloginBtn").onclick=reloginDetailAccount;document.getElementById("guardCircle").onclick=function(){copyGuardCode()};document.getElementById("copyLoginBtn").onclick=function(){copyCredential("login")};document.getElementById("copyPasswordBtn").onclick=function(){copyCredential("password")};
document.getElementById("tradeBanCalendarBtn").onclick=openTradeBanCalendar;document.getElementById("tradeBanCalendarClose").onclick=closeTradeBanCalendar;document.getElementById("tradeBanCalendarModal").onclick=function(e){if(e.target===this)closeTradeBanCalendar()};document.getElementById("calendarGame").onchange=renderTradeBanCalendar;document.getElementById("calendarLoadBtn").onclick=loadTradeBanCalendar;document.getElementById("calendarSelectAll").onclick=selectCalendarLocked;document.getElementById("calendarSelectUnlocked").onclick=selectCalendarUnlocked;document.getElementById("calendarActiveTab").onclick=function(){setCalendarView('active')};document.getElementById("calendarHistoryTab").onclick=function(){setCalendarView('history')};
document.getElementById("bulkTradeBtn").onclick=openBulkTrade;document.getElementById("bulkTradeClose").onclick=closeBulkTrade;document.getElementById("bulkTradeModal").onclick=function(e){if(e.target===this)closeBulkTrade()};document.getElementById("bulkTradeSaved").onchange=function(){if(this.value)document.getElementById('bulkTradeUrl').value=this.value};document.getElementById("bulkTradeStart").onclick=startBulkTrade;document.getElementById("bulkTradeStop").onclick=stopBulkTrade;
document.getElementById("itemCollectorBtn").onclick=openItemCollector;document.getElementById("itemCollectorClose").onclick=closeItemCollector;document.getElementById("itemCollectorModal").onclick=function(e){if(e.target===this)closeItemCollector()};document.getElementById("collectorSaved").onchange=function(){if(this.value)document.getElementById('collectorUrl').value=this.value};document.getElementById("collectorLoad").onclick=loadCollectorItems;document.getElementById("collectorToggleAll").onclick=toggleCollectorAll;document.getElementById("collectorStart").onclick=startCollector;document.getElementById("collectorStop").onclick=stopCollector;document.getElementById("collectorQuery").addEventListener('keydown',function(e){if(e.key==='Enter')loadCollectorItems()});
document.getElementById("bulkSellBtn").onclick=openBulkSell;document.getElementById("bulkSellClose").onclick=closeBulkSell;document.getElementById("bulkSellModal").onclick=function(e){if(e.target===this)closeBulkSell()};document.getElementById("bulkSellLoad").onclick=loadBulkSellItems;document.getElementById("bulkSellQuote").onclick=calculateBulkSellPrices;document.getElementById("bulkSellRefresh").onclick=calculateBulkSellPrices;document.getElementById("bulkSellToggleAll").onclick=toggleBulkSellAll;document.getElementById("bulkSellStart").onclick=startBulkSell;document.getElementById("bulkSellStop").onclick=stopBulkSell;document.getElementById("bulkSellQuery").addEventListener('keydown',function(e){if(e.key==='Enter')loadBulkSellItems()});
document.getElementById("themeClose").onclick=closeTheme;document.getElementById("themeClose2").onclick=closeTheme;document.getElementById("themeApply").onclick=function(){applyTheme(readThemeInputs(),true);closeTheme();toast("Оформление сохранено")};document.getElementById("themeReset").onclick=function(){applyTheme(themeDefaults,false);updateThemeInputs(themeDefaults)};document.getElementById("themeRandom").onclick=generateRandomTheme;document.getElementById("themeModal").onclick=function(e){if(e.target===this)closeTheme()};document.querySelectorAll(".theme-preset").forEach(function(b){b.onclick=function(){var t=themePresets[this.dataset.theme];if(t){applyTheme(t,false);updateThemeInputs(t);this.classList.add("active")}}});
document.addEventListener("click",function(e){var m=document.getElementById("accountContextMenu");if(!m.contains(e.target))closeContextMenu();var inventoryMenu=document.getElementById("inventoryContextMenu");if(!inventoryMenu.contains(e.target))closeInventoryContextMenu()});
document.addEventListener("contextmenu",function(e){if(!e.target.closest('.inventory-item')&&!e.target.closest('#inventoryContextMenu'))closeInventoryContextMenu()});
document.addEventListener("keydown",function(e){if(e.key==='Escape')closeInventoryContextMenu()});
document.addEventListener("keydown",function(e){if(e.key==="Escape"){closeContextMenu();closeModal();closeHistory();closeTheme();closeConfirmModal();closeTradeDialog();closeDeleteAccount();closeTradeBanCalendar();closeBulkTrade();closeItemCollector();closeBulkSell()}});
loadTheme();renderGame("CS2");initGamesSearch();showTopPage("statistic");nodeStatus();startAutoSessionPolling();loadSteamPathSettings();startBoosterQueuePolling();startGamesAllPolling();
// Автозагрузка аккаунтов при открытии: первый запрос сразу после построения DOM, затем повторные попытки.
loadAccounts(0);
var startupAccountRetry=0;
var startupAccountTimer=setInterval(function(){
  if(accounts.length || startupAccountRetry>=20){clearInterval(startupAccountTimer);return;}
  startupAccountRetry++;
  loadAccounts(startupAccountRetry);
},500);
</script>
</body>
</html>
"""


AUTH_STATE = load_account_cache()
AUTH_LOCK = threading.Lock()
if not isinstance(AUTH_STATE, dict):
    AUTH_STATE = {}
# A cached "running" state may come from a previous app crash/restart.
# Only this in-memory set represents authorizations that are actually running now.
ACTIVE_AUTH = set()
with AUTH_LOCK:
    for _login, _state in AUTH_STATE.items():
        if isinstance(_state, dict) and _state.get("auth_status") == "running":
            _state["auth_status"] = "idle"
            _state["auth_error"] = ""
AVATARS_DIR = BASE_DIR / "avatars"
AUTH_HELPER = BASE_DIR / "_shark_steam_auth.js"
NODE_DIR = BASE_DIR / "nodejs"
NODE_EXE = NODE_DIR / "node.exe"
NPM_CMD = NODE_DIR / "npm.cmd"
NPM_CLI = NODE_DIR / "node_modules" / "npm" / "bin" / "npm-cli.js"
NODE_VERSION = "v24.21.0"
NODE_ZIP_URL = f"https://nodejs.org/dist/{NODE_VERSION}/node-{NODE_VERSION}-win-x64.zip"
NODE_ZIP_FILE = BASE_DIR / f"node-{NODE_VERSION}-win-x64.zip"
NODE_INSTALL_LOCK = threading.Lock()
NODE_INSTALL_STATE = {"status": "ready" if NODE_EXE.exists() else "not_installed", "message": ""}

STEAM_AUTH_HELPER = r"""
const SteamUser = require('steam-user');
const SteamTotp = require('steam-totp');
const https = require('https');

const login = process.env.SHARK_STEAM_LOGIN || '';
const password = process.env.SHARK_STEAM_PASSWORD || '';
const sharedSecret = process.env.SHARK_STEAM_SHARED_SECRET || '';
const steamId = process.env.SHARK_STEAM_ID || '';
const refreshToken = process.env.SHARK_STEAM_REFRESH_TOKEN || '';

function out(obj) {
    try { process.stdout.write(JSON.stringify(obj) + '\n'); } catch (_) {}
}
function log(level, message) { out({type:'log', level, message:String(message || '')}); }
function fail(message) { finish({ok:false,error:String(message || 'Unknown error')}); }

if (!login || !steamId || (!refreshToken && (!password || !sharedSecret))) {
    fail('Missing Steam authorization data');
    process.exit(2);
}

const client = new SteamUser({enablePicsCache:true, renewRefreshTokens:false});
let finished = false;
let webCookies = [];
let walletState = null;
let webSessionReceived = false;
let walletEventReceived = false;
let webSessionProcessing = false;
let latestRefreshToken = refreshToken || '';

client.on('refreshToken', token => {
    if (token) latestRefreshToken = String(token);
    log('INFO', 'Steam refresh token received/renewed');
});

const CURRENCY = {
    1:'USD',2:'GBP',3:'EUR',4:'CHF',5:'RUB',6:'PLN',7:'BRL',8:'JPY',9:'NOK',10:'IDR',
    11:'MYR',12:'PHP',13:'SGD',14:'THB',15:'VND',16:'KRW',17:'TRY',18:'UAH',19:'MXN',
    20:'CAD',21:'AUD',22:'NZD',23:'CNY',24:'INR',25:'CLP',26:'PEN',27:'COP',28:'ZAR',
    29:'HKD',30:'TWD',31:'SAR',32:'AED',33:'SEK',34:'ARS',35:'ILS',36:'BYN',37:'KZT',
    38:'KWD',39:'QAR',40:'CRC',41:'UYU',42:'BGN',43:'HRK',44:'CZK',45:'DKK',46:'HUF',47:'RON'
};
const SYMBOL = {
    USD:'$',GBP:'£',EUR:'€',CHF:'CHF ',RUB:'₽',PLN:'zł',BRL:'R$',JPY:'¥',NOK:'kr',IDR:'Rp',
    MYR:'RM',PHP:'₱',SGD:'S$',THB:'฿',VND:'₫',KRW:'₩',TRY:'₺',UAH:'₴',MXN:'MX$',CAD:'C$',
    AUD:'A$',NZD:'NZ$',CNY:'¥',INR:'₹',CLP:'CLP',PEN:'S/',COP:'COP',ZAR:'R',HKD:'HK$',TWD:'NT$',
    SAR:'﷼',AED:'د.إ',SEK:'kr',ARS:'AR$',ILS:'₪',BYN:'Br',KZT:'₸',KWD:'د.ك',QAR:'﷼',CRC:'₡',
    UYU:'$U',BGN:'лв',HRK:'kn',CZK:'Kč',DKK:'kr',HUF:'Ft',RON:'lei'
};

function currencyCode(value) {
    if (typeof value === 'string' && /^[A-Za-z]{3}$/.test(value.trim())) return value.trim().toUpperCase();
    return CURRENCY[Number(value)] || String(value || '').trim().toUpperCase();
}
function formatWallet(balance, currency, alreadyMajor=false) {
    const code = currencyCode(currency);
    const n = Number(balance);
    if (!Number.isFinite(n)) return '';

    // g_rgWalletInfo.wallet_balance is in the smallest unit (e.g. cents).
    // The steam-user `wallet` event, however, already exposes the balance
    // divided by 100. Never divide an event balance twice.
    const amount = alreadyMajor ? n : (n / 100);
    let text = amount.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
    text = text.replace(/\.00$/, '');

    // Keep the stored value ASCII-safe and let the browser render the native
    // symbol. This avoids Windows console/code-page corruption of symbols
    // such as ₸, ₽, ₴ and ₩.
    return text + (code ? ' ' + code : '');
}

function finish(result) {
    if (finished) return;
    finished = true;
    try { client.logOff(); } catch (_) {}
    out(result);
    setTimeout(() => process.exit(result.ok ? 0 : 1), 250);
}

function fetchUrl(url, headers = {}, redirectDepth = 0) {
    return new Promise((resolve) => {
        log('INFO', 'GET ' + url);
        const req = https.get(url, {
            timeout: 15000,
            headers: Object.assign({
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/154.0 Safari/537.36',
                'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language':'en-US,en;q=0.9'
            }, headers)
        }, (res) => {
            const status = res.statusCode || 0;
            log(status >= 400 ? 'WARN' : 'INFO', 'Steam HTTP ' + status + ' for ' + url);

            if ([301,302,303,307,308].includes(status) && res.headers.location && redirectDepth < 5) {
                const nextUrl = new URL(res.headers.location, url).toString();
                log('INFO', 'Following Steam redirect to ' + nextUrl);
                res.resume();
                fetchUrl(nextUrl, headers, redirectDepth + 1).then(resolve);
                return;
            }

            if (!res || status >= 400) {
                if (res) res.resume();
                resolve({html:'',status,headers:res ? res.headers : {}});
                return;
            }

            let body = '';
            res.setEncoding('utf8');
            res.on('data', c => body += c);
            res.on('end', () => {
                log('INFO', 'Received ' + body.length + ' bytes from ' + url);
                resolve({html:body,status,headers:res.headers});
            });
        });
        req.on('error', e => { log('ERROR', 'HTTP request failed: ' + (e.message || e)); resolve({html:'',status:0,error:String(e.message || e)}); });
        req.on('timeout', () => { req.destroy(); log('ERROR', 'HTTP timeout: ' + url); resolve({html:'',status:0,error:'timeout'}); });
    });
}

function cookieHeader() { return webCookies.join('; '); }

function extractLevelXp(html) {
    const source = String(html || '');
    const rankMatch = source.match(/CS:GO Profile Rank:\s*([^\n<]+)/i);
    const xpMatch = source.match(/Experience points earned towards next rank:\s*([^\n<]+)/i);
    if (rankMatch && xpMatch) {
        const level = Number(rankMatch[1].trim().replace(/[,\s]/g, ''));
        const xp = Number(xpMatch[1].trim().replace(/,/g, '').split(/\s+/)[0]);
        if (Number.isInteger(level) && level >= 0 && Number.isInteger(xp) && xp >= 0) return {level, xp};
    }
    const rankJson = source.match(/"profile_rank"\s*:\s*(\d+)/i);
    if (rankJson) {
        const level = Number(rankJson[1]);
        if (Number.isInteger(level) && level >= 0) return {level, xp:0};
    }
    return {level:null, xp:null};
}

function extractCardGames(html) {
    const source=String(html||''), rows=source.split(/<div class="badge_row is_link/gi).slice(1), result=[];
    function clean(v){return String(v||'').replace(/<[^>]*>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/\s+/g,' ').replace(/View details/gi,'').trim();}
    for(const row of rows){
        const link=row.match(/gamecards\/(\d+)/i);
        const remaining=row.match(/(\d+)\s+card drops?\s+remaining/i);
        if(!link||!remaining)continue;
        const count=Number(remaining[1]);if(!Number.isInteger(count)||count<=0)continue;
        const title=row.match(/<div class="badge_title">([\s\S]*?)<\/div>/i);
        result.push({appid:Number(link[1]),name:clean(title?title[1]:'')||('App '+link[1]),cards_remaining:count});
    }
    return result;
}

function extractAvatar(html) {
    const m = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
        || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    return m ? m[1].replace(/&amp;/g, '&') : '';
}

function extractWalletFromHtml(html) {
    if (typeof html !== 'string' || !html.trim()) return {formatted:'', currency:'', country:'', source:'', rawBalance:null};

    // Steam commonly exposes the wallet as:
    // var g_rgWalletInfo = {"wallet_currency":1,"wallet_country":"US","wallet_balance":"52",...};
    // It may also be declared with const/let or split across whitespace/newlines.
    const walletPatterns = [
        /(?:var|let|const)\s+g_rgWalletInfo\s*=\s*(\{[\s\S]*?\})\s*;/i,
        /g_rgWalletInfo\s*=\s*(\{[\s\S]*?\})\s*;/i
    ];

    for (const re of walletPatterns) {
        const m = html.match(re);
        if (!m) continue;
        try {
            const obj = JSON.parse(m[1]);
            const rawBalance = obj.wallet_balance ?? obj.wallet_delayed_balance ?? null;
            const numericBalance = Number(rawBalance);
            const cur = currencyCode(obj.wallet_currency);
            const country = String(obj.wallet_country || '');

            log('INFO', 'Parsed g_rgWalletInfo: currency=' + cur + ', country=' + country + ', rawBalance=' + String(rawBalance));

            if (Number.isFinite(numericBalance)) {
                const formatted = formatWallet(numericBalance, cur);
                if (formatted) {
                    return {formatted, currency:cur, country, source:'g_rgWalletInfo', rawBalance:numericBalance};
                }
            }
        } catch (e) {
            log('WARN', 'g_rgWalletInfo JSON parse failed: ' + String(e.message || e));
        }
    }

    const visibleWalletPatterns = [
        /id=["'](?:marketWalletBalanceAmount|header_wallet_balance)["'][^>]*>([\s\S]*?)<\/[^>]+>/i
    ];
    for (const re of visibleWalletPatterns) {
        const m = html.match(re);
        if (!m) continue;
        const text = m[1].replace(/<[^>]+>/g,' ')
            .replace(/&nbsp;/gi,' ').replace(/&amp;/g,'&')
            .replace(/&#36;/g,'$').replace(/&#8364;/g,'€').replace(/&#163;/g,'£')
            .replace(/&#82;/g,'R').replace(/\s+/g,' ').trim();
        const money = text.match(/(?:R\$|[$€£¥₽₴₸₩₹]|zł|CHF|kr|C\$|A\$|NZ\$|MX\$|S\$|₱|฿|₫|₺)\s*[+-]?\d+(?:[.,]\d{1,2})?(?:\s*(?:USD|EUR|GBP|CHF|RUB|PLN|BRL|JPY|NOK|SEK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|KZT|DKK|CZK|HUF|RON|ISK))?/i);
        if (money) return {formatted:money[0].replace(/\s+/g,' ').trim(),currency:'',country:'',source:'visible-wallet',rawBalance:null};
    }

    const clean = html
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&')
        .replace(/&#36;/g, '$').replace(/&#8364;/g, '€').replace(/&#163;/g, '£')
        .replace(/\s+/g, ' ').trim();

    const marker = clean.match(/(?:Баланс\s+кошелька|Wallet\s+Balance|Steam\s+Wallet|Current\s+balance|Wallet)/i);
    const scope = marker && marker.index !== undefined ? clean.slice(marker.index, marker.index + 500) : clean;
    const money = /(?:[$€£¥₽₴₸₩₹]|(?:USD|EUR|GBP|CHF|RUB|PLN|BRL|JPY|NOK|SEK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|KZT|DKK|CZK|HUF|RON|ISK)\b)\s*[+-]?\s*\d+(?:[.,]\d{1,2})?\s*(?:USD|EUR|GBP|CHF|RUB|PLN|BRL|JPY|NOK|SEK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|KZT|DKK|CZK|HUF|RON|ISK)?/i;
    const match = scope.match(money);
    if (match) return {formatted:match[0].replace(/\s+/g,' ').trim(), currency:'', country:'', source:'page-text', rawBalance:null};
    return {formatted:'', currency:'', country:'', source:'', rawBalance:null};
}

function decodeHtml(value) {
    return String(value || '')
        .replace(/<br\s*\/?>/gi, ' ')
        .replace(/<[^>]*>/g, ' ')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
        .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
        .replace(/&#(\d+);/g, (_, n) => { try { return String.fromCodePoint(Number(n)); } catch (_) { return ''; } })
        .replace(/&#x([0-9a-f]+);/gi, (_, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch (_) { return ''; } })
        .replace(/\s+/g, ' ').trim();
}
function parseMinutes(text) {
    const s = decodeHtml(text).toLowerCase(); let total = 0;
    const h = s.match(/([\d.,]+)\s*(?:hrs?|hours?)/i); const m = s.match(/([\d.,]+)\s*(?:mins?|minutes?)/i);
    if (h) total += parseFloat(h[1].replace(',', '.')) * 60; if (m) total += parseFloat(m[1].replace(',', '.'));
    return Number.isFinite(total) ? Math.round(total) : 0;
}
function extractBalancedJson(source, marker) {
    const text = String(source || '');
    const start = text.indexOf(marker);
    if (start < 0) return null;
    let i = start + marker.length;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text[i] !== '[' && text[i] !== '{') return null;
    const open = text[i], close = open === '[' ? ']' : '}';
    let depth = 0, quote = false, escape = false;
    for (; i < text.length; i++) {
        const ch = text[i];
        if (quote) {
            if (escape) escape = false;
            else if (ch === '\\') escape = true;
            else if (ch === '"') quote = false;
            continue;
        }
        if (ch === '"') { quote = true; continue; }
        if (ch === open) depth++;
        else if (ch === close) {
            depth--;
            if (depth === 0) return text.slice(start + marker.length, i + 1).trim();
        }
    }
    return null;
}
function normalizeCommunityGame(g) {
    const appid = Number(g.appid ?? g.appID ?? g.appId ?? g.id ?? 0);
    if (!Number.isInteger(appid) || appid <= 0) return null;
    const name = decodeHtml(g.name || g.title || '') || `App ${appid}`;
    let minutes = NaN;
    const minuteValue = g.playtime_forever ?? g.playtimeForever ?? g.playtime_minutes;
    if (minuteValue !== undefined && minuteValue !== null && minuteValue !== '') minutes = Number(minuteValue);
    if (!Number.isFinite(minutes)) {
        const hourValue = g.hoursOnRecord ?? g.hours_forever ?? g.hoursForever ?? g.hours_played ?? g.hours;
        if (hourValue !== undefined && hourValue !== null && hourValue !== '') { const n = Number(hourValue); if (Number.isFinite(n)) minutes = n * 60; }
    }
    if (!Number.isFinite(minutes) && typeof g.playtime === 'string') {
        const pm = g.playtime.replace(',', '.').match(/([\d.]+)\s*(hours?|hrs?|h|minutes?|mins?|m)?/i);
        if (pm) { const n = Number(pm[1]); minutes = /^(hours?|hrs?|h)$/i.test(pm[2] || '') ? n * 60 : n; }
    }
    if (!Number.isFinite(minutes)) minutes = 0;
    let icon = g.img_icon_url || g.icon || g.logo || g.img || '';
    let logo = g.img_logo_url || g.logo_url || '';
    if (icon && !/^https?:\/\//i.test(icon) && !/^\/\//.test(icon)) icon = `https://media.steampowered.com/steamcommunity/public/images/apps/${appid}/${icon}.jpg`;
    if (logo && !/^https?:\/\//i.test(logo) && !/^\/\//.test(logo)) logo = `https://media.steampowered.com/steamcommunity/public/images/apps/${appid}/${logo}.jpg`;
    if (icon && /^\/\//.test(icon)) icon = 'https:' + icon;
    if (icon && /^\//.test(icon)) icon = 'https://steamcommunity.com' + icon;
    if (logo && /^\/\//.test(logo)) logo = 'https:' + logo;
    if (logo && /^\//.test(logo)) logo = 'https://steamcommunity.com' + logo;
    return {appid,name,playtime_forever:Math.round(minutes),playtime_2weeks:g.playtime_2weeks == null ? null : Number(g.playtime_2weeks),img_icon_url:icon,img_logo_url:logo,rtime_last_played:Number(g.rtime_last_played || 0)};
}

function parseEmbeddedGameData(html) {
    const source = String(html || '');
    const markers = ['var g_rgGameData =', 'var g_rgGameData=', 'g_rgGameData ='];
    let raw = null;
    for (const marker of markers) { raw = extractBalancedJson(source, marker); if (raw) break; }
    if (!raw) return [];
    try {
        const data = JSON.parse(raw);
        const arr = Array.isArray(data) ? data : Object.entries(data || {}).map(([key, value]) => ({...(value || {}), appid: value?.appid ?? value?.appID ?? key}));
        return arr.map(normalizeCommunityGame).filter(Boolean);
    } catch (e) {
        log('WARN', 'g_rgGameData JSON parse failed: ' + String(e.message || e));
        return [];
    }
}

function parseRgGames(html) {
    const raw = extractBalancedJson(String(html || ''), 'var rgGames =');
    if (!raw) return [];
    try {
        const data = JSON.parse(raw);
        const arr = Array.isArray(data) ? data : Object.values(data || {});
        return arr.map(normalizeCommunityGame).filter(Boolean);
    } catch (_) { return []; }
}
function parseCommunityXml(xml) {
    const source = String(xml || ''), games = new Map();
    const re = /<game>([\s\S]*?)<\/game>/gi; let m;
    const tag = (block, name) => { const x = block.match(new RegExp(`<${name}[^>]*>([\s\S]*?)<\/${name}>`, 'i')); return x ? decodeHtml(x[1]) : ''; };
    while ((m = re.exec(source)) !== null) {
        const block = m[1], appid = Number(tag(block, 'appID'));
        if (!Number.isInteger(appid) || appid <= 0) continue;
        const hours = Number(tag(block, 'hoursOnRecord'));
        const mins = Number.isFinite(hours) ? hours * 60 : 0;
        let logo = tag(block, 'logo');
        if (logo && !/^https?:\/\//i.test(logo)) logo = `https://media.steampowered.com/steamcommunity/public/images/apps/${appid}/${logo}.jpg`;
        games.set(appid,{appid,name:tag(block,'name') || `App ${appid}`,playtime_forever:Math.round(mins),playtime_2weeks:null,img_icon_url:logo,img_logo_url:logo,rtime_last_played:0});
    }
    return Array.from(games.values());
}

function parseCommunityGames(html) {
    const source = String(html || ''); const games = new Map(); let match;
    // Big Picture markup exposes the account's game library as g_rgGameData.
    // Prefer it because it can contain the complete library even when the
    // normal page renders only a limited first batch.
    const bpGames = parseEmbeddedGameData(source);
    for (const g of bpGames) games.set(g.appid, g);
    // The normal Community page may also expose the library as rgGames.
    const embedded = parseRgGames(source);
    for (const g of embedded) {
        const old = games.get(g.appid);
        games.set(g.appid, {
            ...(old || {}), ...(g || {}),
            playtime_forever: Math.max(Number(old?.playtime_forever || 0), Number(g.playtime_forever || 0)),
            img_icon_url: g.img_icon_url || old?.img_icon_url || '',
            img_logo_url: g.img_logo_url || old?.img_logo_url || ''
        });
    }
    const rowRe = /<div[^>]*class=["'][^"']*\bgameListRow\b[^"']*["'][^>]*>[\s\S]*?(?=<div[^>]*class=["'][^"']*\bgameListRow\b|<\/body|$)/gi;
    while ((match = rowRe.exec(source)) !== null) {
        const row = match[0];
        const idMatch = row.match(/\bid=["']game_(\d+)["']/i) || row.match(/\bdata-appid=["'](\d+)["']/i) || row.match(/\/app\/(\d+)/i);
        if (!idMatch) continue; const appid = Number(idMatch[1]); if (!Number.isInteger(appid) || appid <= 0) continue;
        const nameMatch = row.match(/<[^>]+class=["'][^"']*\bgameListRowItemName\b[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
        const hoursMatch = row.match(/<[^>]+class=["'][^"']*\bgameListRowItemHours\b[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
        const imgMatch = row.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
        let icon = imgMatch ? imgMatch[1] : ''; if (icon.startsWith('//')) icon = 'https:' + icon;
        games.set(appid, {appid, name:decodeHtml(nameMatch ? nameMatch[1] : '') || `App ${appid}`, playtime_forever:parseMinutes(hoursMatch ? hoursMatch[1] : ''), playtime_2weeks:null, img_icon_url:icon, img_logo_url:'', rtime_last_played:0});
    }
    // Newer Steam markup may use gameslistitems_GameName_* classes. Capture the nearest app link/card.
    if (!games.size) {
        const blocks = source.match(/<[^>]+class=["'][^"']*gameslistitems_[^"']*["'][^>]*>[\s\S]*?(?=<[^>]+class=["'][^"']*gameslistitems_|<\/body|$)/gi) || [];
        for (const block of blocks) {
            const idMatch = block.match(/(?:\/app\/|data-appid=["'])(\d+)/i); if (!idMatch) continue;
            const appid = Number(idMatch[1]); if (!Number.isInteger(appid) || appid <= 0) continue;
            const nm = block.match(/class=["'][^"']*gameslistitems_GameName_[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
            const name = decodeHtml(nm ? nm[1] : ''); if (!name) continue;
            games.set(appid,{appid,name,playtime_forever:parseMinutes(block),playtime_2weeks:null,img_icon_url:'',img_logo_url:'',rtime_last_played:0});
        }
    }
    // Do NOT scan arbitrary /app/<id> links from the whole page. The Steam
    // page contains recommendations/featured content too, and that can make
    // unrelated games appear in the account library.
    return Array.from(games.values()).sort((a,b)=>String(a.name).localeCompare(String(b.name),undefined,{sensitivity:'base'}));
}

function getSteamOwnedGamesFromClient() {
    return new Promise((resolve) => {
        try {
            if (typeof client.getUserOwnedApps !== 'function') {
                resolve({games:[], count:0, ok:false, source:'client-api-unavailable'});
                return;
            }
            client.getUserOwnedApps(steamId, {
                includePlayedFreeGames: true,
                includeFreeSub: true,
                includeAppInfo: true,
                skipUnvettedApps: false
            }, (err, response) => {
                if (err || !response) {
                    log('WARN', 'Steam owned-games API failed: ' + String(err && (err.message || err) || 'empty response'));
                    resolve({games:[], count:0, ok:false, source:'client-api'});
                    return;
                }
                const raw = Array.isArray(response.games) ? response.games : (Array.isArray(response.apps) ? response.apps : []);
                const games = raw.map(normalizeCommunityGame).filter(Boolean);
                const count = Number(response.game_count ?? response.app_count);
                log('INFO', 'Steam owned-games API: ' + games.length + ' games, reported count=' + (Number.isFinite(count) ? count : 'n/a'));
                resolve({games, count:Number.isFinite(count) && count >= 0 ? Math.max(count, games.length) : games.length, ok:true, source:'client-api'});
            });
        } catch (e) {
            log('WARN', 'Steam owned-games API exception: ' + String(e.message || e));
            resolve({games:[], count:0, ok:false, source:'client-api-exception'});
        }
    });
}

function getSteamOwnedAppIds() {
    return new Promise((resolve) => {
        try {
            if (typeof client.getOwnedApps !== 'function') { resolve(new Set()); return; }
            const finishOwnership = () => {
                try {
                    const ids = client.getOwnedApps({excludeShared: true});
                    resolve(new Set((Array.isArray(ids) ? ids : []).map(Number).filter(n => Number.isInteger(n) && n > 0)));
                } catch (_) { resolve(new Set()); }
            };
            if (ownershipReadyDone) finishOwnership();
            else ownershipReady.then(finishOwnership).catch(() => resolve(new Set()));
        } catch (_) { resolve(new Set()); }
    });
}
function extractDisplayedGameCount(html) {
    const source = String(html || '');
    const patterns = [
        /profile_count_link_total[^>]*>\s*([\d,\.]+)/i,
        /profile_count_link[^>]*>\s*<[^>]*>\s*([\d,\.]+)\s*<\/[^>]+>\s*<[^>]*>\s*Games/i,
        /(?:^|[>\s])Games\s*<[^>]*>\s*([\d,\.]+)/i
    ];
    for (const re of patterns) {
        const m = source.match(re);
        if (m) {
            const n = Number(String(m[1]).replace(/[,.]/g, ''));
            if (Number.isInteger(n) && n >= 0) return n;
        }
    }
    return null;
}
async function scrapeCommunityGames(headers) {
    const url = `https://steamcommunity.com/profiles/${steamId}/games/?tab=all&l=english`;
    log('INFO', 'Steam Community: opening Games -> All Games page');

    const page = await fetchUrl(url, headers);
    if (page.status !== 200 || !page.html) {
        log('WARN','Steam Community games page HTTP '+page.status);
        return {games:[], count:0, ok:false};
    }

    // The Community Games -> All Games page is the authoritative source for
    // whether this account actually has games. Steam's client license list can
    // contain free/default/shared/tool licenses that are NOT shown as games on
    // the profile. In particular, a fresh account can have dozens of such
    // licenses while its Games page correctly says 0 games.
    const displayedCount = extractDisplayedGameCount(page.html);
    const explicitEmpty = /(?:you\s+have\s+no\s+games|this\s+profile\s+has\s+no\s+games|no\s+games\s+to\s+display|games\s*\(\s*0\s*\))/i.test(
        decodeHtml(String(page.html || '').replace(/<script[\s\S]*?<\/script>/gi,' '))
    );
    if (displayedCount === 0 || explicitEmpty) {
        log('INFO', 'Steam Community Games page confirms 0 games for SteamID ' + steamId + '; ignoring client license/app lists');
        return {games:[], count:0, ok:true, source:'community-empty'};
    }

    // Only after confirming that the Community Games page is non-empty do we
    // use the Steam client API to enrich the exact owned AppIDs. This prevents
    // free/default/shared licenses from becoming fake games.
    const ownedIds = await getSteamOwnedAppIds();
    const apiResult = await getSteamOwnedGamesFromClient();

    const byId = new Map();
    const mergeGame = (g) => {
        if (!g || !Number.isInteger(Number(g.appid)) || Number(g.appid) <= 0) return;
        const id = Number(g.appid);
        if (ownedIds.size && !ownedIds.has(id)) return;
        const old = byId.get(id);
        const oldMinutes = Number(old?.playtime_forever || 0);
        const newMinutes = Number(g.playtime_forever || 0);
        byId.set(id, {
            ...(old || {}), ...(g || {}), appid:id,
            name: (g.name && !/^App \d+$/.test(String(g.name))) ? g.name : (old?.name || g.name || `App ${id}`),
            playtime_forever: Math.max(Number.isFinite(oldMinutes) ? oldMinutes : 0, Number.isFinite(newMinutes) ? newMinutes : 0),
            img_icon_url: g.img_icon_url || old?.img_icon_url || '',
            img_logo_url: g.img_logo_url || old?.img_logo_url || ''
        });
    };

    // The Steam client API is the primary source for the current account's
    // library, names, icons and lifetime playtime. It is tied to the exact
    // logged-in SteamID, so it cannot return another account's library.
    for (const g of apiResult.games) mergeGame(g);

    // Community page is used as a second source for games that the API may not
    // enrich, and especially for hoursOnRecord. Only structured library data is
    // accepted; arbitrary store links are intentionally ignored.
    for (const g of parseEmbeddedGameData(page.html)) mergeGame(g);
    for (const g of parseRgGames(page.html)) mergeGame(g);
    for (const g of parseCommunityGames(page.html)) mergeGame(g);

    try {
        const xmlPage = await fetchUrl(url + '&xml=1', headers);
        if (xmlPage.status === 200 && xmlPage.html) {
            const xmlGames = parseCommunityXml(xmlPage.html);
            for (const x of xmlGames) mergeGame(x);
            log('INFO','Steam Community XML: распознано '+xmlGames.length+' игр; итоговая библиотека '+byId.size);
        } else {
            log('WARN','Steam Community XML HTTP '+xmlPage.status);
        }
    } catch (e) { log('WARN','Steam Community XML failed: '+String(e.message || e)); }

    // Big Picture can expose a more complete embedded game object list.
    try {
        const bpHeaders = {...headers, 'X-ValveUserAgent':'panorama'};
        const bp = await fetchUrl(url, bpHeaders);
        if (bp.status === 200 && bp.html) {
            const bpGames = parseEmbeddedGameData(bp.html);
            for (const g of bpGames) mergeGame(g);
            log('INFO','Steam Big Picture: распознано '+bpGames.length+' игр; итоговая библиотека '+byId.size);
        } else {
            log('WARN','Steam Big Picture games page HTTP '+bp.status);
        }
    } catch (e) { log('WARN','Steam Big Picture scrape failed: '+String(e.message || e)); }

    let games = Array.from(byId.values()).filter(g => Number.isInteger(Number(g.appid)) && Number(g.appid) > 0);

    // If the client API succeeded and returned games, its list is authoritative.
    // Community data is only allowed to enrich those exact AppIDs.
    if (apiResult.ok && apiResult.games.length) {
        const authoritative = new Map(apiResult.games.map(g => [Number(g.appid), g]));
        games = games.filter(g => authoritative.has(Number(g.appid)));
        for (const g of games) {
            const a = authoritative.get(Number(g.appid));
            if (Number(a.playtime_forever || 0) > Number(g.playtime_forever || 0)) g.playtime_forever = Number(a.playtime_forever);
            if (!g.name || /^App \d+$/.test(String(g.name))) g.name = a.name;
            if (!g.img_icon_url) g.img_icon_url = a.img_icon_url || '';
            if (!g.img_logo_url) g.img_logo_url = a.img_logo_url || '';
        }
        // Include API games that were not present in Community HTML.
        for (const a of apiResult.games) {
            const id = Number(a.appid);
            if (!games.some(g => Number(g.appid) === id)) games.push(a);
        }
    }

    games.sort((a,b)=>String(a.name||'').localeCompare(String(b.name||''),undefined,{sensitivity:'base'}));
    const count = games.length;
    // Never use response.game_count/app_count here: those can count licenses
    // which are not games displayed in the account's Games -> All Games page.
    log('INFO','Steam library final: '+count+' unique games confirmed for SteamID '+steamId);
    return {games, count, ok:true, source:'community-confirmed'};
}

client.on('loggedOn', () => {
    log('INFO', 'Steam client login accepted by Steam');
    log('INFO', 'SteamID: ' + steamId);
    if (client.wallet) log('INFO', 'Steam wallet object available after logon');
    try { client.setPersona(SteamUser.EPersonaState.Online); } catch (_) {}
    log('INFO', 'Waiting for Steam webSession event');
});

client.on('wallet', (hasWallet, currency, balance) => {
    walletEventReceived = true;
    walletState = {hasWallet:!!hasWallet, currency:currencyCode(currency), balance:Number(balance || 0)};
    log('INFO', 'Wallet event: hasWallet=' + !!hasWallet + ', currency=' + currencyCode(currency) + ', rawBalance=' + String(balance));
});

client.on('webSession', async (_sessionId, cookies) => {
    if (webSessionProcessing || finished) {
        log('INFO', 'Duplicate Steam webSession ignored');
        return;
    }
    webSessionProcessing = true;
    webSessionReceived = true;
    webCookies = Array.isArray(cookies) ? cookies : [];
    log('INFO', 'Steam web session received; cookies=' + webCookies.length);
    if (!webCookies.length) log('WARN', 'Steam web session returned no cookies');
    const headers = {'Cookie': cookieHeader()};

    const profile = await fetchUrl(`https://steamcommunity.com/profiles/${steamId}/`, headers);
    const account = await fetchUrl('https://store.steampowered.com/account/?l=english', headers);
    const transactions = await fetchUrl('https://store.steampowered.com/account/store_transactions/?l=english', {
        ...headers,
        'Referer':'https://store.steampowered.com/account/?l=english'
    });
    // Steam's Community Market page is a very reliable wallet-data source.
    const market = await fetchUrl('https://steamcommunity.com/market/?l=english', headers);
    const gcpd = await fetchUrl('https://steamcommunity.com/my/gcpd/730?l=english', headers);
    const levelData = extractLevelXp(gcpd.html);
    const badges = await fetchUrl(`https://steamcommunity.com/profiles/${steamId}/badges?l=english`, headers);
    const cardGames = badges.status===200 ? extractCardGames(badges.html) : [];
    log('INFO','Games with card drops remaining: '+cardGames.length);
    if (levelData.level !== null) log('INFO', 'CS2 level=' + levelData.level + ', xp=' + levelData.xp + ' / 5000');
    else log('WARN', 'CS2 level/XP not found on /my/gcpd/730 (HTTP ' + gcpd.status + ')');

    if (transactions.status === 200) log('INFO', 'store_transactions page loaded successfully');
    else log('WARN', 'store_transactions page did not return 200 (status=' + transactions.status + ')');

    const avatar = extractAvatar(profile.html);
    const profileWallet = extractWalletFromHtml(profile.html);
    const txWallet = extractWalletFromHtml(transactions.html);
    const accountWallet = extractWalletFromHtml(account.html);
    const marketWallet = extractWalletFromHtml(market.html);
    let gamesPageGames = [];
    let gamesPageCount = 0;

    if (profileWallet.formatted) log('INFO', 'Balance found on Steam profile: ' + profileWallet.formatted);
    else log('WARN', 'Balance was NOT found on Steam profile');
    if (txWallet.formatted) log('INFO', 'Balance found on store_transactions: ' + txWallet.formatted);
    else log('WARN', 'Balance was NOT found on store_transactions');
    if (accountWallet.formatted) log('INFO', 'Balance found on /account/: ' + accountWallet.formatted);
    else log('WARN', 'Balance was NOT found on /account/');
    if (marketWallet.formatted) log('INFO', 'Balance found on Steam Market: ' + marketWallet.formatted);
    else log('WARN', 'Balance was NOT found on Steam Market');
    if (avatar) log('INFO', 'Steam avatar found'); else log('WARN', 'Steam avatar was not found');

    // Only after profile/avatar/wallet data has been collected, scrape the exact
    // Steam Community Games -> All Games page requested by the user.
    try {
        const gamesResult = await scrapeCommunityGames(headers);
        gamesPageGames = Array.isArray(gamesResult?.games) ? gamesResult.games : [];
        gamesPageCount = Number.isInteger(gamesResult?.count) ? gamesResult.count : gamesPageGames.length;
    } catch (e) {
        log('WARN', 'Steam Community games scrape failed: ' + String(e.message || e));
        gamesPageGames = [];
    }

    const pageWallet = profileWallet.formatted ? profileWallet : (txWallet.formatted ? txWallet : (accountWallet.formatted ? accountWallet : marketWallet));
    const eventWallet = walletState && walletState.hasWallet ? formatWallet(walletState.balance, walletState.currency, true) : '';
    const finalBalance = pageWallet.formatted || eventWallet || '0';
    const finalCurrency = pageWallet.currency || (walletState ? walletState.currency : '') || 'USD';

    if (!finalBalance) {
        log('ERROR', 'Steam authorization succeeded, but wallet balance could not be read');
    } else {
        log('INFO', 'Final wallet balance: ' + finalBalance + ' (source=' + (pageWallet.formatted ? pageWallet.source : 'Steam wallet event') + ')');
    }

    finish({
        ok:true,
        steamid:steamId,
        avatar_url:avatar,
        balance:finalBalance,
        currency:finalCurrency,
        country:pageWallet.country || '',
        games:gamesPageGames,
        games_count:gamesPageCount || gamesPageGames.length,
        card_games:cardGames,
        level:levelData.level,
        xp:levelData.xp,
        balance_source:pageWallet.formatted ? pageWallet.source : (eventWallet ? 'steam-wallet-event' : ''),
        wallet_event:walletEventReceived,
        web_session:webSessionReceived,
        refresh_token:latestRefreshToken,
        web_cookies:webCookies
    });
});

client.on('error', (err) => finish({ok:false, auth_session_invalid:!!refreshToken && !client.steamID, error:'Steam client error: ' + String(err && (err.message || err))}));
client.on('disconnected', (eresult, msg) => finish({ok:false, auth_session_invalid:!!refreshToken && !client.steamID, error:'Steam disconnected: ' + String(msg || eresult)}));

if (!finished) {
    try {
        log('INFO', refreshToken ? 'Connecting to Steam using saved encrypted session' : 'Connecting to Steam using credentials');
        if (refreshToken) {
            client.logOn({refreshToken, steamID:steamId, machineName:`shark_${login}`});
        } else {
            const code = SteamTotp.getAuthCode(sharedSecret);
            log('INFO', 'Steam Guard TOTP generated successfully');
            client.logOn({accountName:login,password,twoFactorCode:code,machineName:`shark_${login}`});
        }
    } catch (e) { fail('logOn exception: ' + (e.message || e)); }
}
setTimeout(() => fail('Steam authorization timeout: no successful login/web session within 30 seconds'), 30000);
"""

CARD_FARM_HELPER = r"""
const SteamUser=require('steam-user');
const SteamTotp=require('steam-totp');
const https=require('https');
const login=process.env.SHARK_STEAM_LOGIN||'',password=process.env.SHARK_STEAM_PASSWORD||'';
const shared=process.env.SHARK_STEAM_SHARED_SECRET||'',steamId=process.env.SHARK_STEAM_ID||'';
const refreshToken=process.env.SHARK_STEAM_REFRESH_TOKEN||'';
let appIds=(process.env.SHARK_CARD_APPIDS||'').split(',').map(Number).filter(x=>Number.isInteger(x)&&x>0);
const client=new SteamUser({enablePicsCache:false});let cookies=[],finished=false,timer=null;
function out(v){process.stdout.write(JSON.stringify(v)+'\n');}
function clean(v){return String(v||'').replace(/<[^>]*>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/\s+/g,' ').replace(/View details/gi,'').trim();}
function parseCards(html){const rows=String(html||'').split(/<div class="badge_row is_link/gi).slice(1),result=[];for(const row of rows){const link=row.match(/gamecards\/(\d+)/i),left=row.match(/(\d+)\s+card drops?\s+remaining/i);if(!link||!left)continue;const n=Number(left[1]);if(n>0){const title=row.match(/<div class="badge_title">([\s\S]*?)<\/div>/i);result.push({appid:Number(link[1]),name:clean(title?title[1]:'')||('App '+link[1]),cards_remaining:n});}}return result;}
function fetchBadges(){return new Promise(resolve=>{const req=https.get(`https://steamcommunity.com/profiles/${steamId}/badges?l=english`,{timeout:15000,headers:{Cookie:cookies.join('; '),'User-Agent':'Mozilla/5.0'}},res=>{let body='';res.setEncoding('utf8');res.on('data',c=>body+=c);res.on('end',()=>resolve(res.statusCode===200?body:''));});req.on('error',()=>resolve(''));req.on('timeout',()=>{req.destroy();resolve('')});});}
function stop(ok,message,cardGames){if(finished)return;finished=true;if(timer)clearInterval(timer);try{client.gamesPlayed([]);}catch(_){}try{client.logOff();}catch(_){}out({ok,status:ok?'completed':'error',message,card_games:cardGames||[]});setTimeout(()=>process.exit(ok?0:1),300);}
async function check(){if(finished||!cookies.length)return;const cards=parseCards(await fetchBadges());const active=cards.filter(c=>appIds.includes(c.appid));const remaining=active.reduce((n,c)=>n+c.cards_remaining,0);out({ok:true,status:'running',remaining,card_games:active});if(!active.length){stop(true,'Фарм завершён: свободных карточек не осталось',[]);return;}const next=active.map(c=>c.appid);if(next.join(',')!==appIds.join(',')){appIds=next;client.gamesPlayed(appIds,true);}}
client.on('loggedOn',()=>{client.setPersona(SteamUser.EPersonaState.Online);client.gamesPlayed(appIds,true);out({ok:true,status:'running',message:'Steam: фарм запущен',appids:appIds});try{client.webLogOn();}catch(_){}});
client.on('webSession',(_sessionId,c)=>{cookies=Array.isArray(c)?c:[];check();if(!timer)timer=setInterval(check,60000);});
client.on('error',e=>stop(false,'Steam: '+String(e&&e.message||e),[]));
client.on('disconnected',(r,m)=>{if(!finished)stop(false,'Steam disconnected: '+String(m||r),[])});
process.on('SIGTERM',()=>stop(true,'Фарм остановлен',[]));process.on('SIGINT',()=>stop(true,'Фарм остановлен',[]));
try{if(refreshToken)client.logOn({refreshToken,steamID:steamId});else client.logOn({accountName:login,password,twoFactorCode:SteamTotp.getAuthCode(shared),machineName:'card_farm_'+login});}catch(e){stop(false,String(e),[])}
"""

FARM_STATE = {}
FARM_PROCESSES = {}
FARM_LOCK = threading.Lock()


def farm_status(login):
    with FARM_LOCK:
        return dict(FARM_STATE.get(login,{"status":"idle","remaining":0}))


def stop_card_farm(login):
    with FARM_LOCK:
        proc = FARM_PROCESSES.get(login)
    if proc and proc.poll() is None:
        proc.terminate()
    with FARM_LOCK:
        FARM_STATE[login] = {"status":"idle","remaining":0}
        FARM_PROCESSES.pop(login,None)


def card_farm_reader(login, proc):
    final_cards = None
    try:
        for line in proc.stdout:
            try: payload = json.loads(line)
            except ValueError: continue
            if "status" not in payload: continue
            with FARM_LOCK:
                FARM_STATE[login] = {"status":payload.get("status","running"),"remaining":int(payload.get("remaining") or 0),"message":str(payload.get("message") or "")}
            if payload.get("status")=="completed" and isinstance(payload.get("card_games"),list): final_cards=payload["card_games"]
    finally:
        try: proc.stdout.close()
        except Exception: pass
        with FARM_LOCK:
            FARM_PROCESSES.pop(login,None)
            current = dict(FARM_STATE.get(login,{}))
            if current.get("status")=="running": current["status"]="idle"
            FARM_STATE[login]=current
        if final_cards is not None:
            with AUTH_LOCK: AUTH_STATE.setdefault(login,{})["card_games"]=final_cards
            save_account_cache()
        log_event("Фарм карточек завершён", "INFO", login)


def start_card_farm(login):
    with AUTH_LOCK: state=dict(AUTH_STATE.get(login,{}))
    cards=[c for c in state.get("card_games",[]) if int(c.get("cards_remaining") or 0)>0]
    if not cards: return False,"После авторизации не найдено игр с оставшимися карточками"
    with FARM_LOCK:
        proc=FARM_PROCESSES.get(login)
        if proc and proc.poll() is None:return False,"Фарм уже запущен"
    creds=find_account_credentials(login);ma=find_mafile_data(login)
    if not creds or not ma:return False,"Не найдены logpass или maFile"
    if not ensure_auth_helper() or not node_ready():return False,"Node.js и steam-user не установлены"
    node=get_node_executable();helper=BASE_DIR/"_shark_card_farm.js";helper.write_text(CARD_FARM_HELPER,encoding="utf-8")
    env=os.environ.copy();env["PATH"]=str(NODE_DIR)+os.pathsep+env.get("PATH","");env["NODE_PATH"]=str(NODE_DIR/"node_modules")
    env.update({"SHARK_STEAM_LOGIN":creds[0],"SHARK_STEAM_PASSWORD":creds[1],"SHARK_STEAM_SHARED_SECRET":ma["shared_secret"],"SHARK_STEAM_ID":ma["steamid"],"SHARK_CARD_APPIDS":",".join(str(c["appid"]) for c in cards)})
    saved=load_steam_session(login);token=(saved or {}).get("refresh_token") or ma.get("refresh_token") or ""
    if token:env["SHARK_STEAM_REFRESH_TOKEN"]=str(token)
    proc=subprocess.Popen([node,str(helper)],cwd=str(NODE_DIR),env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding="utf-8",errors="replace",creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    with FARM_LOCK:FARM_PROCESSES[login]=proc;FARM_STATE[login]={"status":"running","remaining":sum(int(c["cards_remaining"]) for c in cards),"message":"Запуск Steam"}
    threading.Thread(target=card_farm_reader,args=(login,proc),daemon=True,name="CardFarm-"+login).start()
    log_event("Запущен фарм карточек: "+str(len(cards))+" игр","INFO",login)
    return True,"Фарм карточек запущен"


@app.route("/api/cards/farm/<path:login>",methods=["GET","POST","DELETE"])
def api_card_farm(login):
    if request.method=="GET":return jsonify({"ok":True,**farm_status(login)})
    if request.method=="DELETE":stop_card_farm(login);return jsonify({"ok":True,"message":"Фарм остановлен"})
    ok,message=start_card_farm(login);return jsonify({"ok":ok,"message":message,**farm_status(login)}),(200 if ok else 409)



ACTIVITY_BOOSTER_HELPER = r"""
const SteamUser = require('steam-user');
const SteamTotp = require('steam-totp');
const https = require('https');
const fs = require('fs');

const client = new SteamUser({enablePicsCache:true});
const login = process.env.SHARK_STEAM_LOGIN || '';
const password = process.env.SHARK_STEAM_PASSWORD || '';
const sharedSecret = process.env.SHARK_STEAM_SHARED_SECRET || '';
const steamIdArg = process.env.SHARK_STEAM_ID || '';
const minIntervalArg = process.env.SHARK_BOOSTER_MIN_MINUTES || '60';
const maxIntervalArg = process.env.SHARK_BOOSTER_MAX_MINUTES || '100';
const preferredAppIdsArg = process.env.SHARK_BOOSTER_APPIDS || '0';
const cardPriorityAppIds = (process.env.SHARK_BOOSTER_CARD_APPIDS || '')
    .split(',')
    .map((id) => Number.parseInt(String(id).trim(), 10))
    .filter((id) => Number.isInteger(id) && id > 0)
    .filter((id, idx, arr) => arr.indexOf(id) === idx);
const libraryAppIdsFile = process.env.SHARK_BOOSTER_LIBRARY_FILE || '';
let providedLibraryGameIds = [];
let libraryLoadError = '';
if (libraryAppIdsFile) {
    try {
        const savedLibrary = JSON.parse(fs.readFileSync(libraryAppIdsFile, 'utf8'));
        providedLibraryGameIds = (Array.isArray(savedLibrary) ? savedLibrary : [])
            .map((id) => Number.parseInt(String(id), 10))
            .filter((id) => Number.isInteger(id) && id > 0)
            .filter((id, idx, arr) => arr.indexOf(id) === idx);
    } catch (err) {
        libraryLoadError = String(err?.message || err || 'library read failed');
        console.error(`[${login}] Could not read the saved Games Library: ${libraryLoadError}`);
    }
}
let refreshToken = process.env.SHARK_STEAM_REFRESH_TOKEN || '';
let hasLoggedOn = false;

if (!login || !password || !sharedSecret || !steamIdArg) {
    console.error('Missing Steam authorization data');
    process.exit(1);
}

const minIntervalMinutes = Math.max(1, Number.parseInt(minIntervalArg, 10));
const maxIntervalMinutes = Math.max(minIntervalMinutes, Number.parseInt(maxIntervalArg, 10));
const rawPreferredAppIds = preferredAppIdsArg
    .split(',')
    .map((id) => Number.parseInt(String(id).trim(), 10))
    .filter((id) => Number.isInteger(id) && id >= 0)
    .filter((id, idx, arr) => arr.indexOf(id) === idx)
    .slice(0, 6);

let availableGameIds = [];
let rotateTimer = null;
let isShuttingDown = false;
let startedPlaying = false;
let fixedPlayableIds = [];
let mustPlayIds = [];
let randomSlotsCount = 0;
let lastRandomIds = [];
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 6;
let ownershipLoaded = false;
let reconnectTimer = null;
let shouldLoadOwnership = true;
let ownershipLoadStarted = false;
let ownershipRetryTimer = null;
let ownershipRetryAttempts = 0;
let webCookies = [];

function randInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function parseCommunityGamesFromHtml(html) {
    if (typeof html !== 'string' || !html.trim()) {
        return [];
    }

    const fromRgGames = parseRgGamesFromHtml(html);
    if (fromRgGames.length > 0) {
        return Array.from(new Set(fromRgGames.map((game) => game.appid)));
    }

    const appIdSet = new Set();
    // Keep parsing conservative here to avoid grabbing unrelated app links from page chrome/recommendations.
    const patterns = [
        /"appid"\s*:\s*(\d+)/gi,
        /\bappid\s*:\s*(\d+)/gi,
        /<appID>\s*(\d+)\s*<\/appID>/gi,
    ];

    for (const pattern of patterns) {
        let match = null;
        while ((match = pattern.exec(html)) !== null) {
            const id = Number.parseInt(match[1], 10);
            if (Number.isInteger(id) && id > 0) {
                appIdSet.add(id);
            }
        }
    }

    return Array.from(appIdSet);
}

function fetchUrl(url, headers = {}) {
    return new Promise((resolve) => {
        const req = https.get(url, { timeout: 15000, headers }, (res) => {
            if (!res || (res.statusCode && res.statusCode >= 400)) {
                resolve('');
                return;
            }

            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
                body += chunk;
            });
            res.on('end', () => {
                resolve(body);
            });
        });

        req.on('error', () => resolve(''));
        req.on('timeout', () => {
            req.destroy();
            resolve('');
        });
    });
}

function parseRgGamesFromHtml(html) {
    if (typeof html !== 'string' || !html.trim()) {
        return [];
    }

    // On /my/games?tab=all Steam renders JS object: var rgGames = [...];
    const rgGamesMatch = html.match(/var\s+rgGames\s*=\s*(\[[\s\S]*?\]);/i);
    if (!rgGamesMatch) {
        return [];
    }

    try {
        const games = JSON.parse(rgGamesMatch[1]);
        if (!Array.isArray(games)) {
            return [];
        }
        return games
            .map((game) => ({
                appid: Number.parseInt(String(game?.appid ?? ''), 10),
                name: String(game?.name || '').trim(),
            }))
            .filter((game) => Number.isInteger(game.appid) && game.appid > 0);
    } catch (_) {
        return [];
    }
}

async function fetchOwnedAppsFromMyProfile() {
    if (!Array.isArray(webCookies) || webCookies.length === 0) {
        return [];
    }

    const headers = {
        Cookie: webCookies.join('; '),
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
        Referer: 'https://steamcommunity.com/my/games/?tab=all',
    };

    const urls = [
        'https://steamcommunity.com/my/games/?tab=all',
        'https://steamcommunity.com/id/me/games/?tab=all',
    ];

    for (const url of urls) {
        const body = await fetchUrl(url, headers);
        const games = parseRgGamesFromHtml(body);
        if (games.length > 0) {
            const appIds = Array.from(new Set(games.map((game) => game.appid)));
            const sampleTitles = games
                .map((game) => game.name)
                .filter(Boolean)
                .slice(0, 5)
                .join(', ');
            console.log(`[${login}] Ownership via authenticated profile: ${games.length} games (${sampleTitles || 'titles unavailable'})`);
            return appIds;
        }
    }

    return [];
}

async function fetchOwnedAppsFromCommunity(steamId) {
    const urls = [
        `https://steamcommunity.com/profiles/${steamId}/games?xml=1`,
        `https://steamcommunity.com/profiles/${steamId}/games/?xml=1`,
        `https://steamcommunity.com/profiles/${steamId}/games?tab=all&l=english`,
        `https://steamcommunity.com/profiles/${steamId}/games?tab=all`,
    ];

    for (const url of urls) {
        const body = await fetchUrl(url);
        let appIds = [];

        if (url.includes('xml=1')) {
            appIds = parseCommunityGamesFromHtml(body);
        } else {
            // For HTML tabs we trust only rgGames payload, to avoid accidental overcount
            // from unrelated app links in the page chrome.
            const rgGames = parseRgGamesFromHtml(body);
            appIds = Array.from(new Set(rgGames.map((game) => game.appid)));
        }

        if (appIds.length > 0) {
            console.log(`[${login}] Ownership fallback succeeded via ${url} (${appIds.length} appids)`);
            return appIds;
        }
    }

    return [];
}

function startIfReady() {
    if (startedPlaying) {
        return;
    }
    startRandomActivity();
    if (!rotateTimer) {
        scheduleNextRotate();
    }
}

async function loadOwnershipAndStart() {
    if (ownershipLoadStarted || ownershipLoaded) {
        return;
    }
    ownershipLoadStarted = true;

    try {
        // Random slots must use exactly the same games shown on this account's
        // Games Library tab. Steam license/PICS ownership lists also contain DLC,
        // tools, dedicated servers and other non-game apps, so they are not a
        // valid fallback for random activity.
        availableGameIds = providedLibraryGameIds.slice();

        if (rawPreferredAppIds.length > 0) {
            fixedPlayableIds = rawPreferredAppIds.filter((id) => id > 0).slice(0, 5);
            const hasRandomToken = rawPreferredAppIds.includes(0);
            randomSlotsCount = hasRandomToken ? Math.max(0, 5 - fixedPlayableIds.length) : 0;
            mustPlayIds = fixedPlayableIds.slice();
        } else {
            mustPlayIds = [];
            randomSlotsCount = Math.min(5, availableGameIds.length);
        }

        if (randomSlotsCount > 0 && availableGameIds.length === 0) {
            console.error(`[${login}] Games Library is empty or unavailable. Open Games Library, press refresh, then restart Booster.${libraryLoadError ? ' Library file could not be read.' : ''}`);
            shutdown(5);
            return;
        }

        // Fixed AppIDs retain their explicit configured behavior. The saved
        // library is needed only to fill random slots.
        if (availableGameIds.length === 0 && mustPlayIds.length > 0) {
            availableGameIds = mustPlayIds.slice();
        }

        if (randomSlotsCount > 0) {
            console.log(`[${login}] Fixed appids: ${mustPlayIds.join(', ') || '-'}, random rotating slots: ${randomSlotsCount}`);
        } else {
            console.log(`[${login}] Will play configured appids: ${mustPlayIds.join(', ')}`);
        }

        console.log(`[${login}] Games Library: ${availableGameIds.length} games; DLC and license-only appids excluded`);
        ownershipLoaded = true;
        ownershipRetryAttempts = 0;

        // If fixed activity started first, add random library games as soon as
        // the saved library is ready instead of waiting for the next rotation.
        if (startedPlaying && randomSlotsCount > 0) {
            startRandomActivity();
        }

        startIfReady();
    } catch (err) {
        console.error(`[${login}] Failed to load Games Library: ${err?.message || err}`);
        shutdown(6);
    }
}

function pickRandomGames(appIds, count = 2, excludeIds = []) {
    const excludeSet = new Set(excludeIds);
    const uniquePool = appIds.filter((id, idx, arr) => arr.indexOf(id) === idx && !excludeSet.has(id));
    const pool = [...uniquePool];
    for (let i = pool.length - 1; i > 0; i -= 1) {
        const j = Math.floor(Math.random() * (i + 1));
        [pool[i], pool[j]] = [pool[j], pool[i]];
    }

    const picked = pool.slice(0, Math.min(count, pool.length));
    if (picked.length < count && excludeIds.length > 0) {
        const fallback = appIds.filter((id) => !picked.includes(id) && !excludeSet.has(id));
        for (let i = fallback.length - 1; i > 0; i -= 1) {
            const j = Math.floor(Math.random() * (i + 1));
            [fallback[i], fallback[j]] = [fallback[j], fallback[i]];
        }
        for (const id of fallback) {
            if (picked.length >= count) {
                break;
            }
            picked.push(id);
        }
    }

    return picked.slice(0, count);
}

function parsePreferredGamePlan() {
    if (rawPreferredAppIds.length === 0) {
        mustPlayIds = [];
        randomSlotsCount = 0;
        shouldLoadOwnership = true;
        return;
    }

    const requestedFixed = rawPreferredAppIds.filter((id) => id > 0).slice(0, 5);
    const hasRandomToken = rawPreferredAppIds.includes(0);

    // Use Set to keep IDs unique without repeated O(n²) scans.
    const uniqueFixed = Array.from(new Set(requestedFixed)).slice(0, 5);
    mustPlayIds = uniqueFixed;
    randomSlotsCount = hasRandomToken ? Math.max(0, 5 - mustPlayIds.length) : 0;

    // If no random slots requested, we can skip ownership loading entirely,
    // which noticeably lowers RAM usage per account.
    shouldLoadOwnership = randomSlotsCount > 0 || mustPlayIds.length === 0;
}

function composeCurrentActivity() {
    // Random slots prefer games with remaining card drops. The regular library
    // is used only to fill slots that priority games cannot cover.
    const priorityPool = availableGameIds.filter((id) => cardPriorityAppIds.includes(id));
    const nextRandom = randomSlotsCount > 0
        ? pickRandomGames(priorityPool, randomSlotsCount, [...mustPlayIds, ...lastRandomIds])
        : [];
    if (nextRandom.length < randomSlotsCount) {
        const refill = pickRandomGames(availableGameIds, randomSlotsCount - nextRandom.length, [...mustPlayIds, ...nextRandom]);
        nextRandom.push(...refill);
    }
    lastRandomIds = nextRandom.slice(0, randomSlotsCount);
    return [...mustPlayIds, ...lastRandomIds].slice(0, 5);
}

function scheduleNextRotate() {
    const nextMinutes = randInt(minIntervalMinutes, maxIntervalMinutes);
    const nextMs = nextMinutes * 60 * 1000;

    console.log(`Next rotation in ${nextMinutes} minutes`);
    rotateTimer = setTimeout(() => {
        if (isShuttingDown) {
            return;
        }
        startRandomActivity();
        scheduleNextRotate();
    }, nextMs);
}

function startRandomActivity() { 
    client.setPersona(SteamUser.EPersonaState.Online);
    startedPlaying = true;
    const selected = composeCurrentActivity();
    if (selected.length === 0) {
        console.log('No games available for activity');
        return;
    }

    client.gamesPlayed(selected, true);
    console.log(`Playing appids: ${selected.join(', ')}`);
} 

function shutdown(code = 0) {
    if (isShuttingDown) {
        return;
    }
    isShuttingDown = true;

    if (rotateTimer) {
        clearTimeout(rotateTimer);
        rotateTimer = null;
    }
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }
    if (ownershipRetryTimer) {
        clearTimeout(ownershipRetryTimer);
        ownershipRetryTimer = null;
    }

    try {
        client.gamesPlayed([]);
    } catch (_) {
        // noop
    }
    try {
        client.logOff();
    } catch (_) {
        // noop
    }

    process.exit(code);
}

function scheduleReconnect(reason) {
    if (isShuttingDown) {
        return;
    }
    // Steam clears gamesPlayed when the connection is lost. Force the next
    // loggedOn event to send the configured activity again instead of treating
    // the previous successful gamesPlayed call as still active.
    startedPlaying = false;
    if (reconnectTimer) {
        return;
    }
    reconnectAttempts += 1;
    if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
        console.error(`[${login}] Too many reconnect attempts, stopping booster (${reason})`);
        shutdown(8);
        return;
    }

    const delaySeconds = Math.min(45, reconnectAttempts * 7);
    console.log(`[${login}] Reconnect attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} in ${delaySeconds}s (${reason})`);
    reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        if (isShuttingDown) {
            return;
        }
        try {
            client.logOn(logonOptions());
        } catch (err) {
            console.error(`[${login}] Reconnect failed to start: ${err?.message || err}`);
            scheduleReconnect('logon exception');
        }
    }, delaySeconds * 1000);
}

function logonOptions() {
    if (refreshToken) {
        return {refreshToken, steamID:steamIdArg, machineName:`booster_${login}`};
    }
    return {
        accountName:login,
        password,
        twoFactorCode:SteamTotp.getAuthCode(sharedSecret),
        machineName:`booster_${login}`,
    };
}

function startLogon() {
    try {
        client.logOn(logonOptions());
    } catch (err) {
        console.error(`[${login}] Initial logon failed to start: ${err?.message || err}`);
        scheduleReconnect('initial logon exception');
    }
}

client.on('loggedOn', () => { 
    hasLoggedOn = true;
    reconnectAttempts = 0;
    reconnectTimer = null;
    console.log(`[${login}] Logged on`); 
    client.setPersona(SteamUser.EPersonaState.Online);
    try {
        client.webLogOn();
    } catch (_) {
        // noop
    }

    // Always start fixed appids immediately if they were explicitly configured.
    // This guarantees activity even if ownership loading is delayed.
    if (mustPlayIds.length > 0 && !startedPlaying) {
        startIfReady();
    }

    if (!ownershipLoaded && shouldLoadOwnership) {
        loadOwnershipAndStart();
    } else {
        startIfReady();
    }
});

client.on('licenses', () => {
    if (shouldLoadOwnership && !ownershipLoaded) {
        loadOwnershipAndStart();
    }
});

client.on('webSession', (_sessionId, cookies) => {
    if (Array.isArray(cookies) && cookies.length > 0) {
        webCookies = cookies;
    }
    if (!startedPlaying) {
        console.log(`[${login}] Web session started`);
    }
    if (shouldLoadOwnership && !ownershipLoaded) {
        loadOwnershipAndStart();
    }
});
client.on('refreshToken', (token) => {
    if (!token) return;
    refreshToken = String(token);
    // The Python parent stores this token encrypted and never writes it to history.
    process.stdout.write('SHARK_REFRESH_TOKEN:' + Buffer.from(refreshToken).toString('base64') + '\n');
});

client.on('error', (err) => {
    const message = String(err?.message || err || '');
    console.error(`[${login}] Steam error: ${message}`);
    if (refreshToken) {
        refreshToken = '';
        reconnectAttempts = 0;
        console.warn(`[${login}] Saved session rejected; retrying with login/password/2FA`);
        scheduleReconnect('saved session rejected');
        return;
    }
    scheduleReconnect(`error: ${message}`);
});

client.on('disconnected', (eresult, msg) => {
    console.error(`[${login}] Disconnected: ${msg || eresult}`);
    scheduleReconnect(`disconnected: ${msg || eresult}`)
});

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

parsePreferredGamePlan();

if (!shouldLoadOwnership && mustPlayIds.length > 0) {
    // Lightweight mode: strictly use configured app ids and avoid loading ownership data.
    availableGameIds = mustPlayIds.slice();
    ownershipLoaded = true;
    console.log(`[${login}] Lightweight mode enabled: ownership cache skipped, fixed appids: ${mustPlayIds.join(', ')}`);
}

startLogon();
"""

BOOSTER_SETTINGS_FILE = BASE_DIR / "booster_settings.json"
BOOSTER_STATE = {}
BOOSTER_PROCESSES = {}
BOOSTER_LOCK = threading.Lock()
BOOSTER_SHUTDOWN = threading.Event()
THEME_SETTINGS_FILE = BASE_DIR / "theme_settings.json"


def booster_status(login):
    with BOOSTER_LOCK:
        state = dict(BOOSTER_STATE.get(login, {"status":"idle","message":"","appids":[]}))
        proc = BOOSTER_PROCESSES.get(login)
    if proc and proc.poll() is None:
        # A live Node process only means that authorization is in progress.
        # Switch to running after loggedOn/Playing instead of showing a false success.
        if state.get("status") not in ("starting","running"):
            state["status"] = "starting"
    elif state.get("status") in ("starting","running"):
        state["status"] = "idle"
    return state


def normalize_booster_appids(value):
    text = str(value if value is not None else "0").strip()
    if not text:
        text = "0"
    tokens = [part.strip() for part in text.split(",")]
    if any(not part.isdigit() for part in tokens):
        raise ValueError("AppID должны быть целыми числами через запятую, например 0,730")
    ids = []
    for part in tokens:
        appid = int(part)
        if appid not in ids:
            ids.append(appid)
    fixed = [appid for appid in ids if appid > 0]
    if len(fixed) > 5 or len(ids) > 6:
        raise ValueError("Можно указать не больше пяти игр, включая слот 0 для случайных игр")
    return ",".join(str(appid) for appid in ids) or "0"


def save_booster_settings(value,login=None):
    appids = normalize_booster_appids(value)
    saved = _read_json_object(BOOSTER_SETTINGS_FILE)
    accounts = saved.get("accounts") if isinstance(saved.get("accounts"),dict) else {}
    accounts = dict(accounts)
    login = str(login or "").strip()
    if login:
        accounts[login] = appids
        payload = {"app_ids":str(saved.get("app_ids") or "0"),"accounts":accounts}
    else:
        payload = {"app_ids":appids}
        if accounts:
            payload["accounts"] = accounts
    _write_json_object(BOOSTER_SETTINGS_FILE,payload)
    return appids


def save_booster_settings_for_all(value):
    """Save one AppID configuration everywhere without starting any Steam process."""
    appids = normalize_booster_appids(value)
    saved = _read_json_object(BOOSTER_SETTINGS_FILE)
    accounts = saved.get("accounts") if isinstance(saved.get("accounts"),dict) else {}
    accounts = dict(accounts)
    logins = [str(account.get("login") or "").strip() for account in read_logpass()[0]]
    logins = [login for login in logins if login]
    for login in logins:
        accounts[login] = appids
    _write_json_object(BOOSTER_SETTINGS_FILE,{"app_ids":appids,"accounts":accounts})
    return appids,len(logins)


def stop_activity_booster(login):
    with BOOSTER_LOCK:
        proc = BOOSTER_PROCESSES.get(login)
        BOOSTER_STATE[login] = {"status":"idle","message":"Booster остановлен","appids":[]}
    if proc and proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass


def stop_all_activity_boosters():
    """Block new launches and terminate every Booster before the manager exits."""
    BOOSTER_SHUTDOWN.set()
    with BOOSTER_LOCK:
        processes = list(BOOSTER_PROCESSES.items())
        for login,_ in processes:
            BOOSTER_STATE[login] = {"status":"idle","message":"Менеджер закрыт","appids":[]}
    running = []
    for _,proc in processes:
        if not proc or proc.poll() is not None:
            continue
        running.append(proc)
        try:
            proc.terminate()
        except OSError:
            pass
    deadline = time.monotonic()+3
    for proc in running:
        try:
            proc.wait(timeout=max(0,deadline-time.monotonic()))
        except Exception:
            pass
    for proc in running:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass


def activity_booster_reader(login, proc, library_file=None):
    exit_code = 0
    try:
        for raw in proc.stdout:
            line = str(raw or "").strip()
            if not line:
                continue
            if line.startswith("SHARK_REFRESH_TOKEN:"):
                try:
                    token = base64.b64decode(line.split(":",1)[1]).decode("utf-8").strip()
                    if token:
                        save_steam_session(login,token)
                except Exception:
                    log_event("Booster: не удалось сохранить обновлённую сессию","WARN",login)
                continue
            match = re.search(r"Playing appids:\s*([0-9,\s]+)",line,re.I)
            with BOOSTER_LOCK:
                current = dict(BOOSTER_STATE.get(login,{}))
                if match:
                    current["status"] = "running"
                elif current.get("status") not in ("idle","error"):
                    # Authorization alone does not prove that gamesPlayed was sent.
                    current["status"] = "starting"
                current["message"] = line[-500:]
                if match:
                    current["appids"] = [int(v) for v in re.findall(r"\d+",match.group(1))]
                BOOSTER_STATE[login] = current
            log_event("Booster: "+line[-800:],"INFO",login)
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            exit_code = proc.wait(timeout=3)
        except Exception:
            exit_code = 0
        with BOOSTER_LOCK:
            BOOSTER_PROCESSES.pop(login,None)
            current = dict(BOOSTER_STATE.get(login,{}))
            if current.get("status") != "idle":
                current["status"] = "idle" if exit_code == 0 else "error"
                if exit_code != 0:
                    current["message"] = "Booster завершился с ошибкой"
            BOOSTER_STATE[login] = current
        if library_file is not None:
            try: Path(library_file).unlink()
            except OSError: pass
        log_event("Booster остановлен","INFO",login)


def start_activity_booster(login, appids):
    if BOOSTER_SHUTDOWN.is_set():
        return False,"Менеджер закрывается"
    with BOOSTER_LOCK:
        proc = BOOSTER_PROCESSES.get(login)
        if proc and proc.poll() is None:
            return False,"Booster уже запущен"
    creds = find_account_credentials(login)
    ma = find_mafile_data(login)
    if not creds or not ma or not ma.get("shared_secret"):
        return False,"Не найдены logpass или maFile"
    if not node_ready():
        ok,message = install_node_runtime()
        if not ok:
            return False,"Не удалось установить Node.js и steam-user: "+str(message)
        if not node_ready():
            return False,"Node.js установлен, но steam-user/steam-totp не прошли проверку. Нажмите «Скачать Node.js» для подробностей"
    # Avoid two helpers overwriting each other's gamesPlayed state.
    stop_card_farm(login)
    helper = BASE_DIR / "_shark_activity_booster.js"
    try:
        helper.write_text(ACTIVITY_BOOSTER_HELPER,encoding="utf-8")
    except OSError:
        return False,"Не удалось создать activity_booster.js"
    with AUTH_LOCK:
        account_state = AUTH_STATE.get(login,{})
        card_games = list(account_state.get("card_games",[]) or [])
        library_games = list(account_state.get("games",[]) or [])
    library_appids = []
    for game in library_games:
        try:
            appid = int(game.get("appid") or 0) if isinstance(game,dict) else 0
        except (TypeError,ValueError):
            continue
        if appid>0 and appid not in library_appids:
            library_appids.append(appid)
    random_requested = any(part.strip()=="0" for part in str(appids or "0").split(","))
    if random_requested and not library_appids:
        return False,"Games Library пуста. Откройте Games Library, нажмите обновление и повторите запуск Booster"
    library_set = set(library_appids)
    card_appids = []
    for game in card_games:
        try:
            appid = int(game.get("appid") or 0)
            remaining = int(game.get("cards_remaining") or 0)
        except (TypeError,ValueError,AttributeError):
            continue
        if appid>0 and remaining>0 and appid in library_set and appid not in card_appids:
            card_appids.append(appid)
    library_file = None
    if library_appids:
        library_file = NODE_DIR / ("_shark_booster_library_"+hashlib.sha256(str(login).encode("utf-8")).hexdigest()[:20]+".json")
        try:
            NODE_DIR.mkdir(parents=True,exist_ok=True)
            library_file.write_text(json.dumps(library_appids,separators=(",",":")),encoding="utf-8")
        except OSError:
            return False,"Не удалось передать Games Library в Booster"
    env = os.environ.copy()
    env["PATH"] = str(NODE_DIR)+os.pathsep+env.get("PATH","")
    env["NODE_PATH"] = str(NODE_DIR/"node_modules")
    env.update({
        "SHARK_STEAM_LOGIN":creds[0],
        "SHARK_STEAM_PASSWORD":creds[1],
        "SHARK_STEAM_SHARED_SECRET":ma["shared_secret"],
        "SHARK_STEAM_ID":str(ma["steamid"]),
        "SHARK_BOOSTER_APPIDS":appids,
        "SHARK_BOOSTER_CARD_APPIDS":",".join(str(appid) for appid in card_appids),
        "SHARK_BOOSTER_MIN_MINUTES":"60",
        "SHARK_BOOSTER_MAX_MINUTES":"100"
    })
    if library_file is not None:
        env["SHARK_BOOSTER_LIBRARY_FILE"] = str(library_file)
    saved_session = load_steam_session(login)
    refresh_token = str((saved_session or {}).get("refresh_token") or ma.get("refresh_token") or "").strip()
    if refresh_token:
        env["SHARK_STEAM_REFRESH_TOKEN"] = refresh_token
    if BOOSTER_SHUTDOWN.is_set():
        if library_file is not None:
            try: library_file.unlink()
            except OSError: pass
        return False,"Менеджер закрывается"
    try:
        proc = subprocess.Popen(
            [get_node_executable(),str(helper)],cwd=str(NODE_DIR),env=env,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,
            encoding="utf-8",errors="replace",
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)
        )
    except Exception as exc:
        if library_file is not None:
            try: library_file.unlink()
            except OSError: pass
        return False,"Не удалось запустить Booster: "+str(exc)
    with BOOSTER_LOCK:
        shutting_down = BOOSTER_SHUTDOWN.is_set()
        if not shutting_down:
            BOOSTER_PROCESSES[login] = proc
            BOOSTER_STATE[login] = {"status":"starting","message":"Подключение к Steam","appids":[]}
    if shutting_down:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            pass
        try: proc.stdout.close()
        except Exception: pass
        if library_file is not None:
            try: library_file.unlink()
            except OSError: pass
        return False,"Менеджер закрывается"
    threading.Thread(target=activity_booster_reader,args=(login,proc,library_file),daemon=True,name="ActivityBooster-"+login).start()
    log_event("Booster запущен; AppID: "+appids,"INFO",login)
    return True,"Booster запущен"



BOOSTER_QUEUE_LOCK = threading.Lock()
BOOSTER_QUEUE_STATE = {
    "running":False,"current":"","done":0,"total":0,"started":[],"errors":{},
    "logins":[],"last_login":"","last_ok":False,"last_message":"","message":""
}


def booster_queue_status():
    with BOOSTER_QUEUE_LOCK:
        state = dict(BOOSTER_QUEUE_STATE)
        state["started"] = list(state.get("started") or [])
        state["errors"] = dict(state.get("errors") or {})
        logins = list(state.get("logins") or [])
    state["runtime"] = {login:booster_status(login) for login in logins}
    return state


def booster_start_worker(logins,appids):
    try:
        for index,login in enumerate(logins):
            if BOOSTER_SHUTDOWN.is_set():
                break
            with BOOSTER_QUEUE_LOCK:
                BOOSTER_QUEUE_STATE["current"] = login
                BOOSTER_QUEUE_STATE["message"] = "Запуск аккаунта"
            login_appids = appids.get(login,"0") if isinstance(appids,dict) else appids
            if not node_ready():
                with BOOSTER_QUEUE_LOCK:
                    BOOSTER_QUEUE_STATE["message"] = "Установка Node.js и steam-user…"
            try:
                ok,message = start_activity_booster(login,login_appids)
            except Exception as exc:
                ok = False
                message = "Ошибка запуска Booster: "+str(exc)
                log_event(message,"ERROR",login)
            with BOOSTER_QUEUE_LOCK:
                if ok:
                    BOOSTER_QUEUE_STATE["started"].append(login)
                else:
                    BOOSTER_QUEUE_STATE["errors"][login] = message
                BOOSTER_QUEUE_STATE.update({
                    "done":index+1,"last_login":login,"last_ok":bool(ok),"last_message":message
                })
            if index+1 < len(logins):
                with BOOSTER_QUEUE_LOCK:
                    BOOSTER_QUEUE_STATE["message"] = "Пауза 10 с перед следующим аккаунтом"
                if BOOSTER_SHUTDOWN.wait(10):
                    break
    finally:
        with BOOSTER_QUEUE_LOCK:
            BOOSTER_QUEUE_STATE["running"] = False
            BOOSTER_QUEUE_STATE["current"] = ""
            BOOSTER_QUEUE_STATE["message"] = "Очередь завершена"


AUTO_SESSION_SETTINGS_FILE = BASE_DIR / "auto_session_settings.json"
AUTO_SESSION_LOCK = threading.Lock()
AUTO_SESSION_RUN_ID = 0
try:
    _AUTO_SESSION_INITIAL_SETTINGS = json.loads(AUTO_SESSION_SETTINGS_FILE.read_text(encoding="utf-8"))
    if not isinstance(_AUTO_SESSION_INITIAL_SETTINGS,dict):
        _AUTO_SESSION_INITIAL_SETTINGS = {}
except (OSError,ValueError,TypeError):
    _AUTO_SESSION_INITIAL_SETTINGS = {}
AUTO_SESSION_STATE = {
    "enabled":bool(_AUTO_SESSION_INITIAL_SETTINGS.get("enabled")),
    "running":False,"cancelling":False,"current":"","done":0,"total":0,
    "reloaded":0,"failed":0,"skipped":0,"message":""
}


def auto_session_status():
    with AUTO_SESSION_LOCK:
        return dict(AUTO_SESSION_STATE)


def steam_session_needs_reload(login):
    """Return True for an expired/missing session, False when valid, None on network uncertainty."""
    if not load_steam_session(login):
        return True
    cookies = load_steam_web_cookies(login)
    if not any(str(cookie).split("=",1)[0].strip().lower()=="steamloginsecure" for cookie in cookies):
        return True
    headers = {
        "Cookie":steam_cookie_header(cookies),
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept-Language":"en-US,en;q=0.9"
    }
    req = urllib.request.Request("https://steamcommunity.com/my/profile?l=english",headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=15) as response:
            final_url = str(response.geturl() or "")
            page = response.read().decode("utf-8",errors="replace")
        if "/login" in final_url.lower():
            return True
        # A successful /my/profile response without a login redirect means the
        # web session is accepted. Some Steam page variants omit g_sessionID;
        # that alone must never trigger another authorization or token rewrite.
        if re.search(r"\bg_sessionID\s*=",page) or page:
            return False
        return None
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return True
        return None
    except Exception:
        return None


def auto_session_sleep(run_id,seconds):
    for _ in range(seconds):
        time.sleep(1)
        with AUTO_SESSION_LOCK:
            if not AUTO_SESSION_STATE.get("running") or AUTO_SESSION_STATE.get("cancelling") or AUTO_SESSION_RUN_ID!=run_id:
                return False
    return True


def auto_session_worker(logins,run_id):
    cancelled = False
    try:
        for index,login in enumerate(logins):
            cooldown = False
            with AUTO_SESSION_LOCK:
                if AUTO_SESSION_RUN_ID!=run_id or AUTO_SESSION_STATE.get("cancelling"):
                    cancelled = True
                    break
                AUTO_SESSION_STATE["current"] = login
                AUTO_SESSION_STATE["message"] = "Проверка сессии"
            with AUTH_LOCK:
                already_running = login in ACTIVE_AUTH
            if already_running:
                with AUTO_SESSION_LOCK:
                    AUTO_SESSION_STATE["skipped"] += 1
                    AUTO_SESSION_STATE["done"] = index+1
            else:
                try:
                    needed = steam_session_needs_reload(login)
                    # Valid sessions are skipped immediately. Keep the 10-second
                    # cooldown only after a reload or an uncertain/failed check.
                    cooldown = needed is not False
                    if needed is None:
                        with AUTO_SESSION_LOCK:
                            AUTO_SESSION_STATE["skipped"] += 1
                            AUTO_SESSION_STATE["message"] = "Проверка недоступна, сессия не изменена"
                    elif needed:
                        with AUTO_SESSION_LOCK:
                            AUTO_SESSION_STATE["message"] = "Восстановление сессии"
                        with AUTH_LOCK:
                            ACTIVE_AUTH.add(login)
                        try:
                            # Uses refresh-token first and automatically falls back
                            # to login/password/TOTP when Steam rejects the session.
                            _authorize_account_worker_impl(login)
                        finally:
                            with AUTH_LOCK:
                                ACTIVE_AUTH.discard(login)
                        with AUTH_LOCK:
                            ok = AUTH_STATE.get(login,{}).get("auth_status")=="ok"
                        with AUTO_SESSION_LOCK:
                            if ok:
                                AUTO_SESSION_STATE["reloaded"] += 1
                            else:
                                AUTO_SESSION_STATE["failed"] += 1
                    else:
                        with AUTO_SESSION_LOCK:
                            AUTO_SESSION_STATE["skipped"] += 1
                            AUTO_SESSION_STATE["message"] = "Сессия действительна"
                except Exception as exc:
                    log_event("Auto Reload Session: "+str(exc),"ERROR",login)
                    with AUTO_SESSION_LOCK:
                        AUTO_SESSION_STATE["failed"] += 1
                finally:
                    with AUTO_SESSION_LOCK:
                        AUTO_SESSION_STATE["done"] = index+1
            if (
                index+1 < len(logins)
                and cooldown
                and not auto_session_sleep(run_id,10)
            ):
                cancelled = True
                break
    finally:
        save_account_cache()
        with AUTO_SESSION_LOCK:
            if AUTO_SESSION_RUN_ID==run_id:
                AUTO_SESSION_STATE["running"] = False
                AUTO_SESSION_STATE["cancelling"] = False
                AUTO_SESSION_STATE["current"] = ""
                AUTO_SESSION_STATE["message"] = "Отменено" if cancelled else "Проверка сессий завершена"


def start_auto_session_reload():
    global AUTO_SESSION_RUN_ID
    with AUTO_SESSION_LOCK:
        if AUTO_SESSION_STATE.get("running"):
            return False,"Восстановление сессий уже выполняется"
    logins = [a["login"] for a in read_logpass()[0]]
    if not logins:
        return False,"Нет аккаунтов для проверки"
    with AUTO_SESSION_LOCK:
        AUTO_SESSION_RUN_ID += 1
        run_id = AUTO_SESSION_RUN_ID
        AUTO_SESSION_STATE.update({
            "running":True,"cancelling":False,"current":"","done":0,"total":len(logins),
            "reloaded":0,"failed":0,"skipped":0,"message":"Подготовка очереди"
        })
    threading.Thread(target=auto_session_worker,args=(logins,run_id),daemon=True,name="AutoReloadSessions").start()
    return True,"Проверка сессий запущена"


def cancel_auto_session_reload():
    with AUTO_SESSION_LOCK:
        if AUTO_SESSION_STATE.get("running"):
            AUTO_SESSION_STATE["cancelling"] = True
            AUTO_SESSION_STATE["message"] = "Отмена после текущего аккаунта"


def set_auto_session_enabled(enabled):
    enabled = bool(enabled)
    _write_json_object(AUTO_SESSION_SETTINGS_FILE,{"enabled":enabled})
    with AUTO_SESSION_LOCK:
        AUTO_SESSION_STATE["enabled"] = enabled
    if not enabled:
        cancel_auto_session_reload()


@app.route("/api/session/auto-reload",methods=["GET","POST","DELETE"])
def api_auto_session_reload():
    if request.method=="GET":
        return jsonify({"ok":True,**auto_session_status()})
    if request.method=="DELETE":
        cancel_auto_session_reload()
        return jsonify({"ok":True,**auto_session_status()})
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled",True))
    set_auto_session_enabled(enabled)
    if not enabled:
        return jsonify({"ok":True,"message":"Auto Reload Session выключен",**auto_session_status()})
    ok,message = start_auto_session_reload()
    return jsonify({"ok":ok,"message":message,**auto_session_status()}),(200 if ok else 409)


@app.route("/api/booster/settings",methods=["GET","POST"])
def api_booster_settings():
    if request.method == "GET":
        saved = _read_json_object(BOOSTER_SETTINGS_FILE)
        accounts = saved.get("accounts") if isinstance(saved.get("accounts"),dict) else {}
        login = str(request.args.get("login") or "").strip()
        appids = accounts.get(login) if login else saved.get("app_ids")
        if appids is None:
            appids = saved.get("app_ids") or "0"
        return jsonify({"ok":True,"app_ids":str(appids),"login":login,"account_specific":bool(login and login in accounts)})
    data = request.get_json(silent=True) or {}
    login = str(data.get("login") or "").strip()
    if data.get("apply_all"):
        try:
            appids,count = save_booster_settings_for_all(data.get("app_ids"))
        except ValueError as exc:
            return jsonify({"ok":False,"message":str(exc)}),400
        return jsonify({"ok":True,"app_ids":appids,"applied":count,"message":"Настройки применены ко всем аккаунтам: "+str(count)+". Booster не запущен"})
    if login and login not in [a["login"] for a in read_logpass()[0]]:
        return jsonify({"ok":False,"message":"Аккаунт не найден"}),404
    try:
        appids = save_booster_settings(data.get("app_ids"),login or None)
    except ValueError as exc:
        return jsonify({"ok":False,"message":str(exc)}),400
    return jsonify({"ok":True,"app_ids":appids,"login":login})


@app.route("/api/booster/queue",methods=["GET"])
def api_booster_queue():
    return jsonify({"ok":True,**booster_queue_status()})


@app.route("/api/booster/start",methods=["POST"])
def api_booster_start():
    data = request.get_json(silent=True) or {}
    account_login = str(data.get("login") or "").strip()
    try:
        appids = save_booster_settings(data.get("app_ids"),account_login or None)
    except ValueError as exc:
        return jsonify({"ok":False,"message":str(exc)}),400
    requested = [account_login] if account_login else (data.get("logins") or [])
    if not isinstance(requested,list):
        return jsonify({"ok":False,"message":"Некорректный список аккаунтов"}),400
    available = [a["login"] for a in read_logpass()[0]]
    wanted = set(str(v) for v in requested)
    logins = [login for login in available if login in wanted]
    if not logins:
        return jsonify({"ok":False,"message":"Сначала выберите аккаунты галочками"}),400
    queue_appids = appids
    if data.get("use_account_settings"):
        saved = _read_json_object(BOOSTER_SETTINGS_FILE)
        accounts = saved.get("accounts") if isinstance(saved.get("accounts"),dict) else {}
        queue_appids = {login:str(accounts.get(login) or appids) for login in logins}
    with BOOSTER_QUEUE_LOCK:
        if BOOSTER_QUEUE_STATE.get("running"):
            return jsonify({"ok":False,"message":"Очередь Booster уже выполняется"}),409
        BOOSTER_QUEUE_STATE.update({
            "running":True,"current":"","done":0,"total":len(logins),"started":[],"errors":{},
            "logins":logins,"last_login":"","last_ok":False,"last_message":"","message":"Подготовка очереди"
        })
    threading.Thread(target=booster_start_worker,args=(logins,queue_appids),daemon=True,name="BoosterStartQueue").start()
    message = "Очередь Booster запущена: "+str(len(logins))+" аккаунтов"
    return jsonify({"ok":True,"message":message,"started":[],"queued":logins,"errors":{},"app_ids":appids})


@app.route("/api/booster/stop",methods=["POST"])
def api_booster_stop():
    data = request.get_json(silent=True) or {}
    requested = data.get("logins") or []
    if not isinstance(requested,list):
        return jsonify({"ok":False,"message":"Некорректный список аккаунтов"}),400
    stopped = []
    for login in requested:
        login = str(login).strip()
        if login:
            stop_activity_booster(login)
            stopped.append(login)
    return jsonify({"ok":True,"message":"Booster остановлен: "+str(len(stopped)),"stopped":stopped})


@app.route("/api/settings/steam-path",methods=["GET","POST"])
def api_steam_path_settings():
    if request.method == "GET":
        path = _steam_path()
        valid = path.name.casefold()=="steam.exe" and path.is_file()
        return jsonify({"ok":True,"steam_path":str(path),"valid":valid,"saved":bool(_saved_steam_path())})
    data = request.get_json(silent=True) or {}
    try:
        path = validate_steam_path(data.get("steam_path"))
        _write_json_object(STEAM_SETTINGS_FILE,{"steam_path":str(path)})
        if _saved_steam_path()!=str(path):
            raise OSError("файл настроек не был записан")
    except ValueError as exc:
        return jsonify({"ok":False,"message":str(exc)}),400
    except OSError as exc:
        return jsonify({"ok":False,"message":"Не удалось сохранить путь: "+str(exc)}),500
    return jsonify({"ok":True,"steam_path":str(path),"valid":True,"saved":True,"message":"steam.exe найден, путь сохранён"})


@app.route("/api/settings/theme",methods=["GET","POST"])
def api_theme_settings():
    if request.method == "GET":
        saved = _read_json_object(THEME_SETTINGS_FILE)
        theme = saved.get("theme") if isinstance(saved.get("theme"),dict) else {}
        return jsonify({"ok":True,"theme":theme})
    data = request.get_json(silent=True) or {}
    theme = data.get("theme") if isinstance(data.get("theme"),dict) else data
    fields = ("bg","bg2","panel","accent","text","muted","border","success")
    if any(not re.fullmatch(r"#[0-9a-fA-F]{6}",str(theme.get(key,""))) for key in fields):
        return jsonify({"ok":False,"message":"Некорректные цвета оформления"}),400
    clean = {key:str(theme[key]).lower() for key in fields}
    _write_json_object(THEME_SETTINGS_FILE,{"theme":clean})
    return jsonify({"ok":True,"theme":clean})


def ensure_auth_helper():
    try:
        if not AUTH_HELPER.exists() or AUTH_HELPER.read_text(encoding="utf-8") != STEAM_AUTH_HELPER:
            AUTH_HELPER.write_text(STEAM_AUTH_HELPER, encoding="utf-8")
        return True
    except OSError:
        return False

def find_account_credentials(login):
    if not LOGPASS_FILE.exists():
        return None
    try:
        raw = None
        for encoding in ("utf-8-sig", "utf-8", "cp1251"):
            try:
                raw = LOGPASS_FILE.read_text(encoding=encoding)
                break
            except UnicodeDecodeError:
                continue
        if raw is None:
            return None
        wanted = login.strip().casefold()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            acc_login, password = line.split(":", 1)
            if acc_login.strip().casefold() == wanted:
                return acc_login.strip(), password.strip()
    except OSError:
        pass
    return None

def _iter_mafiles():
    """Yield every maFile regardless of .mafile/.maFile casing."""
    if not MAFILES_DIR.exists() or not MAFILES_DIR.is_dir():
        return
    seen = set()
    try:
        for path in MAFILES_DIR.iterdir():
            if not path.is_file() or path.suffix.casefold() != ".mafile":
                continue
            key = str(path.resolve()).casefold()
            if key in seen:
                continue
            seen.add(key)
            yield path
    except OSError:
        return


def _read_mafile(path):
    try:
        try:
            raw = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        # Different maFile exporters store SteamID in different places.
        # Support both the legacy top-level field and the common Session.SteamID.
        session = data.get("Session")
        if not isinstance(session, dict):
            session = {}
        steamid = str(
            data.get("steamid")
            or data.get("steam_id")
            or session.get("SteamID")
            or ""
        ).strip()
        shared_secret = str(data.get("shared_secret") or "").strip()
        identity_secret = str(data.get("identity_secret") or "").strip()
        device_id = str(data.get("device_id") or session.get("device_id") or "").strip()
        account_name = str(data.get("account_name") or "").strip()
        steam_login_secure = str(session.get("steamLoginSecure") or session.get("SteamLoginSecure") or "").strip()
        session_id = str(session.get("SessionID") or session.get("sessionid") or "").strip()
        access_token = str(session.get("AccessToken") or "").strip()
        refresh_token = str(session.get("RefreshToken") or "").strip()
        if not account_name:
            account_name = path.stem.strip()
        if not re.fullmatch(r"7656119\d{10}", steamid) or not shared_secret:
            return None
        return {
            "steamid": steamid,
            "shared_secret": shared_secret,
            "identity_secret": identity_secret,
            "device_id": device_id,
            "steam_login_secure": steam_login_secure,
            "session_id": session_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "account_name": account_name,
            "filename": path.name,
            "stem": path.stem,
        }
    except (OSError, UnicodeDecodeError, ValueError, TypeError):
        return None


def find_mafile_data(login):
    """
    Find a Steam maFile by BOTH supported naming schemes:
      1) <login>.mafile
      2) <steamid>.mafile
    The filename match is preferred. For <steamid>.mafile, account_name
    inside the JSON is used to map it back to the login. Extension casing
    is ignored. The shared_secret is never written to logs.
    """
    wanted = str(login or "").strip().casefold()
    if not wanted or not MAFILES_DIR.exists() or not MAFILES_DIR.is_dir():
        return None

    files = list(_iter_mafiles())

    # 1. Exact <login>.mafile match. This is the fastest and most reliable path.
    for path in files:
        if path.stem.strip().casefold() != wanted:
            continue
        data = _read_mafile(path)
        if data:
            return {"steamid": data["steamid"], "shared_secret": data["shared_secret"], "identity_secret": data.get("identity_secret", ""), "device_id": data.get("device_id", ""), "steam_login_secure": data.get("steam_login_secure", ""), "session_id": data.get("session_id", ""), "access_token": data.get("access_token", ""), "refresh_token": data.get("refresh_token", "")}

    # 2. Exact login stored inside a <steamid>.mafile (or any other maFile).
    for path in files:
        data = _read_mafile(path)
        if not data:
            continue
        if data["account_name"].casefold() == wanted:
            return {"steamid": data["steamid"], "shared_secret": data["shared_secret"], "identity_secret": data.get("identity_secret", ""), "device_id": data.get("device_id", ""), "steam_login_secure": data.get("steam_login_secure", ""), "session_id": data.get("session_id", ""), "access_token": data.get("access_token", ""), "refresh_token": data.get("refresh_token", "")}

    return None

FX_CACHE = {}
FX_LOCK = threading.Lock()

def _load_fx_cache():
    global FX_CACHE
    try:
        if FX_CACHE_FILE.exists():
            data = json.loads(FX_CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("rates"), dict):
                FX_CACHE = {str(k).upper(): float(v) for k, v in data["rates"].items() if isinstance(v, (int, float))}
    except (OSError, ValueError, TypeError):
        FX_CACHE = {}


def _save_fx_cache(rates):
    try:
        tmp = FX_CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"base":"USD", "rates":rates, "updated":datetime.datetime.now().isoformat(timespec="seconds")}, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(FX_CACHE_FILE)
    except (OSError, TypeError, ValueError):
        pass


def get_usd_rates():
    """Return USD-base exchange rates; use a local cache if the network is unavailable."""
    global FX_CACHE
    with FX_LOCK:
        if not FX_CACHE:
            _load_fx_cache()
        try:
            req = urllib.request.Request("https://open.er-api.com/v6/latest/USD", headers={"User-Agent":"GSM 1.0.2"})
            with urllib.request.urlopen(req, timeout=8) as response:
                data = json.loads(response.read().decode("utf-8"))
            rates = data.get("rates", {}) if isinstance(data, dict) else {}
            if isinstance(rates, dict):
                fresh = {str(k).upper(): float(v) for k, v in rates.items() if isinstance(v, (int, float)) and float(v) > 0}
                fresh["USD"] = 1.0
                if fresh:
                    FX_CACHE = fresh
                    _save_fx_cache(fresh)
        except Exception:
            pass
        return dict(FX_CACHE)


def currency_from_text(text):
    text = str(text or "")
    pairs = [("R$","BRL"),("zł","PLN"),("CHF","CHF"),("NZ$","NZD"),("A$","AUD"),("C$","CAD"),("MX$","MXN"),("S$","SGD"),("₱","PHP"),("฿","THB"),("₫","VND"),("₺","TRY"),("₽","RUB"),("₴","UAH"),("₸","KZT"),("₩","KRW"),("₹","INR"),("€","EUR"),("£","GBP"),("¥","JPY"),("$","USD")]
    for marker, code in pairs:
        if marker in text:
            return code
    m = re.search(r"\b(USD|EUR|GBP|CHF|RUB|PLN|BRL|JPY|NOK|SEK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|KZT|DKK|CZK|HUF|RON|ISK|TWD|SAR|AED|ARS|ILS|KWD|QAR|CRC|UYU|BGN|HRK|COP|PEN|CLP|ZAR|HKD)\b", text, re.I)
    return m.group(1).upper() if m else ""


def convert_balance_to_usd(balance, currency=""):
    """Legacy compatibility: balance is intentionally never converted.
    Steam wallet values are displayed in their original currency.
    """
    return str(balance or "").strip()


def download_avatar(avatar_url, steamid):
    if not avatar_url or not steamid:
        return None
    try:
        AVATARS_DIR.mkdir(parents=True, exist_ok=True)
        suffix = ".jpg"
        target = AVATARS_DIR / (steamid + suffix)
        req = urllib.request.Request(
            avatar_url,
            headers={"User-Agent":"Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            data = response.read()
        if data:
            target.write_bytes(data)
            return "/avatars/" + target.name
    except Exception:
        return None
    return None

def analyze_project_node_dependencies():
    """Analyze project files in the app.py directory and return npm package names."""
    packages = {"steam-user", "steam-totp"}
    try:
        package_json = BASE_DIR / "package.json"
        if package_json.exists():
            data = json.loads(package_json.read_text(encoding="utf-8"))
            for key in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = data.get(key, {})
                if isinstance(deps, dict):
                    packages.update(str(k).strip() for k in deps if str(k).strip())
    except Exception as exc:
        log_event("package.json analysis error: " + str(exc), "WARN")

    patterns = [
        re.compile(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)"),
        re.compile(r"from\s+['\"]([^'\"]+)['\"]"),
        re.compile(r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
    ]
    skip = {"fs","path","os","url","util","events","http","https","crypto","stream","buffer","child_process","timers","assert","net","tls","zlib","querystring","string_decoder","module"}
    try:
        for path in BASE_DIR.rglob("*.js"):
            if any(part in {"node_modules", ".git", "_node_install_tmp"} for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pattern in patterns:
                for name in pattern.findall(text):
                    name = name.strip()
                    if name.startswith(".") or name.startswith("node:"):
                        continue
                    if name in skip:
                        continue
                    # Only accept syntactically valid npm package names.
                    # This prevents comments/ordinary quoted text from being
                    # mistaken for a dependency by the broad import regex.
                    name = name.strip()
                    if name.startswith("@"):
                        parts = name.split("/")
                        if len(parts) < 2 or not re.fullmatch(r"@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", "/".join(parts[:2])):
                            continue
                        package_name = "/".join(parts[:2])
                    else:
                        package_name = name.split("/")[0]
                        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", package_name):
                            continue
                    packages.add(package_name)
    except OSError as exc:
        log_event("JS dependency scan error: " + str(exc), "WARN")
    return sorted(packages)

def get_node_executable():
    """Prefer the bundled Node.js runtime, but fully support system Node.js."""
    if NODE_EXE.exists():
        return str(NODE_EXE)
    return shutil.which("node") or shutil.which("node.exe") or None


def get_npm_command():
    """Return a usable local npm command without requiring bundled Node.js."""
    if NODE_EXE.exists() and NPM_CLI.exists():
        return [str(NODE_EXE),str(NPM_CLI)]
    npm = shutil.which("npm.cmd") or shutil.which("npm") or shutil.which("npm.exe")
    return [npm] if npm else None


def node_modules_ready():
    """Check the exact local modules used by the Steam auth helper."""
    modules = NODE_DIR / "node_modules"
    required = (
        modules / "steam-user",
        modules / "steam-totp",
    )
    if not all(path.exists() for path in required):
        return False
    node = get_node_executable()
    if not node:
        return False
    env = os.environ.copy()
    env["NODE_PATH"] = str(modules)
    try:
        for package in ("steam-user", "steam-totp"):
            proc = subprocess.run(
                [node, "-e", f"require.resolve({package!r})"],
                cwd=str(NODE_DIR if NODE_DIR.exists() else BASE_DIR),
                env=env,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode != 0:
                return False
        return True
    except Exception:
        return False


def node_ready():
    node = get_node_executable()
    modules_ready = node_modules_ready()
    if not node or not modules_ready:
        return False
    try:
        proc = subprocess.run([node, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return proc.returncode == 0 and bool(proc.stdout.strip())
    except Exception:
        return False

def ensure_bundled_node_gyp():
    """Repair npm's bundled node-gyp if the Node ZIP contains an incomplete npm tree."""
    target = NODE_DIR / "node_modules" / "npm" / "node_modules" / "node-gyp"
    entry = target / "bin" / "node-gyp.js"
    if entry.exists():
        return True
    NODE_INSTALL_STATE["message"] = "Восстановление npm/node-gyp..."
    log_event("npm bundled node-gyp is missing; repairing npm runtime", "WARN")
    tmp = BASE_DIR / "_node_gyp_tmp.tgz"
    extract = BASE_DIR / "_node_gyp_extract"
    try:
        req = urllib.request.Request(
            "https://registry.npmjs.org/node-gyp/latest",
            headers={"User-Agent":"GSM 1.0.2"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            meta = json.loads(response.read().decode("utf-8"))
        tarball = meta.get("dist", {}).get("tarball")
        if not tarball:
            raise RuntimeError("Не найден tarball node-gyp в npm registry")
        with urllib.request.urlopen(urllib.request.Request(tarball, headers={"User-Agent":"GSM 1.0.2"}), timeout=60) as response, open(tmp, "wb") as out:
            shutil.copyfileobj(response, out)
        if extract.exists():
            shutil.rmtree(extract, ignore_errors=True)
        extract.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp, "r") if tmp.suffix.lower()==".zip" else __import__("tarfile").open(tmp, "r:gz") as archive:
            archive.extractall(extract)
        roots = [x for x in extract.iterdir() if x.is_dir()]
        if not roots:
            raise RuntimeError("Архив node-gyp пустой")
        source = roots[0]
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(source, target)
        if not entry.exists():
            raise RuntimeError("node-gyp.js не найден после восстановления")
        log_event("npm bundled node-gyp repaired", "INFO")
        return True
    except Exception as exc:
        log_event("node-gyp repair failed: " + str(exc), "ERROR")
        return False
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        shutil.rmtree(extract, ignore_errors=True)


def run_npm_install(packages, env):
    """Install local modules through bundled or system Node.js/npm."""
    npm_command = get_npm_command()
    if not npm_command:
        raise RuntimeError("npm не найден. Установите Node.js вместе с npm или повторите установку через «Скачать Node.js»")
    NODE_DIR.mkdir(parents=True,exist_ok=True)
    cmd = [*npm_command, "install", "--location=project", "--prefix", str(NODE_DIR), "--no-audit", "--no-fund", "--ignore-scripts", *packages]
    log_event("npm install started: " + ", ".join(packages))
    NODE_INSTALL_STATE["message"] = "npm: установка зависимостей..."
    env = dict(env)
    env["npm_config_global"] = "false"
    env["npm_config_location"] = "project"
    env["npm_config_prefix"] = str(NODE_DIR)
    proc = subprocess.Popen(
        cmd,
        cwd=str(NODE_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    output = []
    try:
        deadline = time.time() + 900
        for line in iter(proc.stdout.readline, ""):
            if time.time() > deadline:
                proc.kill()
                raise TimeoutError("npm install превысил лимит 15 минут")
            clean = line.replace("\r", " ").strip()
            if clean:
                output.append(clean)
                if len(output) > 60:
                    output.pop(0)
                short = clean[-180:]
                NODE_INSTALL_STATE["message"] = "npm: " + short
                # Keep the persistent log useful without dumping npm's full output.
                if "ERR!" in clean or "error" in clean.lower() or "warn" in clean.lower():
                    log_event("npm: " + short, "WARN" if "warn" in clean.lower() else "ERROR")
        proc.stdout.close()
        rc = proc.wait(timeout=15)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    if rc != 0:
        raise RuntimeError("npm install завершился с кодом %s: %s" % (rc, " | ".join(output[-12:])[-1800:]))
    missing = []
    for package in packages:
        if package.startswith("@"):
            path = NODE_DIR / "node_modules" / Path(package)
        else:
            path = NODE_DIR / "node_modules" / package
        if not path.exists():
            missing.append(package)
    if missing:
        raise RuntimeError("npm завершился успешно, но модули не установлены локально в nodejs\\node_modules: " + ", ".join(missing))
    return True


def install_node_runtime():
    with NODE_INSTALL_LOCK:
        if node_ready():
            NODE_INSTALL_STATE.update({"status":"ready", "message":"Node.js уже установлен"})
            return True, "Node.js уже установлен"
        NODE_INSTALL_STATE.update({"status":"installing", "message":"Скачивание Node.js..."})
        log_event("Node.js installation started")
        temp_dir = BASE_DIR / "_node_install_tmp"
        try:
            temp_dir.mkdir(parents=True, exist_ok=True)
            system_node = get_node_executable()
            bundled_npm = NODE_EXE.exists() and NPM_CLI.exists()
            if system_node and get_npm_command() and not bundled_npm:
                NODE_INSTALL_STATE["message"] = "Системный Node.js найден. Установка steam-user и steam-totp..."
                packages = analyze_project_node_dependencies()
                env = os.environ.copy()
                env["PATH"] = str(Path(system_node).parent)+os.pathsep+str(NODE_DIR)+os.pathsep+env.get("PATH","")
                run_npm_install(packages,env)
                if not node_ready():
                    raise RuntimeError("Системный Node.js найден, но локальные steam-user/steam-totp не прошли require.resolve после npm install")
                NODE_INSTALL_STATE.update({"status":"ready","message":"Системный Node.js: steam-user и steam-totp установлены"})
                log_event("System Node.js reused; local Steam npm modules verified")
                return True,"Системный Node.js найден. Необходимые модули установлены"
            NODE_INSTALL_STATE["message"] = "Скачивание Node.js LTS..."
            req = urllib.request.Request(NODE_ZIP_URL, headers={"User-Agent":"GSM 1.0.2"})
            with urllib.request.urlopen(req, timeout=60) as response, open(NODE_ZIP_FILE, "wb") as out:
                total = int(response.headers.get("Content-Length") or 0)
                done = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    if total:
                        NODE_INSTALL_STATE["message"] = "Скачивание Node.js: %d%%" % int(done * 100 / total)

            NODE_INSTALL_STATE["message"] = "Распаковка Node.js..."
            extract_dir = temp_dir / "extract"
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)
            extract_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(NODE_ZIP_FILE, "r") as zf:
                zf.extractall(extract_dir)
            roots = [x for x in extract_dir.iterdir() if x.is_dir()]
            if not roots:
                raise RuntimeError("Архив Node.js пустой")
            source = roots[0]
            if NODE_EXE.exists() and NPM_CLI.exists():
                log_event('Existing Node.js runtime detected; reusing nodejs directory')
            else:
                if NODE_DIR.exists():
                    shutil.rmtree(NODE_DIR, ignore_errors=True)
                    if NODE_DIR.exists():
                        raise RuntimeError('Не удалось очистить старую папку nodejs; она занята другим процессом')
                shutil.copytree(source, NODE_DIR)

            if not NODE_EXE.exists() or not NPM_CLI.exists():
                raise RuntimeError("Не найден node.exe или встроенный npm после установки")

            if not ensure_bundled_node_gyp():
                raise RuntimeError("Не удалось восстановить node-gyp внутри npm")

            packages = analyze_project_node_dependencies()
            NODE_INSTALL_STATE["message"] = "Анализ проекта: " + ", ".join(packages)
            log_event("Node dependency scan: " + ", ".join(packages))
            env = os.environ.copy()
            env["PATH"] = str(NODE_DIR) + os.pathsep + env.get("PATH", "")
            run_npm_install(packages, env)
            if not node_ready():
                raise RuntimeError("Node.js установлен, но steam-user/steam-totp не прошли проверку require.resolve")

            NODE_INSTALL_STATE.update({"status":"ready", "message":f"Node.js {NODE_VERSION} установлен"})
            log_event(f"Node.js {NODE_VERSION} installed successfully; local npm modules verified")
            return True, f"Node.js {NODE_VERSION} установлен и зависимости готовы"
        except Exception as exc:
            NODE_INSTALL_STATE.update({"status":"error", "message":str(exc)})
            log_event("Node.js installation error: " + str(exc), "ERROR")
            return False, str(exc)
        finally:
            try:
                if NODE_ZIP_FILE.exists():
                    NODE_ZIP_FILE.unlink()
            except OSError:
                pass
            shutil.rmtree(temp_dir, ignore_errors=True)

@app.route("/api/node/status")
def api_node_status():
    if node_ready():
        NODE_INSTALL_STATE["status"] = "ready"
    elif NODE_INSTALL_STATE.get("status") != "installing":
        NODE_INSTALL_STATE["status"] = "not_installed"
    return jsonify({"ok":NODE_INSTALL_STATE["status"]=="ready", "status":NODE_INSTALL_STATE["status"], "message":NODE_INSTALL_STATE.get("message", ""), "version":NODE_VERSION})

@app.route("/api/node/install", methods=["POST"])
def api_node_install():
    if NODE_INSTALL_STATE.get("status") == "installing":
        return jsonify({"ok":False,"message":"Установка Node.js уже выполняется"}), 409
    ok, message = install_node_runtime()
    return jsonify({"ok":ok,"message":message,"status":NODE_INSTALL_STATE.get("status")}), (200 if ok else 500)

def _authorize_account_worker_impl(login):
    with AUTH_LOCK:
        state = AUTH_STATE.setdefault(login, {})
        state.update({"auth_status":"running","auth_error":""})
    log_event("Authorization started", "INFO", login)
    creds = find_account_credentials(login)
    ma = find_mafile_data(login)
    if not creds:
        with AUTH_LOCK:
            AUTH_STATE[login].update({"auth_status":"error","auth_error":"Не найден login:password в logpass.txt"})
        log_event("Credentials not found in logpass.txt", "ERROR", login)
        return
    if not ma:
        with AUTH_LOCK:
            AUTH_STATE[login].update({"auth_status":"error","auth_error":"Не найден maFile/shared_secret для аккаунта"})
        log_event("maFile/shared_secret not found", "ERROR", login)
        return
    if not ensure_auth_helper():
        with AUTH_LOCK:
            AUTH_STATE[login].update({"auth_status":"error","auth_error":"Не удалось создать auth helper"})
        log_event("Unable to create auth helper", "ERROR", login)
        return

    try:
        node_exe = get_node_executable()
        if not node_exe or not node_ready():
            ok, message = install_node_runtime()
            if not ok:
                with AUTH_LOCK:
                    AUTH_STATE[login].update({"auth_status":"error","auth_error":"Node.js: " + message})
                    log_event("Node.js error: " + message, "ERROR", login)
                return
            node_exe = get_node_executable()
        env = os.environ.copy()
        env["PATH"] = str(NODE_DIR) + os.pathsep + env.get("PATH", "")
        env["NODE_PATH"] = str(NODE_DIR / "node_modules")
        env["SHARK_STEAM_LOGIN"] = creds[0]
        env["SHARK_STEAM_PASSWORD"] = creds[1]
        env["SHARK_STEAM_SHARED_SECRET"] = ma["shared_secret"]
        env["SHARK_STEAM_ID"] = ma["steamid"]

        def run_auth_process(auth_env):
            return subprocess.run(
                [node_exe, str(AUTH_HELPER)],
                cwd=str(NODE_DIR), env=auth_env,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=45, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )

        saved_session = load_steam_session(login)
        used_session = bool(saved_session and saved_session.get("refresh_token"))
        if used_session:
            env["SHARK_STEAM_REFRESH_TOKEN"] = str(saved_session["refresh_token"])
            log_event("Trying encrypted Steam session first", "INFO", login)

        proc = run_auth_process(env)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        result = None
        helper_log_count = 0
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                log_event("Node stdout: " + line[:500], "WARN", login)
                continue
            if payload.get("type") == "log":
                helper_log_count += 1
                log_event(str(payload.get("message") or ""), str(payload.get("level") or "INFO"), login)
            elif "ok" in payload:
                result = payload

        if (not result or not result.get("ok")) and used_session:
            session_error = str((result or {}).get("error") or stderr.strip() or "session rejected")
            log_event("Saved Steam session rejected; falling back to login/password: " + session_error, "WARN", login)
            env.pop("SHARK_STEAM_REFRESH_TOKEN", None)
            proc = run_auth_process(env)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            result = None
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    log_event("Node stdout: " + line[:500], "WARN", login)
                    continue
                if payload.get("type") == "log":
                    helper_log_count += 1
                    log_event(str(payload.get("message") or ""), str(payload.get("level") or "INFO"), login)
                elif "ok" in payload:
                    result = payload
        if result is None:
            result = {"ok":False,"error":stderr.strip() or "Node не вернул итоговый результат"}
        log_event("Steam helper finished; exit_code=" + str(proc.returncode) + ", helper_logs=" + str(helper_log_count), "INFO" if result.get("ok") else "ERROR", login)
        if not result.get("ok"):
            err = str(result.get("error") or proc.stderr.strip() or "Авторизация не удалась")
            with AUTH_LOCK:
                AUTH_STATE[login].update({"auth_status":"error","auth_error":err})
                log_event("Steam authorization failed: " + err, "ERROR", login)
            return

        if result.get("refresh_token"):
            save_steam_session(login, result.get("refresh_token"), ma["steamid"])
        if result.get("web_cookies"):
            save_steam_web_cookies(login, result.get("web_cookies"))

        local_avatar = download_avatar(result.get("avatar_url",""), ma["steamid"])
        original_balance = result.get("balance") or ""
        original_currency = result.get("currency") or ""
        # Never convert Steam wallet balances to USD. Keep the exact native
        # currency returned by Steam (USD, RUB, KZT, IDR, EUR, etc.).
        shown_balance = original_balance or str(state.get("balance") or "")
        with AUTH_LOCK:
            AUTH_STATE[login].update({
                "auth_status":"ok",
                "auth_error":"",
                "balance":shown_balance,
                "original_balance":original_balance,
                "original_currency":original_currency,
                "avatar_url":local_avatar or result.get("avatar_url") or AUTH_STATE[login].get("avatar_url"),
                "steamid":ma["steamid"],
                "currency":original_currency,
                "country":result.get("country",""),
                # A successful Community scrape may legitimately return [] for an account with no games.
                # Never keep a stale previous library/count in that case.
                "games":(result.get("games") if isinstance(result.get("games"), list) else AUTH_STATE[login].get("games", [])),
                "games_count":(int(result.get("games_count")) if isinstance(result.get("games_count"), (int, float)) and int(result.get("games_count")) >= 0 else (len(result.get("games", [])) if isinstance(result.get("games"), list) else AUTH_STATE[login].get("games_count", 0))),
                "games_updated":(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") if isinstance(result.get("games"), list) else AUTH_STATE[login].get("games_updated", "")),
                "card_games":(result.get("card_games") if isinstance(result.get("card_games"), list) else AUTH_STATE[login].get("card_games", [])),
                "level":(result.get("level") if isinstance(result.get("level"), int) else AUTH_STATE[login].get("level")),
                "xp":(result.get("xp") if isinstance(result.get("xp"), int) else AUTH_STATE[login].get("xp")),
                "level_updated":(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") if isinstance(result.get("level"), int) else AUTH_STATE[login].get("level_updated", ""))
            })
        save_account_cache()
        if shown_balance:
            log_event("Authorized successfully; balance=" + str(shown_balance) + "; original_currency=" + str(original_currency) + "; source=" + str(result.get("balance_source") or "unknown"), "INFO", login)
        else:
            log_event("Authorized successfully, BUT balance was not collected; currency=" + str(result.get("currency") or "") + "; source=" + str(result.get("balance_source") or "none"), "WARN", login)
    except FileNotFoundError:
        with AUTH_LOCK:
            AUTH_STATE[login].update({"auth_status":"error","auth_error":"Node.js не найден. Нажмите «Скачать Node.js»."})
        log_event("Node.js executable not found", "ERROR", login)
    except subprocess.TimeoutExpired:
        with AUTH_LOCK:
            AUTH_STATE[login].update({"auth_status":"error","auth_error":"Тайм-аут авторизации Steam"})
        log_event("Steam authorization timeout", "ERROR", login)
    except Exception as exc:
        with AUTH_LOCK:
            AUTH_STATE[login].update({"auth_status":"error","auth_error":str(exc)})
        log_event("Authorization exception: " + str(exc), "ERROR", login)

BULK_REFRESH_LOCK = threading.Lock()
BULK_REFRESH_STATE = {"running":False,"current":"","done":0,"total":0,"updated":0,"failed":0}

def bulk_refresh_status():
    with BULK_REFRESH_LOCK:
        return dict(BULK_REFRESH_STATE)

def bulk_refresh_worker(logins):
    updated = 0
    failed = 0
    try:
        for index, login in enumerate(logins):
            with AUTH_LOCK:
                if login in ACTIVE_AUTH:
                    failed += 1
                    continue
            with BULK_REFRESH_LOCK:
                BULK_REFRESH_STATE.update({"current":login,"done":index})
            # The existing authorization worker reuses the encrypted refresh
            # token and updates balance, Level/XP, library and card drops.
            # It never launches the Steam client. Deliberately no parallelism.
            _authorize_account_worker_impl(login)
            with AUTH_LOCK:
                ok = AUTH_STATE.get(login, {}).get("auth_status") == "ok"
            if ok:
                updated += 1
            else:
                failed += 1
            save_account_cache()
            with BULK_REFRESH_LOCK:
                BULK_REFRESH_STATE.update({"done":index+1,"updated":updated,"failed":failed})
            # A manual batch is intentionally slow: one account at a time and
            # a cooldown between accounts to avoid bursts of Steam requests.
            if index + 1 < len(logins):
                time.sleep(8)
        # One batched GetPlayerBans request per 100 accounts, not one per account.
        valid = []
        for login in logins:
            with AUTH_LOCK:
                if AUTH_STATE.get(login, {}).get("auth_status") == "ok":
                    valid.append(login)
        if valid and load_steam_api_key():
            try:
                with app.test_request_context("/api/bans", method="POST", json={"logins":valid}):
                    response = api_check_bans()
                    payload = response[0] if isinstance(response, tuple) else response
                    if hasattr(payload, "get_json"):
                        result = payload.get_json(silent=True) or {}
                        if not result.get("ok"):
                            log_event("Массовое обновление: ограничения не обновлены: " + str(result.get("message") or "ошибка"), "WARN")
            except Exception as exc:
                log_event("Массовое обновление ограничений: " + str(exc), "WARN")
    finally:
        with BULK_REFRESH_LOCK:
            BULK_REFRESH_STATE.update({"running":False,"current":""})
        save_account_cache()

@app.route("/api/accounts/refresh-data", methods=["GET", "POST"])
def api_refresh_account_data():
    if request.method == "GET":
        return jsonify({"ok":True, **bulk_refresh_status()})
    data = request.get_json(silent=True) or {}
    requested = data.get("logins", [])
    if not isinstance(requested, list):
        return jsonify({"ok":False,"message":"Некорректный список аккаунтов."}), 400
    available = {a["login"] for a in read_logpass()[0]}
    logins = list(dict.fromkeys(str(v).strip() for v in requested if str(v).strip() in available))
    if not logins:
        return jsonify({"ok":False,"message":"Сначала выберите аккаунты."}), 400
    with BULK_REFRESH_LOCK:
        if BULK_REFRESH_STATE.get("running"):
            return jsonify({"ok":False,"message":"Массовое обновление уже выполняется."}), 409
        BULK_REFRESH_STATE.update({"running":True,"current":"","done":0,"total":len(logins),"updated":0,"failed":0})
    threading.Thread(target=bulk_refresh_worker, args=(logins,), daemon=True).start()
    return jsonify({"ok":True, **bulk_refresh_status()})

def authorize_account_worker(login):
    try:
        _authorize_account_worker_impl(login)
    finally:
        with AUTH_LOCK:
            ACTIVE_AUTH.discard(login)
        save_account_cache()

def start_authorization(login):
    login = str(login or "").strip()
    if not login:
        return False
    with AUTH_LOCK:
        if login in ACTIVE_AUTH:
            return False
        ACTIVE_AUTH.add(login)
        AUTH_STATE.setdefault(login, {}).update({"auth_status":"running", "auth_error":""})
    try:
        threading.Thread(target=authorize_account_worker, args=(login,), daemon=True).start()
    except Exception:
        with AUTH_LOCK:
            ACTIVE_AUTH.discard(login)
            AUTH_STATE.setdefault(login, {})["auth_status"] = "error"
            AUTH_STATE[login]["auth_error"] = "Не удалось запустить поток авторизации"
        save_account_cache()
        return False
    return True

@app.route("/api/authorize/<path:login>", methods=["POST"])
def api_authorize(login):
    if not start_authorization(login):
        return jsonify({"ok":False,"message":"Авторизация уже выполняется для этого аккаунта"}), 409
    return jsonify({"ok":True})

@app.route("/avatars/<path:name>")
def avatar_file(name):
    safe = Path(name).name
    target = AVATARS_DIR / safe
    if not target.exists() or target.parent != AVATARS_DIR:
        return ("", 404)
    return Response(target.read_bytes(), mimetype="image/jpeg")

STEAM_PROCESS_SCAN_LOCK = threading.Lock()
STEAM_PROCESS_SCAN_CACHE = {"at":0.0,"profiles":{}}


def _isolated_steam_processes():
    """Return one short-lived process snapshot keyed by isolated profile name."""
    now = time.monotonic()
    with STEAM_PROCESS_SCAN_LOCK:
        if now-STEAM_PROCESS_SCAN_CACHE["at"]<4:
            return dict(STEAM_PROCESS_SCAN_CACHE["profiles"])
        profiles = {}
        for proc in psutil.process_iter(["pid","name","cmdline"]):
            try:
                if str(proc.info.get("name") or "").casefold()!="steam.exe":
                    continue
                args = proc.info.get("cmdline") or []
                if not isinstance(args,(list,tuple)):
                    continue
                lowered = [str(arg).casefold() for arg in args]
                if "-master_ipc_name_override" not in lowered:
                    continue
                index = lowered.index("-master_ipc_name_override")
                if index+1>=len(args):
                    continue
                profile = str(args[index+1]).strip().casefold()
                if profile and profile not in profiles:
                    profiles[profile] = proc
            except (psutil.NoSuchProcess,psutil.AccessDenied,ProcessLookupError):
                continue
        STEAM_PROCESS_SCAN_CACHE.update({"at":now,"profiles":profiles})
        return dict(profiles)


def find_isolated_steam_process(login):
    profile = _safe_profile_name(login).casefold()
    proc = _isolated_steam_processes().get(profile)
    if not proc:
        return None
    try:
        if proc.is_running() and proc.status()!=psutil.STATUS_ZOMBIE:
            return proc
    except (psutil.NoSuchProcess,psutil.AccessDenied,ProcessLookupError):
        pass
    return None


def steam_process_alive(login):
    with STEAM_LAUNCH_LOCK:
        state = dict(STEAM_LAUNCHES.get(login, {}))
    pid = state.get("pid")
    if pid:
        try:
            proc = psutil.Process(int(pid))
            alive = proc.is_running() and proc.status()!=psutil.STATUS_ZOMBIE and proc.name().casefold()=="steam.exe"
            if alive:
                return True
        except (psutil.NoSuchProcess,psutil.AccessDenied,ProcessLookupError,ValueError):
            pass
    proc = find_isolated_steam_process(login)
    if proc:
        _steam_status(login,"running","Steam обнаружен после перезапуска менеджера",proc.pid)
        return True
    if pid:
        _steam_status(login,"idle","Steam закрыт",0)
    return False


LOGPASS_CACHE_LOCK = threading.Lock()
LOGPASS_CACHE = {"signature":None,"logins":[],"invalid":0,"exists":None}


def _read_logpass_entries(force=False):
    """Cache only validated logins; passwords are never retained in this cache."""
    try:
        stat = LOGPASS_FILE.stat()
        signature = (stat.st_mtime_ns,stat.st_size)
    except FileNotFoundError:
        with LOGPASS_CACHE_LOCK:
            LOGPASS_CACHE.update({"signature":None,"logins":[],"invalid":0,"exists":False})
        return [],0,False
    except OSError:
        return [],0,True
    with LOGPASS_CACHE_LOCK:
        if not force and LOGPASS_CACHE.get("exists") is True and LOGPASS_CACHE.get("signature")==signature:
            return list(LOGPASS_CACHE["logins"]),LOGPASS_CACHE["invalid"],True
        raw = None
        for encoding in ("utf-8-sig","utf-8","cp1251"):
            try:
                raw = LOGPASS_FILE.read_text(encoding=encoding)
                break
            except UnicodeDecodeError:
                continue
            except OSError:
                return [],0,True
        if raw is None:
            return [],0,True
        logins = []
        invalid = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                invalid += 1
                continue
            login,password = line.split(":",1)
            login = login.strip()
            password = password.strip()
            if not login or not password:
                invalid += 1
                continue
            logins.append(login)
        LOGPASS_CACHE.update({"signature":signature,"logins":list(logins),"invalid":invalid,"exists":True})
        return logins,invalid,True


def build_account_snapshot(login,account_id=1):
    """Build one account payload without loading any other account or session."""
    with AUTH_LOCK:
        auth = dict(AUTH_STATE.get(login, {}))
    saved_session = load_steam_session(login)
    return {"id":account_id,"login":login,"status":"Готов",
            "marked":login in MARKED_ACCOUNTS,
            "auth_status":auth.get("auth_status","idle"),
            "auth_error":auth.get("auth_error",""),
            "balance":auth.get("balance") or ("$0.00 USD" if auth.get("auth_status")=="ok" else ""),
            "avatar_url":auth.get("avatar_url"),
            "currency":auth.get("currency"),"country":auth.get("country",""),
            "level":auth.get("level"),"xp":auth.get("xp"),"level_updated":auth.get("level_updated",""),
            "games":auth.get("games",[]),"card_games":auth.get("card_games",[]),"games_count":auth.get("games_count",len(auth.get("games",[])) if isinstance(auth.get("games",[]),list) else 0),"games_updated":auth.get("games_updated",""),
            "steam_running":steam_process_alive(login),"farm_status":farm_status(login).get("status","idle"),"booster_status":booster_status(login).get("status","idle"),
            "session_status":("active" if auth.get("auth_status")=="ok" and saved_session else "relogin_required" if auth.get("auth_status")=="error" or not saved_session else "saved"),
            "session_saved_at":(saved_session or {}).get("saved_at",0),
            "community_banned":bool(auth.get("community_banned",False)),"vac_banned":bool(auth.get("vac_banned",False)),
            "game_banned":bool(auth.get("game_banned",False)),"bans_updated":auth.get("bans_updated",""),
            "limited_account":bool(auth.get("limited_account",False)),"trade_banned":bool(auth.get("trade_banned",False)),
            "trade_hold":bool(auth.get("trade_hold",False)),"market_hold":bool(auth.get("market_hold",False))}


def read_logpass(force=False):
    logins,invalid,exists = _read_logpass_entries(force=force)
    if not exists:
        return [],invalid,False
    accounts = [build_account_snapshot(login,index) for index,login in enumerate(logins,1)]
    return accounts,invalid,True


INVENTORY_CACHE_FILE = BASE_DIR / "inventory_cache.json"
TRADE_LOCK_HISTORY_FILE = BASE_DIR / "trade_lock_history.json"
MARKET_PRICE_CACHE_FILE = BASE_DIR / "market_price_cache.json"
INVENTORY_LOCK = threading.Lock()
INVENTORY_CACHE = {}
TRADE_LOCK_HISTORY = {}
PRICE_CACHE = {}
PRICE_WORKERS = {}
PRICE_STATE = {}

def _read_json_object(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}

def _write_json_object(path, value):
    try:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass

INVENTORY_CACHE = _read_json_object(INVENTORY_CACHE_FILE)
TRADE_LOCK_HISTORY = _read_json_object(TRADE_LOCK_HISTORY_FILE)
PRICE_CACHE = _read_json_object(MARKET_PRICE_CACHE_FILE)

STEAM_CURRENCY_IDS = {"USD":1,"GBP":2,"EUR":3,"CHF":4,"RUB":5,"PLN":6,"BRL":7,"JPY":8,"NOK":9,"IDR":10,"MYR":11,"PHP":12,"SGD":13,"THB":14,"VND":15,"KRW":16,"TRY":17,"UAH":18,"MXN":19,"CAD":20,"AUD":21,"NZD":22,"CNY":23,"INR":24,"CLP":25,"PEN":26,"COP":27,"ZAR":28,"HKD":29,"TWD":30,"SAR":31,"AED":32,"ARS":34,"ILS":35,"KZT":37}

def steam_currency_code(account):
    code = str(account.get("currency") or account.get("original_currency") or "").upper().strip()
    if code in STEAM_CURRENCY_IDS:
        return code
    balance = str(account.get("original_balance") or account.get("balance") or "").upper()
    match = re.search(r"\b("+"|".join(STEAM_CURRENCY_IDS)+r")\b",balance)
    if match:
        return match.group(1)
    for symbol,symbol_code in (("$","USD"),("£","GBP"),("€","EUR"),("₽","RUB"),("₴","UAH"),("₸","KZT"),("zł","PLN")):
        if symbol in balance:
            return symbol_code
    return "USD"

def steam_currency_id(account):
    return STEAM_CURRENCY_IDS.get(steam_currency_code(account),1)

def market_price_number(value):
    text = re.sub(r"[^0-9,.]", "", str(value or "")).replace(" ", "")
    if not text:
        return None
    if "." in text and "," in text:
        if text.rfind(",") > text.rfind("."):
            text = text.replace(".", "").replace(",", ".")
        else:
            text = text.replace(",", "")
    elif "," in text:
        parts = text.split(",")
        text = text.replace(",", ".") if len(parts[-1]) in (1,2) else text.replace(",", "")
    try:
        return float(text)
    except ValueError:
        return None

def inventory_cache_key(login, appid, contextid):
    return str(login) + ":" + str(appid) + ":" + str(contextid)

def inventory_cache_expiration(value):
    text = re.sub(r"\s+"," ",str(value or "")).strip()
    if not text:
        return 0
    if text.isdigit():
        return int(text)
    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z","+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return int(parsed.timestamp())
    except (ValueError, OverflowError, OSError):
        pass
    # Legacy Steam formats, with and without an explicit timezone.
    for fmt in (
        "%b %d, %Y (%H:%M:%S) GMT",
        "%b %d, %Y (%H:%M:%S) UTC",
        "%B %d, %Y (%H:%M:%S) GMT",
        "%B %d, %Y (%H:%M:%S) UTC",
        "%a, %b %d, %Y (%H:%M:%S) GMT",
        "%a, %b %d, %Y (%H:%M:%S) UTC",
        "%A, %B %d, %Y (%H:%M:%S) GMT",
        "%A, %B %d, %Y (%H:%M:%S) UTC",
        "%b %d, %Y (%H:%M:%S)",
        "%B %d, %Y (%H:%M:%S)",
        "%a, %b %d, %Y (%H:%M:%S)",
        "%A, %B %d, %Y (%H:%M:%S)",
        "%a, %b %d, %Y %I:%M:%S %p",
        "%b %d, %Y %I:%M:%S %p",
        "%a, %b %d, %Y %H:%M:%S",
        "%b %d, %Y %H:%M:%S",
    ):
        try:
            parsed = datetime.datetime.strptime(text,fmt).replace(tzinfo=datetime.timezone.utc)
            return int(parsed.timestamp())
        except ValueError:
            continue
    # Since June 2026 Steam also sends e.g. "04 Nov @ 12:00am",
    # without a year or timezone. Locks are near-future, so handle Dec/Jan.
    for fmt in ("%d %b @ %I:%M%p","%d %b @ %I:%M %p"):
        try:
            parsed = datetime.datetime.strptime(text,fmt)
            now = datetime.datetime.now(datetime.timezone.utc)
            parsed = parsed.replace(year=now.year,tzinfo=datetime.timezone.utc)
            if parsed < now-datetime.timedelta(days=2):
                parsed = parsed.replace(year=now.year+1)
            return int(parsed.timestamp())
        except ValueError:
            continue
    return 0


def inventory_trade_lock_notice(desc, asset):
    notices = []
    # Depending on app/context Steam puts the owner-only red notice in either
    # owner_descriptions or descriptions. Check both, with asset data first.
    for source in (asset,desc):
        for field in ("owner_descriptions","descriptions"):
            values = source.get(field) or []
            if isinstance(values,list):
                notices.extend(values)
    for notice in notices:
        text = str(notice.get("value") or "") if isinstance(notice,dict) else str(notice or "")
        text = re.sub(r"<[^>]+>"," ",text).replace("&nbsp;"," ")
        text = re.sub(r"\s+"," ",text).strip()
        match = re.search(r"\b(?:Tradable|Marketable)(?:\s*/\s*(?:Tradable|Marketable))?\s+After\s*:?\s+(.+)$",text,re.I)
        if match:
            return match.group(1).strip()
    return ""


def inventory_trade_lock_until(desc, asset):
    # item_expiration is used by newer owner-specific inventory responses;
    # cache_expiration and the red owner notice cover the older responses.
    for source in (asset,desc):
        for field in ("item_expiration","cache_expiration"):
            expires = inventory_cache_expiration(source.get(field))
            if expires:
                return expires
    return inventory_cache_expiration(inventory_trade_lock_notice(desc,asset))


def steam_inventory_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401,403):
            raise RuntimeError("Инвентарь приватный или Steam запретил доступ")
        if exc.code == 429:
            raise RuntimeError("Steam ограничил запросы. Попробуйте позже")
        raise RuntimeError("Steam Inventory HTTP " + str(exc.code))


def inventory_bool(value):
    if isinstance(value,str):
        return value.strip().lower() in ("1","true","yes")
    return bool(value)


def fetch_steam_inventory(login, steamid, appid, contextid):
    profile_url = "https://steamcommunity.com/profiles/" + str(steamid)
    headers = {
        "User-Agent":"Mozilla/5.0",
        "Accept":"application/json",
        "Referer":profile_url + "/inventory/"
    }
    cookies = load_steam_web_cookies(login)
    if cookies:
        headers["Cookie"] = steam_cookie_header(cookies)

    # Steam's own inventory page still uses this owner-specific endpoint. Unlike
    # the compact endpoint it returns owner_descriptions with temporary locks.
    legacy_url = profile_url + "/inventory/json/" + str(appid) + "/" + str(contextid) + "/"
    try:
        payload = steam_inventory_json(legacy_url + "?l=english",headers)
        if not isinstance(payload,dict) or not payload.get("success") or "rgInventory" not in payload:
            raise RuntimeError("Steam не вернул owner-инвентарь")
        descriptions = payload.get("rgDescriptions") or {}
        if not isinstance(descriptions,dict):
            descriptions = {}
        else:
            descriptions = dict(descriptions)
        def legacy_values(value):
            if isinstance(value,dict):
                return list(value.values())
            return list(value) if isinstance(value,list) else []
        assets = legacy_values(payload.get("rgInventory")) + legacy_values(payload.get("rgCurrency"))
        pages = 0
        while payload.get("more") and pages < 20:
            start = str(payload.get("more_start") or "")
            if not start:
                break
            page_url = legacy_url + "?" + urllib.parse.urlencode({"l":"english","start":start})
            payload = steam_inventory_json(page_url,headers)
            if not isinstance(payload,dict) or not payload.get("success"):
                break
            page_descriptions = payload.get("rgDescriptions") or {}
            if isinstance(page_descriptions,dict):
                descriptions.update(page_descriptions)
            assets.extend(legacy_values(payload.get("rgInventory")) + legacy_values(payload.get("rgCurrency")))
            pages += 1
    except Exception as exc:
        if "ограничил запросы" in str(exc):
            raise
        log_event("Owner-инвентарь недоступен, используется compact API: " + str(exc),"WARN",login)
        compact_url = "https://steamcommunity.com/inventory/" + str(steamid) + "/" + str(appid) + "/" + str(contextid) + "?l=english&count=2000"
        payload = steam_inventory_json(compact_url,headers)
        if not isinstance(payload,dict) or not payload.get("success"):
            raise RuntimeError("Steam не вернул инвентарь. Проверьте приватность профиля")
        descriptions = {}
        for desc in payload.get("descriptions") or []:
            key = str(desc.get("classid")) + "_" + str(desc.get("instanceid") or "0")
            descriptions[key] = desc
        assets = payload.get("assets") or []

    items = []
    for asset in assets:
        key = str(asset.get("classid")) + "_" + str(asset.get("instanceid") or "0")
        desc = descriptions.get(key, {})
        icon = str(desc.get("icon_url_large") or desc.get("icon_url") or "")
        marketable = inventory_bool(asset.get("marketable") if "marketable" in asset else desc.get("marketable"))
        tradable = inventory_bool(asset.get("tradable") if "tradable" in asset else desc.get("tradable"))
        trade_lock_until = inventory_trade_lock_until(desc,asset) if not tradable else 0
        trade_lock_notice = inventory_trade_lock_notice(desc,asset) if not tradable else ""
        name = str(desc.get("market_hash_name") or desc.get("name") or "Предмет")
        items.append({"assetid":str(asset.get("assetid") or asset.get("id") or ""),"name":name,"type":str(desc.get("type") or ""),"icon":("https://community.fastly.steamstatic.com/economy/image/"+icon if icon else ""),"amount":int(asset.get("amount") or 1),"marketable":marketable,"tradable":tradable,"trade_lock_until":trade_lock_until,"trade_lock_notice":trade_lock_notice,"market_hash_name":str(desc.get("market_hash_name") or "")})
    return {"items":items,"updated":int(time.time()),"count":len(items),"lock_data_version":5}

def market_cache_key(appid, currency, name):
    return str(appid)+":"+str(currency)+":"+name

def price_worker(worker_key, login, appid, currency, names):
    try:
        for index, name in enumerate(names):
            with INVENTORY_LOCK:
                PRICE_STATE[worker_key].update({"current":name,"done":index})
            key = market_cache_key(appid, currency, name)
            url = "https://steamcommunity.com/market/priceoverview/?" + urllib.parse.urlencode({"appid":appid,"currency":currency,"market_hash_name":name})
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0","Accept":"application/json"})
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = json.loads(response.read().decode("utf-8", errors="replace"))
                if data.get("success"):
                    raw = str(data.get("lowest_price") or data.get("median_price") or "")
                    value = market_price_number(raw)
                    with INVENTORY_LOCK:
                        PRICE_CACHE[key] = {"price":raw,"value":value,"updated":int(time.time())}
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    with INVENTORY_LOCK:
                        PRICE_STATE[worker_key]["message"] = "Steam ограничил цены; показаны сохранённые значения"
                    break
            except Exception:
                pass
            with INVENTORY_LOCK:
                PRICE_STATE[worker_key]["done"] = index + 1
            if index + 1 < len(names):
                time.sleep(4)
        _write_json_object(MARKET_PRICE_CACHE_FILE, PRICE_CACHE)
    finally:
        with INVENTORY_LOCK:
            PRICE_STATE[worker_key]["running"] = False
            PRICE_STATE[worker_key]["current"] = ""
            PRICE_WORKERS.pop(worker_key, None)

def attach_inventory_prices(result, login, appid, currency, start_prices=True):
    now = int(time.time())
    names = sorted({x.get("market_hash_name") for x in result.get("items",[]) if x.get("marketable") and x.get("market_hash_name")})
    missing = []
    total = 0.0
    known = 0
    for item in result.get("items",[]):
        key = market_cache_key(appid,currency,item.get("market_hash_name", ""))
        cached = PRICE_CACHE.get(key) or {}
        fresh = now-int(cached.get("updated") or 0) < 12*3600
        item["price"] = cached.get("price") or ""
        item["price_updated"] = cached.get("updated") or 0
        item["price_value"] = cached.get("value")
        if item.get("marketable"):
            if cached.get("value") is not None:
                total += float(cached["value"]) * max(1,int(item.get("amount") or 1));known += 1
            if not fresh and item.get("market_hash_name") not in missing:
                missing.append(item["market_hash_name"])
        else:
            item["price"] = "Не продаётся"
    worker_key = str(login)+":"+str(appid)+":"+str(currency)
    with INVENTORY_LOCK:
        state = PRICE_STATE.get(worker_key) or {"running":False,"done":0,"total":0,"current":"","message":""}
        if start_prices and missing and worker_key not in PRICE_WORKERS:
            state = {"running":True,"done":0,"total":len(missing),"current":"","message":""}
            PRICE_STATE[worker_key] = state
            thread = threading.Thread(target=price_worker,args=(worker_key,login,appid,currency,missing),daemon=True)
            PRICE_WORKERS[worker_key] = thread
            thread.start()
        result["price_state"] = dict(state)
    result["total_value"] = round(total,2)
    result["priced_items"] = known
    result["unique_prices"] = len(names)
    result["currency_id"] = currency
    return result

@app.route("/api/inventory/<path:login>", methods=["GET"])
def api_real_inventory(login):
    appid = int(request.args.get("appid", "730") or 730)
    contextid = str(request.args.get("context", "2") or "2")
    refresh = request.args.get("refresh") == "1"
    with_prices = request.args.get("prices") != "0"
    ma = find_mafile_data(login) or {}
    with AUTH_LOCK:
        account = dict(AUTH_STATE.get(login, {}))
    steamid = str(ma.get("steamid") or account.get("steamid") or "")
    if not re.fullmatch(r"\d{17}",steamid):
        return jsonify({"ok":False,"message":"SteamID64 не найден в maFile"}),400
    currency = steam_currency_id(account)
    key = inventory_cache_key(login,appid,contextid)
    with INVENTORY_LOCK:
        cached = dict(INVENTORY_CACHE.get(key) or {})
    if not refresh and cached.get("lock_data_version")==5 and cached and int(time.time())-int(cached.get("updated") or 0)<300:
        return jsonify({"ok":True,"cached":True,**attach_inventory_prices(cached,login,appid,currency,with_prices)})
    try:
        result = fetch_steam_inventory(login,steamid,appid,contextid)
        with INVENTORY_LOCK:
            INVENTORY_CACHE[key] = result
        _write_json_object(INVENTORY_CACHE_FILE,INVENTORY_CACHE)
        remember_trade_locks([(login,appid,contextid,result.get("items",[]))])
        return jsonify({"ok":True,"cached":False,**attach_inventory_prices(result,login,appid,currency,with_prices)})
    except Exception as exc:
        if cached:
            return jsonify({"ok":True,"cached":True,"warning":str(exc),**attach_inventory_prices(cached,login,appid,currency,False)})
        return jsonify({"ok":False,"message":str(exc)}),502


INVENTORY_GAME_NAMES = {730:"CS2",440:"TF2",570:"Dota 2",252490:"Rust",753:"Steam"}


def trade_lock_history_key(entry):
    return "|".join(str(entry.get(field) or "") for field in ("login","appid","contextid","assetid","trade_lock_until"))


def remember_trade_locks(observations):
    """Persist every observed temporary lock so its expiration survives refreshes."""
    now = int(time.time())
    changed = False
    with INVENTORY_LOCK:
        for login,appid,contextid,items in observations:
            for item in items or []:
                unlock = int(item.get("trade_lock_until") or 0)
                if item.get("tradable") or not unlock:
                    continue
                entry = {
                    "login":str(login),"game":INVENTORY_GAME_NAMES.get(int(appid),str(appid)),
                    "appid":int(appid),"contextid":str(contextid),
                    "assetid":str(item.get("assetid") or ""),
                    "name":str(item.get("name") or "Предмет"),
                    "icon":str(item.get("icon") or ""),
                    "amount":max(1,int(item.get("amount") or 1)),
                    "trade_lock_until":unlock,"first_seen":now
                }
                key = trade_lock_history_key(entry)
                previous = TRADE_LOCK_HISTORY.get(key)
                if not previous:
                    TRADE_LOCK_HISTORY[key] = entry
                    changed = True
                elif not previous.get("icon") and entry["icon"]:
                    previous["icon"] = entry["icon"]
                    changed = True
        snapshot = dict(TRADE_LOCK_HISTORY) if changed else None
    if snapshot is not None:
        _write_json_object(TRADE_LOCK_HISTORY_FILE,snapshot)


def inventory_lock_calendar():
    """Build active locks and expiration history without contacting Steam."""
    now = int(time.time())
    entries = []
    loaded = {}
    observations = []
    with INVENTORY_LOCK:
        snapshot = list(INVENTORY_CACHE.items())
    for key,cached in snapshot:
        try:
            login,appid_text,contextid = str(key).rsplit(":",2)
            appid = int(appid_text)
        except (ValueError,TypeError):
            continue
        scope = str(appid)+":"+str(contextid)
        loaded.setdefault(login,[])
        if scope not in loaded[login]:
            loaded[login].append(scope)
        observations.append((login,appid,contextid,cached.get("items",[])))
        for item in cached.get("items",[]):
            unlock = int(item.get("trade_lock_until") or 0)
            if item.get("tradable") or unlock <= now:
                continue
            entries.append({
                "login":login,"game":INVENTORY_GAME_NAMES.get(appid,str(appid)),
                "appid":appid,"contextid":str(contextid),
                "assetid":str(item.get("assetid") or ""),
                "name":str(item.get("name") or "Предмет"),
                "icon":str(item.get("icon") or ""),
                "amount":max(1,int(item.get("amount") or 1)),
                "trade_lock_until":unlock
            })
    remember_trade_locks(observations)
    with INVENTORY_LOCK:
        history_snapshot = list(TRADE_LOCK_HISTORY.values())
    history = [dict(item) for item in history_snapshot if 0 < int(item.get("trade_lock_until") or 0) <= now]
    entries.sort(key=lambda item:(item["trade_lock_until"],item["login"].casefold(),item["name"].casefold()))
    history.sort(key=lambda item:(-item["trade_lock_until"],item["login"].casefold(),item["name"].casefold()))
    return {"ok":True,"entries":entries,"history":history,"loaded":loaded,"generated":now}


@app.route("/api/inventory/locks",methods=["GET"])
def api_inventory_locks():
    return jsonify(inventory_lock_calendar())


def steam_market_cookies(login):
    cookies = load_steam_web_cookies(login)
    if not cookies:
        raise RuntimeError("Нет сохранённой Steam web-сессии. Выполните авторизацию аккаунта")
    session_id = ""
    for cookie in cookies:
        pair = str(cookie).split(";",1)[0].strip()
        if pair.lower().startswith("sessionid="):
            session_id = pair.split("=",1)[1].strip()
            break
    if not session_id:
        ma = find_mafile_data(login) or {}
        session_id = str(ma.get("session_id") or "").strip()
        if session_id:
            cookies.append("sessionid="+session_id)
    if not session_id:
        raise RuntimeError("В Steam web-сессии отсутствует sessionid. Выполните повторный вход")
    return cookies, session_id

def steam_market_classic_session(login, referer):
    """Open the same classic listing page as the browser before a buy order."""
    cookies, saved_session = steam_market_cookies(login)
    classic_cookies = []
    for cookie in cookies:
        pair = str(cookie).split(";", 1)[0].strip()
        name = pair.split("=", 1)[0].lower()
        # Keep the existing sessionid for the GET. Removing it makes Steam
        # redirect the listing request instead of returning the classic page.
        if name != "bmarketoptout":
            classic_cookies.append(str(cookie))
    # This is the exact opt-out cookie written by Steam's current market.js.
    classic_cookies.append("bMarketOptOut=1")
    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":"en-US,en;q=0.9",
        "Accept-Encoding":"gzip,identity"
    }
    def update_response_cookies(response):
        try:
            set_cookies = response.headers.get_all("Set-Cookie") or []
        except AttributeError:
            set_cookies = []
        for set_cookie in set_cookies:
            pair = str(set_cookie).split(";",1)[0].strip()
            if "=" not in pair:
                continue
            name = pair.split("=",1)[0].strip()
            if not name:
                continue
            classic_cookies[:] = [
                cookie for cookie in classic_cookies
                if str(cookie).split(";",1)[0].split("=",1)[0].strip().lower() != name.lower()
            ]
            classic_cookies.append(pair)
    class MarketNoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(MarketNoRedirect)
    current_url = referer
    html = ""
    final_url = referer
    # urllib repeats the original Cookie header across redirects. Steam rotates
    # sessionid with Set-Cookie, so follow Market redirects and update cookies
    # explicitly, just as a browser does.
    for redirect_count in range(5):
        page_headers = dict(headers)
        page_headers["Cookie"] = steam_cookie_header(classic_cookies)
        req = urllib.request.Request(current_url, headers=page_headers)
        try:
            with opener.open(req, timeout=25) as response:
                update_response_cookies(response)
                raw = response.read()
                if "gzip" in str(response.headers.get("Content-Encoding") or "").lower():
                    raw = gzip.decompress(raw)
                html = raw.decode("utf-8", errors="replace")
                final_url = current_url
                break
        except urllib.error.HTTPError as exc:
            update_response_cookies(exc)
            location = str(exc.headers.get("Location") or "").strip()
            if exc.code in (301,302,303,307,308) and location:
                next_url = urllib.parse.urljoin(current_url, location)
                parsed = urllib.parse.urlparse(next_url)
                if parsed.scheme != "https" or (parsed.hostname or "").lower() != "steamcommunity.com":
                    raise RuntimeError("Steam перенаправил Market на неподдерживаемый адрес")
                current_url = next_url
                final_url = next_url
                continue
            if exc.code == 429:
                raise RuntimeError("Steam ограничил открытие страницы Market. Подождите несколько минут перед повторной попыткой")
            raise RuntimeError("Не удалось открыть классическую страницу Market: HTTP "+str(exc.code))
    else:
        raise RuntimeError("Steam выполнил слишком много перенаправлений Market. Выполните повторный вход")
    if "/login" in final_url or not re.search(r"\bg_sessionID\s*=", html):
        raise RuntimeError("Steam не открыл авторизованную страницу Market. Выполните повторный вход")
    match = re.search(r"\bg_sessionID\s*=\s*[\"']([^\"']+)", html)
    if not match:
        raise RuntimeError("Steam не вернул свежий sessionid для Market. Выполните повторный вход")
    session_id = match.group(1).strip()
    if not session_id:
        raise RuntimeError("Steam вернул пустой sessionid для Market")
    wallet = {}
    wallet_match = re.search(r"\bg_rgWalletInfo\s*=\s*", html)
    if wallet_match:
        try:
            start = wallet_match.end()
            while start < len(html) and html[start].isspace():
                start += 1
            parsed, end = json.JSONDecoder().raw_decode(html[start:])
            if isinstance(parsed, dict):
                wallet = parsed
        except (ValueError, json.JSONDecodeError):
            wallet = {}
    # Replace the GET session only after the page supplied a fresh one. The
    # session cookie and POST form field must belong to the same page.
    classic_cookies = [
        cookie for cookie in classic_cookies
        if str(cookie).split(";",1)[0].split("=",1)[0].strip().lower() != "sessionid"
    ]
    classic_cookies.append("sessionid="+session_id)
    return steam_cookie_header(classic_cookies), session_id, wallet, html


def market_html_text(value):
    text = re.sub(r"<[^>]+>"," ",str(value or ""))
    return re.sub(r"\s+"," ",html_unescape(text)).strip()


def parse_market_tf2_buy_orders(html):
    supported = {"Mann Co. Supply Crate Key","Tour of Duty Ticket"}
    row_pattern = re.compile(r"<div\b[^>]*\bid=[\"'](?:mybuyorder|mbuyorder)_(\d+)[\"'][^>]*>",re.I)
    matches = list(row_pattern.finditer(html))
    orders = []
    for index, match in enumerate(matches):
        order_id = match.group(1)
        end = matches[index+1].start() if index+1 < len(matches) else html.find("</table>",match.end())
        if end < 0:
            end = len(html)
        row = html[match.end():end]
        name = ""
        name_match = re.search(r"<span\b[^>]*\bid=[\"'](?:mybuyorder|mbuyorder)_"+re.escape(order_id)+r"_name[\"'][^>]*>(.*?)</span>",row,re.I|re.S)
        if name_match:
            name = market_html_text(name_match.group(1))
        appid = 0
        link_match = re.search(r"href=[\"'](?:https?://steamcommunity\.com)?/market/listings/(\d+)/([^\"']+)",row,re.I)
        if link_match:
            appid = int(link_match.group(1))
            if not name:
                name = urllib.parse.unquote(link_match.group(2))
        if appid != 440 or name not in supported:
            continue
        # Current Steam wraps "quantity @" in another span. A simple outer-span
        # regex stops at that inner </span> and loses the actual price.
        nested_price = re.search(
            r"<span\b[^>]*class=[\"'][^\"']*market_listing_price[^\"']*[\"'][^>]*>\s*"
            r"<span\b[^>]*class=[\"'][^\"']*market_listing_inline_buyorder_qty[^\"']*[\"'][^>]*>(.*?)</span>"
            r"\s*(.*?)</span>",
            row,re.I|re.S
        )
        if nested_price:
            order_price = market_html_text(nested_price.group(1)+" "+nested_price.group(2))
        else:
            prices = re.findall(r"<span\b[^>]*class=[\"'][^\"']*market_listing_price[^\"']*[\"'][^>]*>(.*?)</span>",row,re.I|re.S)
            order_price = market_html_text(prices[0]) if prices else ""
        # Steam puts the user's buy order in one cell: "quantity @ unit price".
        # Parsing the whole cell as a price turns "1 @ 945,00₸" into 1.00.
        price_parts = re.split(r"\s*@\s*",order_price,maxsplit=1)
        unit_price = market_price_number(price_parts[-1]) if order_price else None
        quantity = 0
        if len(price_parts) == 2:
            quantity_digits = re.sub(r"\D","",price_parts[0])
            if quantity_digits:
                quantity = int(quantity_digits)
        if not quantity:
            quantity_match = re.search(r"<div\b[^>]*class=[\"'][^\"']*market_listing_num_buy_orders[^\"']*[\"'][^>]*>(.*?)</div>",row,re.I|re.S)
            if quantity_match:
                number_match = re.search(r"\d+",market_html_text(quantity_match.group(1)))
                if number_match:
                    quantity = int(number_match.group(0))
        unit_cents = int(round(unit_price*100)) if unit_price is not None else None
        orders.append({
            "buy_orderid":order_id,"appid":440,"name":name,
            "quantity":quantity,"unit_cents":unit_cents,
            "total_cents":unit_cents*quantity if unit_cents is not None and quantity else None
        })
    return orders


def steam_market_tf2_buy_orders(login):
    cookie_header, session_id, _, html = steam_market_classic_session(login,"https://steamcommunity.com/market/")
    return parse_market_tf2_buy_orders(html), (cookie_header,session_id)


def update_account_wallet_from_market(login,wallet):
    if not isinstance(wallet,dict):
        return ""
    try:
        balance_cents = int(str(wallet.get("wallet_balance")).strip())
        currency_id = int(wallet.get("wallet_currency") or 0)
    except (TypeError,ValueError):
        return ""
    currency_code = next((code for code,value in STEAM_CURRENCY_IDS.items() if value==currency_id),"")
    amount = format(balance_cents/100,".2f").rstrip("0").rstrip(".")
    balance = amount+(" "+currency_code if currency_code else "")
    with AUTH_LOCK:
        state = AUTH_STATE.setdefault(login,{})
        state["balance"] = balance
        if currency_code:
            state["currency"] = currency_code
        if wallet.get("wallet_country"):
            state["country"] = str(wallet.get("wallet_country"))
    save_account_cache()
    return balance


def market_html_element_content_end(source,start,tag):
    """Return the matching close-tag start, respecting nested div/span elements."""
    token_pattern = re.compile(r"</?"+re.escape(tag)+r"\b[^>]*>",re.I)
    depth = 0
    for token in token_pattern.finditer(source,start):
        value = token.group(0)
        if value.startswith("</"):
            depth -= 1
            if depth == 0:
                return token.start()
        elif not value.rstrip().endswith("/>"):
            depth += 1
    return len(source)


def market_sell_listing_price_cells(row):
    """Extract every amount separately, including two prices inside one Steam cell."""
    marker_pattern = re.compile(
        r"<(div|span)\b[^>]*class=[\"'][^\"']*market_listing_price[^\"']*[\"'][^>]*>",
        re.I
    )
    amount_pattern = re.compile(
        r"(?<![\d.,])(?:"
        r"\d{1,3}(?:[ \u00a0]\d{3})+(?:[.,]\d{1,2})?"
        r"|\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?"
        r"|\d{1,3}(?:\.\d{3})+(?:,\d{1,2})?"
        r"|\d+(?:[.,]\d{1,2})?"
        r")(?![\d.,])"
    )
    cells = []
    covered_until = -1
    for marker in marker_pattern.finditer(row):
        if marker.start() < covered_until:
            continue
        tag = marker.group(1)
        content_end = market_html_element_content_end(row,marker.start(),tag)
        text = market_html_text(row[marker.end():content_end])
        previous_end = 0
        for amount_match in amount_pattern.finditer(text):
            value = market_price_number(amount_match.group(0))
            if value is not None:
                # The label immediately before each amount identifies its role.
                # This prevents "Buyer pays 144 / You receive 125" becoming 144125.
                label = text[previous_end:amount_match.start()]
                cells.append((label,int(round(value*100))))
            previous_end = amount_match.end()
        # Nested price spans belong to this cell and must not be parsed again.
        close_match = re.search(r"</"+re.escape(tag)+r"\s*>",row[content_end:],re.I)
        covered_until = content_end+(close_match.end() if close_match else 0)
    return cells


def parse_market_sell_listings(page_html):
    source = str(page_html or "")
    row_pattern = re.compile(r"<div\b[^>]*\bid=[\"']mylisting_(\d+)[\"'][^>]*>",re.I)
    matches = list(row_pattern.finditer(source))
    listings = []
    for index,match in enumerate(matches):
        listing_id = match.group(1)
        end = matches[index+1].start() if index+1<len(matches) else len(source)
        row = source[match.end():end]
        appid = 0
        name = ""
        link_match = re.search(r"href=[\"'](?:https?://steamcommunity\.com)?/market/listings/(\d+)/([^\"']+)",row,re.I)
        if link_match:
            appid = int(link_match.group(1))
            name = urllib.parse.unquote(link_match.group(2))
        name_match = re.search(r"class=[\"'][^\"']*market_listing_item_name[^\"']*[\"'][^>]*>(.*?)</",row,re.I|re.S)
        if name_match:
            name = market_html_text(name_match.group(1)) or name
        if appid<=0 or not name:
            continue
        icon_match = re.search(r"<img\b[^>]*\bsrc=[\"']([^\"']+)",row,re.I)
        game_match = re.search(r"class=[\"'][^\"']*market_listing_game_name[^\"']*[\"'][^>]*>(.*?)</",row,re.I|re.S)
        prices = market_sell_listing_price_cells(row)
        seller_cents = prices[0][1] if len(prices)>1 else None
        buyer_cents = prices[-1][1] if prices else None
        for label,cents in prices:
            normalized = label.casefold()
            if "buyer pays" in normalized or "покупатель платит" in normalized:
                buyer_cents = cents
            elif "you receive" in normalized or "вы получите" in normalized or "вы получаете" in normalized:
                seller_cents = cents
        # Buyer pays seller net + Steam/publisher fees. Localized labels and
        # their position vary, so enforce this invariant if Steam swaps blocks.
        if seller_cents is not None and buyer_cents is not None and buyer_cents<seller_cents:
            seller_cents,buyer_cents = buyer_cents,seller_cents
        listings.append({
            "listing_id":listing_id,"appid":appid,"name":name,
            "game":market_html_text(game_match.group(1)) if game_match else "",
            "icon":html_unescape(icon_match.group(1)) if icon_match else "",
            "seller_cents":seller_cents,"buyer_cents":buyer_cents
        })
    return listings


def apply_market_listing_price_data(listings,payload):
    """Prefer Steam's exact integer minor units over localized HTML numbers."""
    raw = payload.get("listings") if isinstance(payload,dict) else None
    if isinstance(raw,dict):
        records = list(raw.values())
    elif isinstance(raw,list):
        records = raw
    else:
        records = []
    by_id = {}
    for record in records:
        if not isinstance(record,dict):
            continue
        listing_id = str(record.get("listingid") or record.get("listing_id") or "").strip()
        if listing_id:
            by_id[listing_id] = record
    def minor_units(value):
        if isinstance(value,bool) or value is None:
            return None
        try:
            text = str(value).strip()
            return int(text) if re.fullmatch(r"\d+",text) else None
        except (TypeError,ValueError):
            return None
    for listing in listings:
        record = by_id.get(str(listing.get("listing_id")))
        if not record:
            continue
        seller = minor_units(record.get("price"))
        fee = minor_units(record.get("fee"))
        if fee is None:
            steam_fee = minor_units(record.get("steam_fee"))
            publisher_fee = minor_units(record.get("publisher_fee"))
            if steam_fee is not None or publisher_fee is not None:
                fee = (steam_fee or 0)+(publisher_fee or 0)
        if seller is not None:
            listing["seller_cents"] = seller
            if fee is not None:
                listing["buyer_cents"] = seller+fee
    return listings


def steam_market_sell_listings(login):
    cookie_header, _, wallet, home_html = steam_market_classic_session(login,"https://steamcommunity.com/market/")
    balance = update_account_wallet_from_market(login,wallet)
    warning = ""
    listings = []
    total_count = 0
    try:
        url = "https://steamcommunity.com/market/mylistings?start=0&count=100"
        headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Accept":"application/json, text/javascript, */*; q=0.01",
            "Accept-Language":"en-US,en;q=0.9",
            "Accept-Encoding":"identity",
            "Referer":"https://steamcommunity.com/market/",
            "X-Requested-With":"XMLHttpRequest",
            "Cookie":cookie_header
        }
        with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=25) as response:
            payload = json.loads(response.read().decode("utf-8",errors="replace"))
        if not isinstance(payload,dict) or payload.get("success") not in (True,1):
            raise RuntimeError("Steam не вернул активные лоты")
        listings = apply_market_listing_price_data(
            parse_market_sell_listings(payload.get("results_html") or ""),payload
        )
        total_count = int(payload.get("total_count") or len(listings))
    except Exception as exc:
        warning = str(exc)
        listings = parse_market_sell_listings(home_html)
        total_count = len(listings)
    with AUTH_LOCK:
        account = dict(AUTH_STATE.get(login,{}))
    currency = steam_currency_id(account)
    try:
        currency = int(wallet.get("wallet_currency") or currency)
    except (TypeError,ValueError):
        pass
    return {
        "ok":True,"listings":listings,"count":total_count,"currency":currency,
        "currency_code":steam_currency_code(account),"balance":balance or str(account.get("balance") or ""),
        "country":str(account.get("country") or ""),"updated":int(time.time()),"warning":warning
    }


def steam_market_post(login, path, fields, referer="https://steamcommunity.com/market/", market_session=None):
    if market_session:
        cookie_header, session_id = market_session
    else:
        cookies, session_id = steam_market_cookies(login)
        cookie_header = steam_cookie_header(cookies)
    if path == "createbuyorder":
        cookie_header, session_id, wallet, _ = steam_market_classic_session(login, referer)
        wallet_currency = wallet.get("wallet_currency")
        if wallet_currency not in (None, "", 0, "0"):
            try:
                currency_matches = int(wallet_currency) == int(fields.get("currency"))
            except (TypeError, ValueError):
                currency_matches = False
            if not currency_matches:
                raise RuntimeError("Валюта кошелька на свежей странице Steam не совпадает с валютой ордера. Обновите данные аккаунта перед покупкой")
        # Recheck the fresh wallet immediately before every real create request.
        # price_total and wallet_balance are both integer minor currency units.
        try:
            wallet_balance = int(str(wallet.get("wallet_balance")).strip())
            order_total = int(fields.get("price_total"))
        except (TypeError,ValueError):
            raise RuntimeError("Не удалось проверить баланс кошелька Steam. Ордер не отправлен")
        if order_total > wallet_balance:
            currency_code = next((code for code,value in STEAM_CURRENCY_IDS.items() if value==int(fields.get("currency"))),"")
            raise RuntimeError(
                "Недостаточно средств: нужно "+format(order_total/100,".2f")+" "+currency_code
                +", доступно "+format(wallet_balance/100,".2f")+" "+currency_code
                +". Ордер не отправлен"
            )
    # Keep the official browser form order, with sessionid first.
    values = {"sessionid":session_id}
    values.update(fields)
    data = urllib.parse.urlencode(values).encode("utf-8")
    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept":"*/*",
        "Accept-Language":"en-US,en;q=0.9",
        "Accept-Encoding":"gzip,identity",
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
        "Cookie":cookie_header,"Referer":referer,"Origin":"https://steamcommunity.com","X-Requested-With":"XMLHttpRequest"
    }
    request_url = "https://steamcommunity.com/market/"+path
    # The official RemoveMarketListing script uses no trailing slash.
    if not path.startswith("removelisting/"):
        request_url += "/"
    req = urllib.request.Request(request_url,data=data,method="POST",headers=headers)
    def response_text(response):
        raw = response.read()
        if "gzip" in str(response.headers.get("Content-Encoding") or "").lower():
            raw = gzip.decompress(raw)
        return raw.decode("utf-8",errors="replace")
    try:
        with urllib.request.urlopen(req,timeout=25) as response:
            return json.loads(response_text(response))
    except urllib.error.HTTPError as exc:
        payload = None
        try:
            body = response_text(exc).strip()
        except Exception:
            body = ""
        detail = ""
        if body:
            try:
                payload = json.loads(body)
                if isinstance(payload,dict):
                    detail = str(payload.get("message") or payload.get("error") or "").strip()
            except Exception:
                detail = re.sub(r"<[^>]+>"," ",body)
                detail = re.sub(r"\s+"," ",detail).strip()[:240]
        # Steam's official createbuyorder script handles need_confirmation in
        # the JSON body of a failed HTTP response, not only in HTTP 200.
        if path == "createbuyorder" and isinstance(payload,dict) and (
            payload.get("need_confirmation") or payload.get("needs_confirmation")
            or payload.get("needs_mobile_confirmation")
        ):
            return payload
        if exc.code == 429:
            retry_after = str(exc.headers.get("Retry-After") or "").strip()
            wait_hint = " Повторите через "+retry_after+" сек." if retry_after.isdigit() else " Подождите несколько минут: лимит учитывает предыдущие Market-запросы аккаунта и IP, а не только это нажатие."
            raise RuntimeError("Steam вернул HTTP 429 именно на Market-запрос «"+path+"»."+wait_hint)
        if exc.code in (401,403):
            raise RuntimeError("Steam отклонил Market-сессию. Выполните повторный вход"+(": "+detail if detail else ""))
        if exc.code == 406:
            raise RuntimeError("Steam отклонил Market-запрос (HTTP 406)"+(": "+detail if detail else ""))
        raise RuntimeError("Steam Market HTTP "+str(exc.code)+(": "+detail if detail else ""))
    except json.JSONDecodeError:
        raise RuntimeError("Steam Market вернул неожиданный ответ")


def steam_market_remove_sell_listing(login,listing_id):
    if not re.fullmatch(r"\d+",str(listing_id or "")):
        raise ValueError("Некорректный ID лота")
    result = None
    def removal_confirmed_after_error():
        try:
            data = steam_market_sell_listings(login)
        except Exception:
            return False
        if data.get("warning"):
            return False
        # Steam can remove the listing and then return 502. A fresh listing
        # response without this exact ID is stronger evidence than that error.
        return all(
            str(item.get("listing_id"))!=str(listing_id)
            for item in (data.get("listings") or [])
        )
    for attempt in range(2):
        cookie_header, session_id, _, _ = steam_market_classic_session(
            login,"https://steamcommunity.com/market/"
        )
        # Official URL: /market/removelisting/{listingid} without a trailing /.
        # listingid belongs in the URL; putting it only in the form causes 400.
        try:
            result = steam_market_post(
                login,"removelisting/"+str(listing_id),{},
                market_session=(cookie_header,session_id)
            )
        except RuntimeError as exc:
            temporary = re.search(r"HTTP 50[234]\b",str(exc))
            if attempt==0 and temporary:
                time.sleep(1)
                continue
            if temporary and removal_confirmed_after_error():
                log_event("Market sell listing removal confirmed after Steam error: "+str(listing_id),"INFO",login)
                return {"success":1,"verified_absent":True}
            raise
        if isinstance(result,dict) and result.get("success") in (True,1):
            log_event("Market sell listing removed: "+str(listing_id),"INFO",login)
            return result
        detail = ""
        if isinstance(result,dict):
            detail = str(result.get("message") or result.get("error") or "").strip()
        if detail or attempt==1:
            raise RuntimeError(detail or "Steam не снял лот с продажи")
        # An empty unsuccessful response can be transient; retry once with a
        # fresh Market session before reporting failure to the user.
        time.sleep(1)
    raise RuntimeError("Steam не снял лот с продажи")


def steam_market_remove_all_sell_listings(login):
    removed = 0
    errors = {}
    completed = False
    # Re-read the first page after each full batch so accounts with more than
    # 100 listings are processed without skipping rows as pagination shifts.
    for _batch in range(20):
        data = steam_market_sell_listings(login)
        if data.get("warning"):
            raise RuntimeError("Не удалось получить активные лоты: "+str(data.get("warning")))
        listing_ids = [
            str(item.get("listing_id")) for item in (data.get("listings") or [])
            if re.fullmatch(r"\d+",str(item.get("listing_id") or ""))
        ]
        if not listing_ids:
            completed = True
            break
        cookie_header, session_id, _, _ = steam_market_classic_session(
            login,"https://steamcommunity.com/market/"
        )
        stop_after_batch = False
        for listing_id in listing_ids:
            try:
                result = steam_market_post(
                    login,"removelisting/"+listing_id,{},
                    market_session=(cookie_header,session_id)
                )
                if not isinstance(result,dict) or result.get("success") not in (True,1):
                    detail = ""
                    if isinstance(result,dict):
                        detail = str(result.get("message") or result.get("error") or "").strip()
                    raise RuntimeError(detail or "Steam не снял лот с продажи")
                removed += 1
            except Exception as exc:
                errors[listing_id] = str(exc)
                if "HTTP 429" in str(exc):
                    stop_after_batch = True
                    break
            time.sleep(0.5)
        if errors or stop_after_batch:
            break
    failed = len(errors)
    if failed:
        message = "Удалено лотов: "+str(removed)+". Ошибок: "+str(failed)+". Обновите список и повторите"
    elif not completed:
        message = "Удалено лотов: "+str(removed)+". Часть лотов осталась — повторите удаление"
    else:
        message = "Все активные лоты удалены: "+str(removed) if removed else "Активных лотов нет"
    log_event(
        "Market remove-all finished: removed="+str(removed)+", failed="+str(failed),
        "INFO" if not failed else "WARNING",login
    )
    return {
        "removed":removed,"failed":failed,"complete":completed,
        "errors":dict(list(errors.items())[:10]),"message":message
    }


def market_cents(value, field="цена"): 
    number = market_price_number(value)
    if number is None or number <= 0 or number > 1000000:
        raise ValueError("Укажите корректную "+field)
    return int(round(number*100))


MARKET_STEAM_FEE_RATE = 0.05
MARKET_PUBLISHER_FEE_RATES = {730:0.10, 440:0.10, 570:0.10, 252490:0.10, 753:0.10}
MARKET_FEE_CACHE = {}
MARKET_FEE_CACHE_LOCK = threading.Lock()
MARKET_FEE_CACHE_TTL = 3600


def market_fee_config(appid, fee=None):
    """Validated sell-dialog fee rules, all amounts in minor currency units."""
    fee = fee or {}
    try:
        minimum = max(1,int(fee.get("minimum") or 1))
        base = max(0,int(fee.get("base") or 0))
        publisher_minimum = max(1,int(fee.get("publisher_minimum") or 1))
        steam_rate = float(fee.get("steam_rate",MARKET_STEAM_FEE_RATE))
        publisher_rate = float(fee.get(
            "publisher_rate",MARKET_PUBLISHER_FEE_RATES.get(int(appid),0.10)
        ))
    except (TypeError,ValueError):
        raise ValueError("Steam вернул некорректные параметры комиссий")
    if not (0 <= steam_rate <= 1 and 0 <= publisher_rate <= 1):
        raise ValueError("Steam вернул некорректный процент комиссии")
    return {
        "minimum":minimum,"base":base,"publisher_minimum":publisher_minimum,
        "steam_rate":steam_rate,"publisher_rate":publisher_rate
    }


def market_fee_breakdown(seller_cents, appid, fee=None):
    """Exact sell-dialog fees: wallet minimum plus base, then the item publisher fee."""
    fee = market_fee_config(appid,fee)
    seller_cents = int(seller_cents)
    steam_fee = int(max(seller_cents*fee["steam_rate"],fee["minimum"])+fee["base"])
    publisher_fee = int(max(seller_cents*fee["publisher_rate"],fee["publisher_minimum"])) if fee["publisher_rate"]>0 else 0
    return {"steam":steam_fee,"publisher":publisher_fee}


def market_buyer_pays_cents(seller_cents, appid, fee=None):
    """Buyer total used by Steam's inventory sell dialog, without display rounding."""
    fees = market_fee_breakdown(seller_cents,appid,fee)
    return int(seller_cents)+fees["steam"]+fees["publisher"]


def market_seller_receives_cents(buyer_target_cents, appid, fee=None):
    """Seller amount only when Steam's official buyer total exactly equals the target."""
    fee = market_fee_config(appid,fee)
    target = int(buyer_target_cents)
    if target < market_buyer_pays_cents(1,appid,fee):
        raise ValueError("Цена покупателя слишком мала с учётом минимальной комиссии Steam")
    low,high,best = 1,target,0
    while low <= high:
        middle = (low+high)//2
        if market_buyer_pays_cents(middle,appid,fee) <= target:
            best = middle
            low = middle+1
        else:
            high = middle-1
    if best <= 0 or market_buyer_pays_cents(best,appid,fee) != target:
        raise ValueError("Steam не может выставить ровно эту цену с текущим шагом комиссий валюты. Измените цену")
    return best


def market_wallet_fee_settings(login, appid, name="", force=False):
    """Read the account's real wallet fee rules instead of assuming USD cents."""
    key = str(login)+":"+str(int(appid))
    now = int(time.time())
    if not force:
        with MARKET_FEE_CACHE_LOCK:
            cached = dict((MARKET_FEE_CACHE.get(key) or {}).get("config") or {})
            updated = int((MARKET_FEE_CACHE.get(key) or {}).get("updated") or 0)
        if cached and now-updated < MARKET_FEE_CACHE_TTL:
            return cached
    referer = "https://steamcommunity.com/market/"
    if name:
        referer = "https://steamcommunity.com/market/listings/"+str(int(appid))+"/"+urllib.parse.quote(str(name),safe="")
    _, _, wallet, page_html = steam_market_classic_session(login,referer)
    if not wallet:
        raise RuntimeError("Steam не вернул параметры комиссий кошелька. Обновите вход и повторите")
    publisher_rate = wallet.get("wallet_publisher_fee_percent_default",MARKET_PUBLISHER_FEE_RATES.get(int(appid),0.10))
    publisher_match = re.search(r"\bg_fPubFee_Rate\s*=\s*[\"']?([0-9.]+)",page_html)
    if publisher_match:
        publisher_rate = publisher_match.group(1)
    config = market_fee_config(appid,{
        "minimum":wallet.get("wallet_fee_minimum") or 1,
        "base":wallet.get("wallet_fee_base") or 0,
        "publisher_minimum":wallet.get("wallet_publisher_fee_minimum") or 1,
        "steam_rate":wallet.get("wallet_fee_percent",MARKET_STEAM_FEE_RATE),
        "publisher_rate":publisher_rate
    })
    with MARKET_FEE_CACHE_LOCK:
        MARKET_FEE_CACHE[key] = {"updated":now,"config":dict(config)}
    return config

def market_confirmation_price_cents(value):
    """Read Steam's actual buyer total from a Market confirmation summary."""
    text = market_html_text(value)
    match = re.search(r"\bSelling\s+for\s+([0-9][0-9\s]*(?:[.,]\d{1,2})?)",text,re.I)
    if not match:
        return None
    number = market_price_number(match.group(1))
    return int(round(number*100)) if number is not None else None


def find_market_sale_confirmation(login, sale_result, assetid, started):
    """Find only the confirmation created by this exact sell request."""
    confirmation = sale_result.get("confirmation") or {}
    direct_confirmation = str(sale_result.get("confirmation_id") or confirmation.get("confirmation_id") or "")
    listing_id = str(sale_result.get("listingid") or sale_result.get("listing_id") or "")
    for attempt in range(4):
        result, _ = fetch_account_confirmations(login,with_details=False)
        candidates = [x for x in result.get("confirmations",[]) if x.get("confirmation_type")==3] if result.get("ok") else []
        match = None
        if direct_confirmation:
            match = next((x for x in candidates if str(x.get("id"))==direct_confirmation),None)
        if not match and listing_id:
            match = next((x for x in candidates if str(x.get("creator_id") or "")==listing_id),None)
        if not match:
            recent = [x for x in candidates if int(x.get("created") or 0)>=int(started)-3]
            if len(recent)==1:
                # Market confirmation details often contain no assetids at all.
                match = recent[0]
            else:
                asset_matches = []
                for candidate in recent:
                    details = fetch_confirmation_details(login,candidate.get("id"))
                    if str(assetid) in {str(value) for value in details.get("assetids",[])}:
                        asset_matches.append(candidate)
                if len(asset_matches)==1:
                    match = asset_matches[0]
                elif recent:
                    match = max(recent,key=lambda x:int(x.get("created") or 0))
        if match:
            return match
        if attempt<3:
            time.sleep(1.2)
    return None


def review_market_sale_confirmation(login, sale_result, assetid, started, expected_buyer_cents, accept):
    """Reject an incorrect price; accept only Steam's exact expected buyer total."""
    match = find_market_sale_confirmation(login,sale_result,assetid,started)
    if not match:
        return {"status":"error","message":"Объявление создано, но его точное подтверждение не найдено"}
    details = fetch_confirmation_details(login,match.get("id"))
    actual = details.get("market_buyer_pays_cents")
    if actual is None:
        # Steam puts the Market buyer total in the list headline ("Selling for ...").
        # The summary usually contains only the item name, and details may be empty.
        actual = market_confirmation_price_cents(match.get("recipient"))
    if actual is None:
        for summary in match.get("items",[]):
            actual = market_confirmation_price_cents(summary)
            if actual is not None:
                break
    if actual is None:
        cancelled, _ = process_trade_confirmations(login,"cancel",confirmation_ids=[match["id"]])
        message = "Steam не показал точную цену подтверждения"
        if cancelled.get("ok"):
            message += "; непроверенное подтверждение отменено"
        return {"status":"error","message":message}
    actual = int(actual)
    if actual != int(expected_buyer_cents):
        cancelled, cancel_message = process_trade_confirmations(login,"cancel",confirmation_ids=[match["id"]])
        if not cancelled.get("ok"):
            return {"status":"error","actual":actual,"message":"Цена Steam не совпала, а неправильное подтверждение не удалось отменить: "+str(cancel_message or "")}
        return {"status":"rejected","actual":actual,"message":"Неточное подтверждение отменено"}
    if not accept:
        return {"status":"pending","actual":actual,"message":"Цена проверена. Подтвердите объявление через ✓"}
    confirmed, message = process_trade_confirmations(login,"accept",confirmation_ids=[match["id"]])
    if confirmed.get("ok"):
        return {"status":"accepted","actual":actual,"message":str(message or "")}
    return {"status":"error","actual":actual,"message":str(message or "Не удалось принять проверенное подтверждение")}


def market_sale_error_message(error):
    """Turn common Steam sellitem failures into clear Russian UI messages."""
    text = str(error or "").strip()
    lower = text.casefold()
    if ("already" in lower and ("list" in lower or "market" in lower)) or "existing listing" in lower or "currently listed" in lower:
        return "Этот предмет уже выставлен на Торговую площадку. Снимите текущее объявление или выберите другой предмет."
    if "not marketable" in lower or "cannot be marketed" in lower:
        return "Этот предмет нельзя продать на Торговой площадке."
    if "not in your inventory" in lower or "unavailable in your inventory" in lower or "no longer in your inventory" in lower or "asset not found" in lower:
        return "Предмет больше не находится в инвентаре. Обновите инвентарь и повторите."
    if "locked" in lower or "trade hold" in lower:
        return "Предмет заблокирован для продажи. Проверьте ограничения предмета в инвентаре."
    if "maximum" in lower and "listing" in lower:
        return "Достигнут лимит активных объявлений Steam. Снимите часть текущих лотов и повторите."
    if "not logged" in lower or "session" in lower or "unauthorized" in lower:
        return "Сессия Steam недействительна. Авторизуйте аккаунт заново и повторите продажу."
    if "invalid price" in lower or "price" in lower and "invalid" in lower:
        return "Steam отклонил указанную цену. Пересчитайте её и повторите."
    if "try again later" in lower or "rate limit" in lower or "too many requests" in lower:
        return "Steam временно ограничил создание объявлений. Подождите немного и повторите."
    if re.search(r"[А-Яа-яЁё]",text):
        return text
    return "Steam не создал объявление на Торговой площадке. Обновите инвентарь и повторите попытку."


@app.route("/api/market/sell/<path:login>",methods=["POST"])
def api_market_sell(login):
    data = request.get_json(silent=True) or {}
    try:
        appid = int(data.get("appid") or 0)
        contextid = str(data.get("contextid") or "2")
        assetid = str(data.get("assetid") or "").strip()
        if appid <= 0 or not assetid.isdigit():
            raise ValueError("Некорректный предмет")
        buyer_target = None
        fee_config = None
        if data.get("buyer_pays") is not None:
            buyer_target = market_cents(data.get("buyer_pays"),"цену покупателя")
            if data.get("expected_buyer_price_cents") is not None and int(data.get("expected_buyer_price_cents"))!=buyer_target:
                raise ValueError("Цена покупателя изменилась. Выполните расчёт заново")
            fee_config = market_wallet_fee_settings(login,appid)
            cents = market_seller_receives_cents(buyer_target,appid,fee_config)
        else:
            # Backward compatibility for callers that explicitly send seller-receives.
            cents = market_cents(data.get("price"),"цену продажи")
            if data.get("expected_price_cents") is not None and int(data.get("expected_price_cents"))!=cents:
                raise ValueError("Цена изменилась. Выполните расчёт заново")
        with INVENTORY_LOCK:
            cached = INVENTORY_CACHE.get(inventory_cache_key(login,appid,contextid)) or {}
        asset = next((x for x in cached.get("items",[]) if str(x.get("assetid"))==assetid),None)
        if not asset:
            return jsonify({"ok":False,"message":"Предмет не найден в загруженном инвентаре. Обновите инвентарь"}),400
        if not asset.get("marketable"):
            return jsonify({"ok":False,"message":"Этот предмет нельзя продать на Торговой площадке"}),400
        confirmed = False
        confirmation_message = ""
        verified_buyer = None
        attempted_prices = {cents}
        for attempt in range(5):
            started = int(time.time())
            result = steam_market_post(login,"sellitem",{"appid":appid,"contextid":contextid,"assetid":assetid,"amount":1,"price":cents})
            if not result.get("success"):
                raise RuntimeError(str(result.get("message") or "Steam не создал объявление"))
            needs_confirmation = bool(result.get("needs_confirmation") or result.get("needs_mobile_confirmation") or result.get("requires_confirmation"))
            if not needs_confirmation:
                break
            if buyer_target is None:
                if data.get("auto_confirm"):
                    match = find_market_sale_confirmation(login,result,assetid,started)
                    if match:
                        accepted, accept_message = process_trade_confirmations(login,"accept",confirmation_ids=[match["id"]])
                        confirmed = bool(accepted.get("ok"))
                        confirmation_message = str(accept_message or "")
                    else:
                        confirmation_message = "Объявление создано, но его точное подтверждение не найдено"
                break
            review = review_market_sale_confirmation(
                login,result,assetid,started,buyer_target,bool(data.get("auto_confirm"))
            )
            if review.get("actual") is not None:
                verified_buyer = int(review["actual"])
            if review.get("status") == "rejected":
                actual = int(review["actual"])
                corrected = cents+(buyer_target-actual)
                if corrected <= 0 or corrected in attempted_prices:
                    raise RuntimeError("Steam не позволяет выставить ровно эту цену. Неточные подтверждения отменены")
                cents = corrected
                attempted_prices.add(cents)
                continue
            if review.get("status") == "error":
                raise RuntimeError(str(review.get("message") or "Не удалось проверить цену подтверждения"))
            confirmed = review.get("status") == "accepted"
            confirmation_message = str(review.get("message") or "")
            break
        else:
            raise RuntimeError("Steam не дал точную цену после нескольких попыток. Неточные подтверждения отменены")
        if not data.get("preserve_cache"):
            with INVENTORY_LOCK:
                INVENTORY_CACHE.pop(inventory_cache_key(login,appid,contextid),None)
        message = "Предмет выставлен на Торговую площадку"
        if needs_confirmation:
            message = "Объявление создано и подтверждено" if confirmed else (confirmation_message or "Объявление создано. Подтвердите его через ✓")
        response = {"ok":True,"needs_confirmation":needs_confirmation,"confirmed":confirmed,"message":message}
        if buyer_target is not None:
            fees = market_fee_breakdown(cents,appid,fee_config)
            response.update({
                "seller_receives_cents":cents,
                "steam_fee_cents":fees["steam"],
                "publisher_fee_cents":fees["publisher"],
                "buyer_pays_cents":verified_buyer if verified_buyer is not None else market_buyer_pays_cents(cents,appid,fee_config),
                "price_verified":verified_buyer == buyer_target,
                "fee":fee_config
            })
        return jsonify(response)
    except Exception as exc:
        log_event("Ошибка продажи Market: "+str(exc),"WARN",login)
        return jsonify({"ok":False,"message":market_sale_error_message(exc)}),400

MARKET_LISTING_CACHE_FILE = BASE_DIR / "market_listing_cache.json"
MARKET_LISTING_CACHE = _read_json_object(MARKET_LISTING_CACHE_FILE)
MARKET_NAME_ID_CACHE_FILE = BASE_DIR / "market_name_ids.json"
MARKET_NAME_ID_CACHE = _read_json_object(MARKET_NAME_ID_CACHE_FILE)
MARKET_LISTING_TTL = 600

def market_listing_data(appid, name, currency=1, country="US", login=""):
    listing_url = "https://steamcommunity.com/market/listings/"+str(appid)+"/"+urllib.parse.quote(str(name),safe="")
    browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    headers = {
        "User-Agent":browser_ua,
        "Accept":"application/json, text/javascript, */*; q=0.01",
        "Accept-Language":"en-US,en;q=0.9",
        "Accept-Encoding":"identity",
        "Referer":listing_url,
        "X-Valve-Request-Type":"queryAction",
        "X-Requested-With":"XMLHttpRequest"
    }
    account_cookies = load_steam_web_cookies(login) if login else []
    if account_cookies:
        headers["Cookie"] = steam_cookie_header(account_cookies)
    # Current Market Beta resolves the order book directly by appid and exact
    # market_hash_name. No HTML page or item_nameid discovery is required.
    query = urllib.parse.urlencode({
        "q":"Load",
        "qp":json.dumps([appid,name],ensure_ascii=False,separators=(",",":")),
        "cc":country or "US",
        "l":"english",
        "currency":currency
    })
    req = urllib.request.Request("https://steamcommunity.com/market/orderbook?"+query,headers=headers)
    with urllib.request.urlopen(req,timeout=20) as response:
        outer = json.loads(response.read().decode("utf-8",errors="replace"))
    if not isinstance(outer,dict):
        raise RuntimeError("Steam вернул некорректный ответ ордеров")
    payload = outer if "success" in outer else outer.get("data")
    if not isinstance(payload,dict) or payload.get("success") is not True:
        raise RuntimeError("Steam не вернул ордера для "+name)
    data = payload.get("data") or {}
    if not isinstance(data,dict):
        raise RuntimeError("Steam вернул пустой стакан ордеров")
    returned_currency = data.get("eCurrency")
    if returned_currency not in (None,"") and int(returned_currency)!=int(currency):
        raise RuntimeError("Steam вернул другую валюту ордеров")
    def compact_levels(values):
        if values is None:
            return []
        if not isinstance(values,list) or len(values)%2:
            raise RuntimeError("Steam вернул повреждённый список ордеров")
        return [[values[index],values[index+1]] for index in range(0,len(values),2)]
    buy_orders = compact_levels(data.get("rgCompactBuyOrders"))[:20]
    sell_orders = compact_levels(data.get("rgCompactSellOrders"))[:20]
    return {
        "appid":appid,"name":name,"icon":"","item_nameid":"","currency":currency,
        "highest_buy_order":data.get("amtMaxBuyOrder"),
        "lowest_sell_order":data.get("amtMinSellOrder"),
        "buy_order_count":data.get("cBuyOrders"),
        "sell_order_count":data.get("cSellOrders"),
        "buy_orders":buy_orders,"sell_orders":sell_orders
    }

@app.route("/api/market/listing",methods=["GET"])
def api_market_listing():
    appid = int(request.args.get("appid") or 440)
    name = str(request.args.get("name") or "").strip()
    currency = int(request.args.get("currency") or 1)
    country = str(request.args.get("country") or "US")[:2].upper()
    login = str(request.args.get("login") or "").strip()
    cached_only = request.args.get("cached") == "1"
    force_refresh = request.args.get("force") == "1"
    include_fees = request.args.get("include_fees") == "1" and bool(login)
    if appid not in INVENTORY_GAME_NAMES or not name or len(name)>250:
        return jsonify({"ok":False,"message":"Неподдерживаемый предмет"}),400
    fee_config = None
    if include_fees:
        try:
            fee_config = market_wallet_fee_settings(login,appid,name)
        except Exception as exc:
            return jsonify({"ok":False,"message":"Не удалось получить комиссии Steam: "+str(exc)}),502
    def listing_response(payload,status=200):
        if fee_config is not None:
            payload = {**payload,"fee":fee_config}
        return jsonify(payload),status
    key = str(appid)+":"+str(currency)+":"+country+":"+name
    cached = MARKET_LISTING_CACHE.get(key) or {}
    age = int(time.time())-int(cached.get("updated") or 0)
    if cached and not force_refresh and (cached_only or age < MARKET_LISTING_TTL):
        return listing_response({"ok":True,"cached":True,"stale":age>=MARKET_LISTING_TTL,**cached})
    if cached_only:
        return listing_response({"ok":False,"message":"Ордера ещё не сохранены"},404)
    try:
        result = market_listing_data(appid,name,currency,country,login)
        result["updated"] = int(time.time())
        MARKET_LISTING_CACHE[key] = result
        _write_json_object(MARKET_LISTING_CACHE_FILE,MARKET_LISTING_CACHE)
        return listing_response({"ok":True,"cached":False,"stale":False,**result})
    except urllib.error.HTTPError as exc:
        if cached:
            return listing_response({"ok":True,"cached":True,"stale":True,"warning":"Steam ограничил запросы; показаны последние сохранённые ордера",**cached})
        message = "Steam ограничил запросы ордеров. Подождите несколько минут" if exc.code==429 else "Steam Market HTTP "+str(exc.code)
        return listing_response({"ok":False,"message":message,"rate_limited":exc.code==429},429 if exc.code==429 else 502)
    except Exception as exc:
        if cached:
            return listing_response({"ok":True,"cached":True,"stale":True,"warning":"Показаны последние сохранённые ордера",**cached})
        return listing_response({"ok":False,"message":str(exc)},502)

@app.route("/api/market/listings/<path:login>",methods=["GET"])
def api_market_sell_listings(login):
    try:
        return jsonify(steam_market_sell_listings(login))
    except Exception as exc:
        return jsonify({"ok":False,"message":str(exc)}),502


@app.route("/api/market/listings/<path:login>/remove",methods=["POST"])
def api_market_remove_sell_listing(login):
    data = request.get_json(silent=True) or {}
    listing_id = str(data.get("listing_id") or "").strip()
    if not listing_id.isdigit():
        return jsonify({"ok":False,"message":"Некорректный ID лота"}),400
    try:
        steam_market_remove_sell_listing(login,listing_id)
        return jsonify({"ok":True,"listing_id":listing_id,"message":"Лот снят с продажи"})
    except Exception as exc:
        return jsonify({"ok":False,"message":str(exc)}),400


@app.route("/api/market/listings/<path:login>/remove-all",methods=["POST"])
def api_market_remove_all_sell_listings(login):
    try:
        result = steam_market_remove_all_sell_listings(login)
        return jsonify({"ok":True,**result})
    except Exception as exc:
        return jsonify({"ok":False,"message":str(exc)}),400


@app.route("/api/market/buy-orders/<path:login>",methods=["GET"])
def api_market_buy_orders(login):
    try:
        orders, _ = steam_market_tf2_buy_orders(login)
        with AUTH_LOCK:
            account = dict(AUTH_STATE.get(login,{}))
        return jsonify({"ok":True,"orders":orders,"currency":steam_currency_id(account)})
    except Exception as exc:
        return jsonify({"ok":False,"message":str(exc)}),502


@app.route("/api/market/buy-orders/<path:login>/cancel",methods=["POST"])
def api_market_cancel_buy_order(login):
    data = request.get_json(silent=True) or {}
    order_id = str(data.get("buy_orderid") or "").strip()
    if not order_id.isdigit():
        return jsonify({"ok":False,"message":"Некорректный ID ордера"}),400
    try:
        # Re-read the account's own orders and cancel only an exact TF2 match.
        orders, market_session = steam_market_tf2_buy_orders(login)
        order = next((item for item in orders if item.get("buy_orderid")==order_id),None)
        if not order:
            return jsonify({"ok":False,"message":"Активный TF2-ордер с таким ID не найден. Обновите список"}),404
        result = steam_market_post(login,"cancelbuyorder",{"buy_orderid":order_id},market_session=market_session)
        if not result.get("success"):
            raise RuntimeError(str(result.get("message") or "Steam не отменил ордер"))
        log_event("TF2 buy order cancelled: "+order_id,"INFO",login)
        return jsonify({"ok":True,"buy_orderid":order_id,"message":"Ордер отменён"})
    except Exception as exc:
        return jsonify({"ok":False,"message":str(exc)}),400


@app.route("/api/market/buy/<path:login>",methods=["POST"])
def api_market_buy(login):
    data = request.get_json(silent=True) or {}
    try:
        name = str(data.get("name") or "").strip()
        if name not in ("Mann Co. Supply Crate Key","Tour of Duty Ticket"):
            raise ValueError("Неподдерживаемый предмет")
        quantity = int(data.get("quantity") or 1)
        if quantity < 1 or quantity > 100:
            raise ValueError("Количество: от 1 до 100")
        unit_cents = market_cents(data.get("price"),"цену ордера")
        with AUTH_LOCK:
            account = dict(AUTH_STATE.get(login,{}))
        currency = steam_currency_id(account)
        listing_url = "https://steamcommunity.com/market/listings/440/" + urllib.parse.quote(name,safe="")
        # price_total is the total for the whole order in the wallet's minor units.
        # Since Steam's 2025 market change, an order can require a separate
        # confirmation pass: confirmation=0, mobile allow, then same request
        # with the returned confirmation_id.
        # Exact fields used by Steam's current classic market.js. Empty billing
        # values are intentional for accounts that do not require billing info.
        fields = {
            "currency":currency,
            "appid":440,
            "market_hash_name":name,
            "price_total":unit_cents*quantity,
            "tradefee_tax":0,
            "quantity":quantity,
            "first_name":"",
            "last_name":"",
            "billing_address":"",
            "billing_address_two":"",
            "billing_country":"",
            "billing_city":"",
            "billing_state":"",
            "billing_postal_code":"",
            "save_my_address":0,
            "confirmation":0
        }
        log_event("TF2 buy order: sending "+name+"; "+str(quantity)+" pcs; currency="+steam_currency_code(account),"INFO",login)
        result = steam_market_post(login,"createbuyorder",fields,referer=listing_url)
        if result.get("success") == 1:
            log_event("TF2 buy order created: "+str(result.get("buy_orderid") or "completed immediately"),"INFO",login)
            return jsonify({"ok":True,"needs_confirmation":False,"buy_orderid":result.get("buy_orderid"),"message":"✓ Ордер на покупку создан"})
        if result.get("need_confirmation") or result.get("needs_confirmation") or result.get("needs_mobile_confirmation"):
            confirmation = result.get("confirmation") or {}
            confirmation_id = str(confirmation.get("confirmation_id") or result.get("confirmation_id") or "").strip()
            if not confirmation_id:
                raise RuntimeError("Steam запросил подтверждение, но не вернул confirmation_id")
            match = None
            last_confirmation_error = ""
            for attempt in range(8):
                if attempt:
                    time.sleep(1.5)
                confirmations, status = fetch_account_confirmations(login)
                if confirmations.get("ok"):
                    # For Market confirmations Steam may return the buy-order
                    # confirmation_id as either id or creator_id. Both are exact
                    # identifiers; never fall back to accepting another item.
                    match = next((
                        item for item in confirmations.get("confirmations",[])
                        if item.get("kind")=="market" and confirmation_id in (
                            str(item.get("id") or ""),
                            str(item.get("creator_id") or "")
                        )
                    ),None)
                    if match:
                        break
                else:
                    last_confirmation_error = str(confirmations.get("message") or "")
            if not match:
                raise RuntimeError(last_confirmation_error or "Подтверждение ордера не найдено. Откройте ✓ и подтвердите его вручную, затем повторите создание")
            log_event("TF2 buy order: mobile confirmation found; approving only this order","INFO",login)
            confirmed, code = process_trade_confirmations(login,"accept",confirmation_ids=[match["id"]])
            if not confirmed.get("ok") or int(confirmed.get("count") or 0) != 1:
                raise RuntimeError("Не удалось автоматически подтвердить именно этот ордер: "+str(confirmed.get("message") or "Steam не выполнил подтверждение"))
            time.sleep(1.5)
            fields["confirmation"] = confirmation_id
            result = steam_market_post(login,"createbuyorder",fields,referer=listing_url)
            if result.get("success") == 1:
                log_event("TF2 buy order confirmed and created: "+str(result.get("buy_orderid") or "completed immediately"),"INFO",login)
                return jsonify({"ok":True,"needs_confirmation":False,"confirmed":True,"buy_orderid":result.get("buy_orderid"),"message":"✓ Ордер подтверждён и создан"})
            raise RuntimeError(str(result.get("message") or "Ордер подтверждён, но повторный запрос Steam отклонён (success="+str(result.get("success"))+")"))
        detail = str(result.get("message") or result.get("error") or "").strip()
        raise RuntimeError(detail or "Steam не создал ордер (success="+str(result.get("success"))+")")
    except Exception as exc:
        log_event("TF2 buy order failed: "+str(exc),"ERROR",login)
        return jsonify({"ok":False,"message":str(exc)}),400

def confirm_outgoing_tradeoffer(login, tradeofferid):
    # Confirm only the confirmation whose creator_id equals this exact offer.
    # Never accept unrelated pending trades as a side effect.
    for attempt in range(4):
        result, status = fetch_account_confirmations(login,with_details=False)
        if result.get("ok"):
            match = next((x for x in result.get("confirmations",[]) if x.get("kind")=="trade" and str(x.get("creator_id") or "")==str(tradeofferid)),None)
            if match:
                confirmed, code = process_trade_confirmations(login,"accept",confirmation_ids=[match["id"]])
                return bool(confirmed.get("ok")), str(confirmed.get("message") or "")
        if attempt < 3:
            time.sleep(1.2)
    return False, "Трейд создан, но его подтверждение не найдено. Откройте ✓"

@app.route("/api/inventory/trade/<path:login>",methods=["POST"])
def api_inventory_trade(login):
    data = request.get_json(silent=True) or {}
    try:
        trade_url = parse_trade_url(data.get("trade_url"))
        if not trade_url:
            raise ValueError("Выберите сохранённую Trade URL")
        parsed = urllib.parse.urlparse(trade_url)
        query = urllib.parse.parse_qs(parsed.query)
        partner = str((query.get("partner") or [""])[0])
        token = str((query.get("token") or [""])[0])
        if not partner.isdigit() or not token:
            raise ValueError("Trade URL не содержит partner/token")
        appid = int(data.get("appid") or 0)
        contextid = str(data.get("contextid") or "2")
        requested = data.get("assetids") or []
        if not isinstance(requested,list):
            raise ValueError("Некорректный список предметов")
        selected_ids = list(dict.fromkeys(str(x) for x in requested if str(x).isdigit()))
        if not selected_ids or len(selected_ids)>100:
            raise ValueError("Выберите от 1 до 100 предметов")
        with INVENTORY_LOCK:
            cached = INVENTORY_CACHE.get(inventory_cache_key(login,appid,contextid)) or {}
        by_id = {str(x.get("assetid")):x for x in cached.get("items",[])}
        assets = []
        for assetid in selected_ids:
            item = by_id.get(assetid)
            if not item:
                raise ValueError("Предмет отсутствует в загруженном инвентаре. Обновите его")
            trade_lock_until = int(item.get("trade_lock_until") or 0)
            if not item.get("tradable") and trade_lock_until and trade_lock_until <= int(time.time()):
                item["tradable"] = True
            if not item.get("tradable"):
                raise ValueError("В выборе есть недоступный для обмена предмет: "+str(item.get("name") or assetid))
            amount = max(1,int(item.get("amount") or 1)) if data.get("full_amount") else 1
            assets.append({"appid":appid,"contextid":contextid,"amount":amount,"assetid":assetid})
        cookies, session_id = steam_market_cookies(login)
        # The saved web cookie may contain an obsolete sessionid. Open the same
        # trade URL first and use the fresh g_sessionID issued for this offer.
        preflight_req = urllib.request.Request(trade_url,headers={"User-Agent":"Mozilla/5.0","Cookie":steam_cookie_header(cookies),"Accept":"text/html","Accept-Encoding":"identity"})
        try:
            with urllib.request.urlopen(preflight_req,timeout=25) as preflight_response:
                preflight_html = preflight_response.read().decode("utf-8",errors="replace")
            fresh_session = re.search(r"g_sessionID\s*=\s*[\"']([^\"']+)",preflight_html)
            if fresh_session:
                session_id = fresh_session.group(1)
            else:
                raise RuntimeError("Steam не открыл авторизованную страницу трейда. Выполните повторный вход")
            if "login/redirect" in str(preflight_response.geturl()) or "Sign in" in preflight_html[:5000]:
                raise RuntimeError("Trade web-сессия не активна. Выполните повторный вход")
        except urllib.error.HTTPError as exc:
            # A 302 is often Steam's normal trade-page redirect. It must not
            # abort the actual offer request. Reuse a redirected sessionid when
            # Steam provides one; otherwise keep the saved web session.
            if exc.code in (301,302,303,307,308):
                set_cookie = str(exc.headers.get("Set-Cookie") or "")
                redirected_session = re.search(r"(?:^|[,;]\s*)sessionid=([^;,\s]+)",set_cookie,re.I)
                if redirected_session:
                    session_id = redirected_session.group(1)
                log_event("Trade preflight redirect HTTP "+str(exc.code)+"; continuing with the web session","WARN",login)
            else:
                raise RuntimeError("Не удалось открыть Trade URL: HTTP "+str(exc.code))
        offer = {"newversion":True,"version":len(assets)+1,"me":{"assets":assets,"currency":[],"ready":True},"them":{"assets":[],"currency":[],"ready":True}}
        fields = {"sessionid":session_id,"serverid":1,"partner":str(76561197960265728+int(partner)),"tradeoffermessage":"","json_tradeoffer":json.dumps(offer,separators=(",",":")),"captcha":"","trade_offer_create_params":json.dumps({"trade_offer_access_token":token},separators=(",",":"))}
        req = urllib.request.Request("https://steamcommunity.com/tradeoffer/new/send",data=urllib.parse.urlencode(fields).encode("utf-8"),method="POST",headers={"User-Agent":"Mozilla/5.0","Accept":"application/json","Content-Type":"application/x-www-form-urlencoded; charset=UTF-8","Cookie":steam_cookie_header(cookies),"Referer":trade_url,"Origin":"https://steamcommunity.com","Accept-Encoding":"identity"})
        try:
            with urllib.request.urlopen(req,timeout=30) as response:
                raw_response = response.read()
                if raw_response.startswith(b"\x1f\x8b"):
                    raw_response = gzip.decompress(raw_response)
                result = json.loads(raw_response.decode("utf-8",errors="replace"))
        except urllib.error.HTTPError as exc:
            raw_body = exc.read()
            if raw_body.startswith(b"\x1f\x8b"):
                try:
                    raw_body = gzip.decompress(raw_body)
                except OSError:
                    pass
            body = raw_body.decode("utf-8",errors="replace")[:1500]
            try:
                error_payload = json.loads(body)
                detail = str(error_payload.get("strError") or error_payload.get("message") or body)
            except Exception:
                detail = ("Steam отклонил предложение без описания. Обновите инвентарь, проверьте Trade URL и Trade Hold" if body.strip() in ("", "null") else body)
            raise RuntimeError("Steam Trade HTTP "+str(exc.code)+": "+detail[:500])
        if not isinstance(result,dict) or result.get("strError"):
            raise RuntimeError(str((result or {}).get("strError") or "Steam не создал трейд"))
        offerid = str(result.get("tradeofferid") or "")
        if not offerid:
            raise RuntimeError("Steam не вернул tradeofferid")
        needs_confirmation = bool(result.get("needs_mobile_confirmation") or result.get("needs_mobile_confirmtaion"))
        confirmed = False
        confirmation_message = "Подтверждение не требуется"
        if needs_confirmation:
            confirmed,confirmation_message = confirm_outgoing_tradeoffer(login,offerid)
        if not data.get("preserve_cache"):
            with INVENTORY_LOCK:
                INVENTORY_CACHE.pop(inventory_cache_key(login,appid,contextid),None)
        log_event("Trade offer sent from inventory: "+str(len(assets))+" items; auto_confirmed="+str(confirmed),"INFO",login)
        return jsonify({"ok":True,"tradeofferid":offerid,"items_sent":len(assets),"confirmed":confirmed,"needs_confirmation":needs_confirmation,"message":"Трейд отправлен и подтверждён" if confirmed else "Трейд отправлен. "+confirmation_message})
    except Exception as exc:
        log_event("Inventory trade failed: "+str(exc)[:500],"ERROR",login)
        return jsonify({"ok":False,"message":str(exc)}),400

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html; charset=utf-8")


@app.route("/api/history")
def api_history():
    text, lines = read_history()
    login = str(request.args.get("login") or "").strip()
    if login:
        marker = "] [" + login + "] "
        text = "\n".join(line for line in text.splitlines() if marker in line)
        lines = len(text.splitlines()) if text else 0
    return jsonify({"ok":True,"text":text,"lines":lines,"path":str(HISTORY_FILE),"login":login})

@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    try:
        HISTORY_FILE.write_text("", encoding="utf-8")
        return jsonify({"ok":True})
    except OSError as exc:
        return jsonify({"ok":False,"message":str(exc)}), 500

@app.route("/api/project")
def api_project():
    return jsonify({
        "project": str(BASE_DIR),
        "logpass": str(LOGPASS_FILE),
        "mafiles": str(MAFILES_DIR),
        "mafiles_exists": MAFILES_DIR.exists()
    })


@app.route("/api/open/<target>")
def api_open(target):
    targets = {"project": BASE_DIR, "mafiles": MAFILES_DIR, "logpass": LOGPASS_FILE}
    target_path = targets.get(target)
    if target_path is None:
        return jsonify({"ok": False, "message": "Неизвестный путь"}), 400
    try:
        if target in ("project", "mafiles"):
            target_path.mkdir(parents=True, exist_ok=True)
        if target == "logpass" and not target_path.exists():
            target_path.touch()
        os.startfile(str(target_path))
        return jsonify({"ok": True, "path": str(target_path)})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


def find_steamid_by_login(login):
    wanted = str(login or "").strip().casefold()
    if not wanted:
        return None

    # Same lookup rules as authorization: <login>.mafile first, then
    # <steamid>.mafile resolved through account_name inside the file.
    files = list(_iter_mafiles())
    for path in files:
        if path.stem.strip().casefold() == wanted:
            data = _read_mafile(path)
            if data:
                return data["steamid"]
    for path in files:
        data = _read_mafile(path)
        if data and data["account_name"].casefold() == wanted:
            return data["steamid"]
    return None



STEAM_GUARD_CHARS = "23456789BCDFGHJKMNPQRTVWXY"

def generate_steam_guard_code(shared_secret, now=None):
    """Generate the current Steam Guard mobile authenticator code locally."""
    if not shared_secret:
        raise ValueError("shared_secret отсутствует")
    raw = base64.b64decode(str(shared_secret).strip() + "=" * (-len(str(shared_secret).strip()) % 4))
    timestamp = int(time.time() if now is None else now) // 30
    digest = hmac.new(raw, timestamp.to_bytes(8, "big"), hashlib.sha1).digest()
    start = digest[-1] & 0x0F
    value = int.from_bytes(digest[start:start + 4], "big") & 0x7FFFFFFF
    code = ""
    for _ in range(5):
        code += STEAM_GUARD_CHARS[value % len(STEAM_GUARD_CHARS)]
        value //= len(STEAM_GUARD_CHARS)
    return code


@app.route("/api/security/<path:login>")
def api_security(login):
    """Return only the current Guard code; never expose the maFile secret/token data."""
    ma = find_mafile_data(login)
    if not ma:
        return jsonify({"ok": False, "message": "Для аккаунта не найден maFile с shared_secret."}), 404
    try:
        now = time.time()
        code = generate_steam_guard_code(ma["shared_secret"], now)
        remaining = 30 - (int(now) % 30)
        return jsonify({
            "ok": True,
            "code": code,
            "remaining": remaining,
            "steamid": ma.get("steamid", "")
        }), 200, {"Cache-Control":"no-store, no-cache, must-revalidate, max-age=0", "Pragma":"no-cache"}
    except Exception:
        return jsonify({"ok": False, "message": "Не удалось вычислить код Steam Guard."}), 500, {"Cache-Control":"no-store"}


@app.route("/api/profile/<path:login>")
def api_profile(login):
    steamid = find_steamid_by_login(login)
    if not steamid:
        return jsonify({
            "ok": False,
            "message": "Для аккаунта «%s» не найден подходящий maFile." % login
        }), 404
    return jsonify({
        "ok": True,
        "steamid": steamid,
        "url": "https://steamcommunity.com/profiles/" + steamid + "/"
    })


@app.route("/api/account-credentials/<path:login>")
def api_account_credentials(login):
    wanted = login.strip().casefold()
    accounts, _, exists = read_logpass()
    if not exists:
        return jsonify({"ok": False, "message": "logpass.txt не найден."}), 404
    try:
        raw = LOGPASS_FILE.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raw = LOGPASS_FILE.read_text(encoding="utf-8")
    except OSError:
        return jsonify({"ok": False, "message": "Не удалось прочитать logpass.txt."}), 500
    for line in raw.splitlines():
        line=line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, password = line.split(":", 1)
        if name.strip().casefold() == wanted:
            return jsonify({"ok": True, "login": name.strip(), "password": password.strip()})
    return jsonify({"ok": False, "message": "Аккаунт не найден в logpass.txt."}), 404


def run_games_helper(login, command, target=None):
    """Run games.js with encrypted refresh-session first, then credentials fallback."""
    login = str(login or "").strip()
    creds = find_account_credentials(login)
    ma = find_mafile_data(login)
    if not creds:
        return {"ok": False, "error": "Аккаунт не найден в logpass.txt."}, 404
    if not ma or not ma.get("shared_secret") or not ma.get("steamid"):
        return {"ok": False, "error": "Для аккаунта не найден maFile/shared_secret/steamid."}, 404
    helper = BASE_DIR / "games.js"
    if not helper.exists():
        return {"ok": False, "error": "games.js не найден рядом с app.py."}, 500
    node_exe = get_node_executable()
    if not node_exe or not node_ready():
        ok, message = install_node_runtime()
        if not ok:
            return {"ok": False, "error": "Node.js: " + str(message)}, 500
        node_exe = get_node_executable()
    if not node_exe:
        return {"ok": False, "error": "node.exe не найден."}, 500

    base_env = os.environ.copy()
    base_env["PATH"] = str(NODE_DIR) + os.pathsep + base_env.get("PATH", "")
    base_env["NODE_PATH"] = str(NODE_DIR / "node_modules")
    base_env["SHARK_STEAM_LOGIN"] = creds[0]
    base_env["SHARK_STEAM_PASSWORD"] = creds[1]
    base_env["SHARK_STEAM_SHARED_SECRET"] = ma["shared_secret"]
    base_env["SHARK_STEAM_ID"] = ma["steamid"]

    args = [node_exe, str(helper), command]
    if target is not None:
        args.append(str(target))

    def execute(env):
        try:
            return subprocess.run(
                args, cwd=str(BASE_DIR), env=env,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=70, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        except subprocess.TimeoutExpired:
            return None

    session = load_steam_session(login)
    used_session = bool(session and session.get("refresh_token"))
    env = dict(base_env)
    if used_session:
        env["SHARK_STEAM_REFRESH_TOKEN"] = str(session["refresh_token"])
        log_event("Games: trying encrypted Steam session first", "INFO", login)

    proc = execute(env)
    if proc is None:
        return {"ok": False, "error": "games.js: тайм-аут ожидания Steam."}, 504

    def parse_process(proc):
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        result = None
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                log_event("games.js stdout: " + line[:500], "WARN", login)
                continue
            if payload.get("type") == "log":
                log_event(str(payload.get("message") or ""), str(payload.get("level") or "INFO"), login)
            elif "ok" in payload or payload.get("action"):
                result = payload
        if stderr.strip():
            for line in stderr.splitlines():
                if line.strip():
                    log_event("games.js stderr: " + line.strip()[:500], "WARN", login)
        return result, stderr

    result, stderr = parse_process(proc)
    if (not result or not result.get("ok")) and used_session and (result or {}).get("auth_session_invalid") is True:
        session_error = str((result or {}).get("error") or stderr.strip() or "session expired/invalid")
        log_event("Games saved session rejected; falling back to login/password: " + session_error, "WARN", login)
        env = dict(base_env)
        proc = execute(env)
        if proc is None:
            return {"ok": False, "error": "games.js: тайм-аут ожидания Steam."}, 504
        result, stderr = parse_process(proc)

    if result is None:
        return {"ok": False, "error": stderr.strip() or "games.js не вернул результат."}, 500
    if result.get("ok") and result.get("refresh_token"):
        new_token = str(result.get("refresh_token") or "")
        old_token = str((session or {}).get("refresh_token") or "")
        if new_token and new_token != old_token:
            save_steam_session(login, new_token, ma.get("steamid", ""))
    return result, (200 if result.get("ok") else 422)


@app.route("/api/games/<path:login>")
def api_games(login):
    login = str(login or "").strip()
    with AUTH_LOCK:
        state = dict(AUTH_STATE.get(login, {}))
    if not state or state.get("auth_status") != "ok":
        return jsonify({"ok": False, "error": "Сначала нажмите «Авторизация» для этого аккаунта."}), 409
    games = state.get("games", [])
    if not isinstance(games, list):
        games = []
    count = state.get("games_count", len(games))
    try: count = int(count)
    except (TypeError, ValueError): count = len(games)
    return jsonify({"ok": True, "action": "list", "games": games, "card_games":state.get("card_games",[]),"count": count, "updated": state.get("games_updated", "")})


@app.route("/api/games/add/<path:login>", methods=["POST"])
def api_games_add(login):
    data = request.get_json(silent=True) or {}
    target = str(data.get("target") or "").strip()
    if not target:
        return jsonify({"ok": False, "error": "Не указан AppID/SubID/Steam URL."}), 400
    result, status = run_games_helper(login, "add", target)
    if status == 200 and result.get("ok") and result.get("action") in ("added", "already_owned"):
        # Refresh the in-memory library immediately. The Games page reads from
        # AUTH_STATE, so a successful Steam license grant must also update the
        # cached list before the browser reloads it.
        # Steam's license grant and its owned-games WebAPI are asynchronous.
        # Refresh a few times instead of assuming the first response is already
        # updated. This does not re-authenticate unless the saved session is invalid.
        refreshed = None
        refresh_status = 500
        for attempt in range(1, 5):
            time.sleep(2.0 if attempt > 1 else 0.5)
            refreshed, refresh_status = run_games_helper(login, "list")
            if refresh_status == 200 and refreshed.get("ok") and isinstance(refreshed.get("games"), list):
                games = refreshed["games"]
                target_text = target.strip()
                target_appid = None
                m = re.search(r"(?:/app/|^)(\d+)", target_text, re.I)
                if m:
                    try:
                        target_appid = int(m.group(1))
                    except ValueError:
                        target_appid = None
                if target_appid is None or any(int(g.get("appid", 0)) == target_appid for g in games if isinstance(g, dict)):
                    log_event(f"Games library refresh confirmed on attempt {attempt}", "INFO", login)
                    break
                log_event(f"Games library refresh attempt {attempt}: AppID {target_appid} not visible yet", "INFO", login)
        # Steam can acknowledge a free license before GetOwnedGames exposes it.
        # The license grant is already authoritative, so keep the granted AppID
        # in the local UI cache instead of making the user press Add to Library.
        if result.get("action") == "added" and (result.get("owned_confirmed") is True or result.get("license_confirmed") is True):
            try:
                target_appid = None
                m = re.search(r"(?:/app/|^)(\d+)", target.strip(), re.I)
                if m:
                    target_appid = int(m.group(1))
                if target_appid:
                    current = (refreshed or {}).get("games", []) if isinstance(refreshed, dict) else []
                    if not any(int(g.get("appid", 0)) == target_appid for g in current if isinstance(g, dict)):
                        current = list(current)
                        current.append({
                            "appid": target_appid,
                            "name": f"App {target_appid}",
                            "playtime_forever": 0,
                            "playtime_2weeks": None,
                            "img_icon_url": "",
                            "img_logo_url": "",
                            "rtime_last_played": 0
                        })
                        refreshed = {"ok": True, "games": current, "games_count": len(current)}
                        refresh_status = 200
                        log_event(f"Confirmed license: added AppID {target_appid} to local library cache", "INFO", login)
            except Exception as e:
                log_event("Local library cache update failed: " + str(e), "WARN", login)
        elif result.get("action") == "added":
            log_event("Steam helper reported added without ownership/license confirmation; refusing to fake a library entry", "WARN", login)
            result["ok"] = False
            result["action"] = "purchase_required"
            result["error"] = "Steam не подтвердил лицензию. Игра не была добавлена в библиотеку."
            status = 422

        if refresh_status == 200 and refreshed and refreshed.get("ok") and isinstance(refreshed.get("games"), list):
            with AUTH_LOCK:
                if login in AUTH_STATE:
                    AUTH_STATE[login]["games"] = refreshed["games"]
                    AUTH_STATE[login]["games_count"] = len(refreshed["games"])
                    AUTH_STATE[login]["games_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["games"] = refreshed["games"]
            result["games_count"] = len(refreshed["games"])
            result["games_updated"] = AUTH_STATE.get(login, {}).get("games_updated", "")
        else:
            log_event("Games add succeeded, but library refresh failed: " + str((refreshed or {}).get("error") or "unknown error"), "WARN", login)
    return jsonify(result), status


GAMES_ALL_LOCK = threading.Lock()
GAMES_ALL_STATE = {
    "running":False,"cancelling":False,"current":"","done":0,"total":0,
    "added":0,"skipped":0,"failed":0,"target":"","message":"",
    "last_login":"","last_action":"","last_message":"","errors":{}
}


def games_all_status():
    with GAMES_ALL_LOCK:
        state = dict(GAMES_ALL_STATE)
        state["errors"] = dict(state.get("errors") or {})
    return state


def game_target_appid(target):
    match = re.search(r"(?:/app/|^)(\d+)",str(target or "").strip(),re.I)
    if not match:
        return None
    try:
        appid = int(match.group(1))
        return appid if appid>0 else None
    except ValueError:
        return None


def account_owns_appid(login,appid):
    if not appid:
        return False
    with AUTH_LOCK:
        games = list(AUTH_STATE.get(login,{}).get("games",[]) or [])
    for game in games:
        try:
            if isinstance(game,dict) and int(game.get("appid") or 0)==appid:
                return True
        except (TypeError,ValueError):
            continue
    return False


def remember_mass_added_game(login,appid,result):
    games = result.get("games") if isinstance(result.get("games"),list) else None
    with AUTH_LOCK:
        state = AUTH_STATE.setdefault(login,{})
        if games is None:
            games = list(state.get("games",[]) or [])
            if appid and not any(isinstance(game,dict) and int(game.get("appid") or 0)==appid for game in games):
                games.append({"appid":appid,"name":"App "+str(appid),"playtime_forever":0,"playtime_2weeks":None,"img_icon_url":"","img_logo_url":"","rtime_last_played":0})
        state["games"] = games
        state["games_count"] = len(games)
        state["games_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_account_cache()


def games_all_add_worker(logins,target):
    try:
        for index,login in enumerate(logins):
            with GAMES_ALL_LOCK:
                if GAMES_ALL_STATE.get("cancelling"):
                    break
                GAMES_ALL_STATE.update({"current":login,"message":"Проверка библиотеки и добавление"})
            appid = game_target_appid(target)
            action = "error"
            message = ""
            try:
                if account_owns_appid(login,appid):
                    action = "skipped"
                    message = "Игра уже есть — аккаунт пропущен"
                else:
                    result,status = run_games_helper(login,"add",target)
                    result_action = str(result.get("action") or "")
                    if status==200 and result.get("ok") and result_action=="already_owned":
                        action = "skipped"
                        message = "Игра уже есть — аккаунт пропущен"
                    elif status==200 and result.get("ok") and result_action=="added" and (result.get("owned_confirmed") is True or result.get("license_confirmed") is True):
                        remember_mass_added_game(login,appid,result)
                        action = "added"
                        message = "Игра добавлена в библиотеку"
                    elif status==200 and result_action=="added":
                        message = "Steam не подтвердил лицензию; игра не добавлена"
                    else:
                        message = str(result.get("error") or result.get("message") or "Steam не добавил игру")
            except Exception as exc:
                message = "Ошибка добавления: "+str(exc)
                log_event(message,"ERROR",login)
            with GAMES_ALL_LOCK:
                if action=="added":
                    GAMES_ALL_STATE["added"] += 1
                elif action=="skipped":
                    GAMES_ALL_STATE["skipped"] += 1
                else:
                    GAMES_ALL_STATE["failed"] += 1
                    GAMES_ALL_STATE["errors"][login] = message
                GAMES_ALL_STATE.update({
                    "done":index+1,"last_login":login,"last_action":action,"last_message":message
                })
                log_event("Add Games Library: "+message,"INFO" if action!="error" else "WARN",login)
            if index+1<len(logins):
                with GAMES_ALL_LOCK:
                    if GAMES_ALL_STATE.get("cancelling"):
                        break
                    GAMES_ALL_STATE["message"] = "Пауза перед следующим аккаунтом"
                time.sleep(2)
    finally:
        with GAMES_ALL_LOCK:
            cancelled = bool(GAMES_ALL_STATE.get("cancelling"))
            GAMES_ALL_STATE.update({"running":False,"cancelling":False,"current":"","message":"Очередь остановлена" if cancelled else "Очередь завершена"})


@app.route("/api/games-all/add",methods=["POST","DELETE"])
def api_games_all_add():
    if request.method=="DELETE":
        with GAMES_ALL_LOCK:
            if not GAMES_ALL_STATE.get("running"):
                return jsonify({"ok":False,"message":"Массовое добавление не выполняется"}),409
            GAMES_ALL_STATE["cancelling"] = True
            GAMES_ALL_STATE["message"] = "Остановка после текущего аккаунта"
        return jsonify({"ok":True,"message":"Остановка после текущего аккаунта"})
    data = request.get_json(silent=True) or {}
    target = str(data.get("target") or "").strip()
    if not target:
        return jsonify({"ok":False,"message":"Укажите AppID, SubID или Steam URL"}),400
    logins = [account["login"] for account in read_logpass()[0]]
    if not logins:
        return jsonify({"ok":False,"message":"В logpass.txt нет аккаунтов"}),400
    with GAMES_ALL_LOCK:
        if GAMES_ALL_STATE.get("running"):
            return jsonify({"ok":False,"message":"Массовое добавление уже выполняется"}),409
        GAMES_ALL_STATE.update({
            "running":True,"cancelling":False,"current":"","done":0,"total":len(logins),
            "added":0,"skipped":0,"failed":0,"target":target,"message":"Подготовка очереди",
            "last_login":"","last_action":"","last_message":"","errors":{}
        })
    threading.Thread(target=games_all_add_worker,args=(logins,target),daemon=True,name="GamesAllAddQueue").start()
    return jsonify({"ok":True,"message":"Add Games Library запущен: "+str(len(logins))+" аккаунтов",**games_all_status()})


@app.route("/api/games-all/status",methods=["GET"])
def api_games_all_status():
    return jsonify({"ok":True,**games_all_status()})


def parse_trade_url(value):
    trade_url = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(trade_url)
        query = urllib.parse.parse_qs(parsed.query)
        partner = str((query.get("partner") or [""])[0])
        token = str((query.get("token") or [""])[0]).strip()
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == "steamcommunity.com"
            and parsed.path == "/tradeoffer/new/"
            and partner.isdigit()
            and bool(token)
        )
    except (ValueError, TypeError):
        valid = False
    return trade_url if valid else None


def read_saved_trade_links():
    try:
        if not TRADE_LINK_FILE.exists():
            return []
        data = json.loads(TRADE_LINK_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return []
        values = data.get("trade_urls", [])
        if not values and data.get("trade_url"):
            values = [data.get("trade_url")]
        if not isinstance(values, list):
            return []
        result = []
        for value in values:
            link = parse_trade_url(value)
            if link and link not in result:
                result.append(link)
        return result[:5]
    except (OSError, ValueError, TypeError):
        return []


def write_saved_trade_links(links):
    tmp = TRADE_LINK_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"trade_urls": links}, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(TRADE_LINK_FILE)


@app.route("/api/trade/saved-link", methods=["GET", "POST", "DELETE"])
def api_saved_trade_link():
    if request.method == "GET":
        links = read_saved_trade_links()
        return jsonify({"ok": True, "trade_urls": links, "trade_url": links[-1] if links else ""})
    data = request.get_json(silent=True) or {}
    trade_url = parse_trade_url(data.get("trade_url"))
    if not trade_url:
        return jsonify({"ok": False, "message": "Некорректный Trade URL."}), 400
    links = read_saved_trade_links()
    try:
        if request.method == "DELETE":
            links = [link for link in links if link != trade_url]
        else:
            links = [link for link in links if link != trade_url]
            links.append(trade_url)
            if len(links) > 5:
                return jsonify({"ok": False, "message": "Можно сохранить не больше 5 ссылок."}), 409
        write_saved_trade_links(links)
        return jsonify({"ok": True, "trade_urls": links, "trade_url": links[-1] if links else ""})
    except OSError as exc:
        return jsonify({"ok": False, "message": "Не удалось сохранить ссылки: " + str(exc)}), 500


TRADE_BROWSER_HELPER = r"""
const fs = require('fs');
const http = require('http');
const port = Number(process.env.SHARK_TRADE_DEBUG_PORT || 0);
const tradeUrl = process.env.SHARK_TRADE_URL || '';
const rawCookies = JSON.parse(process.env.SHARK_TRADE_COOKIES || '[]');
function out(value){process.stdout.write(JSON.stringify(value)+'\n');}
function getJson(path){return new Promise((resolve,reject)=>{http.get({host:'127.0.0.1',port,path,timeout:1500},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>{try{resolve(JSON.parse(body));}catch(e){reject(e);}});}).on('error',reject).on('timeout',function(){this.destroy(new Error('CDP timeout'));});});}
async function main(){
 let version=null;
 for(let i=0;i<80;i++){try{version=await getJson('/json/version');if(version&&version.webSocketDebuggerUrl)break;}catch(e){}await new Promise(r=>setTimeout(r,100));}
 if(!version)throw new Error('Browser debugging endpoint did not start');
 const ws=new WebSocket(version.webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
 let nextId=0;const pending=new Map();
 ws.onmessage=event=>{try{const msg=JSON.parse(event.data);if(msg.id&&pending.has(msg.id)){const p=pending.get(msg.id);pending.delete(msg.id);clearTimeout(p.timer);if(msg.error)p.reject(new Error(msg.error.message||'CDP error'));else p.resolve(msg.result||{});}}catch(e){}};
 function call(method,params={},sessionId){return new Promise((resolve,reject)=>{const id=++nextId;const timer=setTimeout(()=>{pending.delete(id);reject(new Error('CDP command timeout: '+method));},10000);pending.set(id,{resolve,reject,timer});const msg={id,method,params};if(sessionId)msg.sessionId=sessionId;ws.send(JSON.stringify(msg));});}
 const wantedTitle=process.env.SHARK_TRADE_WINDOW_TITLE || '';
 let target=null;
 for(let i=0;i<60;i++){
  const targets=await getJson('/json/list');
  target=targets.find(t=>t.type==='page'&&t.title===wantedTitle)||targets.find(t=>t.type==='page'&&String(t.title||'').startsWith('Steam Trade'));
  if(target)break;
  await new Promise(r=>setTimeout(r,100));
 }
 if(!target)throw new Error('Trade dialog target not found');
 const attached=await call('Target.attachToTarget',{targetId:target.id,flatten:true});
 const sessionId=attached.sessionId;
 await call('Network.enable',{},sessionId);
 await call('Page.enable',{},sessionId);
 const cookies=[];
 for(const raw of rawCookies){
  const pair=String(raw).split(';',1)[0].trim();const at=pair.indexOf('=');if(at<=0)continue;
  const name=pair.slice(0,at).trim(),value=pair.slice(at+1);
  cookies.push({name,value,domain:'.steamcommunity.com',path:'/',secure:true,sameSite:'Lax'});
 }
 if(!cookies.some(c=>c.name==='steamLoginSecure'))throw new Error('steamLoginSecure cookie is missing');
 await call('Network.setCookies',{cookies},sessionId);
 const nav=await call('Page.navigate',{url:tradeUrl},sessionId);
 if(nav.errorText)throw new Error(nav.errorText);
 out({ok:true});ws.close();setTimeout(()=>process.exit(0),250);
}
main().catch(e=>{out({ok:false,error:String(e&&e.message||e)});process.exit(1);});
"""

def refresh_steam_web_cookies_for_trade(login):
    """Authenticate in the background and return fresh Steam Community cookies.

    Credentials and secrets stay in the child-process environment and are never
    sent to the dialog JavaScript or written to the trade HTML.
    """
    creds = find_account_credentials(login)
    ma = find_mafile_data(login)
    if not creds:
        return [], "Не найдены login:password в logpass.txt"
    if not ma or not ma.get("shared_secret"):
        return [], "Не найден maFile/shared_secret для аккаунта"
    if not ensure_auth_helper():
        return [], "Не удалось подготовить модуль авторизации Steam"
    if not node_ready():
        ok, message = install_node_runtime()
        if not ok:
            return [], message
    node_exe = get_node_executable()
    if not node_exe:
        return [], "Node.js не найден"

    env = os.environ.copy()
    env["PATH"] = str(NODE_DIR) + os.pathsep + env.get("PATH", "")
    env["NODE_PATH"] = str(NODE_DIR / "node_modules")
    env["SHARK_STEAM_LOGIN"] = creds[0]
    env["SHARK_STEAM_PASSWORD"] = creds[1]
    env["SHARK_STEAM_SHARED_SECRET"] = ma["shared_secret"]
    env["SHARK_STEAM_ID"] = ma.get("steamid", "")

    def run(auth_env):
        return subprocess.run(
            [node_exe, str(AUTH_HELPER)], cwd=str(NODE_DIR), env=auth_env,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )

    def parse(proc):
        answer = None
        for raw_line in (proc.stdout or "").splitlines():
            try:
                payload = json.loads(raw_line)
            except (ValueError, TypeError):
                continue
            if "ok" in payload:
                answer = payload
        if answer is None:
            answer = {"ok":False, "error":(proc.stderr or "").strip() or "Steam не вернул результат авторизации"}
        return answer

    try:
        saved = load_steam_session(login)
        used_saved = bool(saved and saved.get("refresh_token"))
        if used_saved:
            env["SHARK_STEAM_REFRESH_TOKEN"] = str(saved["refresh_token"])
        proc = run(env)
        result = parse(proc)
        if (not result.get("ok")) and used_saved:
            env.pop("SHARK_STEAM_REFRESH_TOKEN", None)
            proc = run(env)
            result = parse(proc)
        if not result.get("ok"):
            return [], str(result.get("error") or "Фоновая авторизация Steam не удалась")
        cookies = result.get("web_cookies") or []
        if not any(str(item).startswith("steamLoginSecure=") for item in cookies):
            return [], "Steam авторизовался, но не выдал steamLoginSecure"
        save_steam_web_cookies(login, cookies)
        if result.get("refresh_token"):
            save_steam_session(login, result["refresh_token"], ma.get("steamid", ""))
        log_event("Фоновая авторизация для trade-диалога завершена", "INFO", login)
        return cookies, ""
    except subprocess.TimeoutExpired:
        return [], "Тайм-аут фоновой авторизации Steam"
    except Exception as exc:
        log_event("Trade authorization exception: " + str(exc), "ERROR", login)
        return [], str(exc)


def install_trade_cookies_in_dialog(login, trade_url, cookies):
    if not WEBVIEW_DEBUG_PORT:
        raise RuntimeError("Отладочный канал окна приложения не инициализирован")
    if not node_ready():
        ok, message = install_node_runtime()
        if not ok:
            raise RuntimeError(message)
    node_exe = get_node_executable()
    if not node_exe:
        raise RuntimeError("Node.js не найден")
    helper = BASE_DIR / "_shark_trade_window.js"
    helper.write_text(TRADE_BROWSER_HELPER, encoding="utf-8")
    env = os.environ.copy()
    env["SHARK_TRADE_DEBUG_PORT"] = str(WEBVIEW_DEBUG_PORT)
    env["SHARK_TRADE_URL"] = trade_url
    env["SHARK_TRADE_WINDOW_TITLE"] = "Steam Trade — " + login
    env["SHARK_TRADE_COOKIES"] = json.dumps(cookies)
    proc = subprocess.run(
        [node_exe, str(helper)], cwd=str(NODE_DIR), env=env,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    result = None
    for line in (proc.stdout or "").splitlines():
        try:
            payload = json.loads(line)
            if "ok" in payload:
                result = payload
        except ValueError:
            continue
    if not result or not result.get("ok"):
        raise RuntimeError(str((result or {}).get("error") or (proc.stderr or "").strip() or "Не удалось установить Steam-сессию в диалоге"))


def open_authenticated_trade_window(login, trade_url):
    import webview

    loading_html = """<!doctype html><html><head><meta charset='utf-8'><title>Steam Trade — """ + login + """</title><style>
    html,body{margin:0;width:100%;height:100%;background:#071013;color:#dce8e8;font-family:Segoe UI,Arial;overflow:hidden}
    body{display:flex;align-items:center;justify-content:center}.box{text-align:center;padding:25px;max-width:440px}.spin{width:38px;height:38px;margin:0 auto 18px;border:3px solid #18373d;border-top-color:#54dce4;border-radius:50%;animation:s 1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}
    .title{font-size:17px;font-weight:700}.account{margin-top:7px;color:#58d7e1;font-size:11px}.status{margin-top:13px;color:#8ca5aa;font-size:11px;line-height:1.55}.track{width:260px;height:5px;margin:18px auto 0;background:#15292e;border-radius:8px;overflow:hidden}.bar{width:45%;height:100%;border-radius:8px;background:linear-gradient(90deg,#23aebb,#69e6ec);animation:p 1.35s ease-in-out infinite}@keyframes p{0%{transform:translateX(-110%)}100%{transform:translateX(330%)}}.error{color:#ed848c}</style></head><body><div class='box'><div class='spin' id='spin'></div><div class='title'>Подготовка Steam Trade</div><div class='account'>""" + login + """</div><div class='status' id='status'>Запуск фоновой авторизации...</div><div class='track' id='track'><div class='bar'></div></div></div></body></html>"""
    window = webview.create_window(
        "Steam Trade — " + login,
        html=loading_html,
        width=620,
        height=480,
        min_size=(620, 480),
        resizable=True,
        text_select=True,
    )

    def status(text, error=False):
        try:
            script = "(function(){var e=document.getElementById('status');if(e){e.textContent=" + json.dumps(text, ensure_ascii=False) + ";e.className=" + json.dumps("status error" if error else "status") + ";}if(" + ("true" if error else "false") + "){var s=document.getElementById('spin');var t=document.getElementById('track');if(s)s.style.display='none';if(t)t.style.display='none';}return true;})()"
            window.evaluate_js(script)
        except Exception:
            pass

    def worker():
        try:
            status("Авторизация через logpass.txt и maFile...")
            cookies, error = refresh_steam_web_cookies_for_trade(login)
            if not cookies:
                raise RuntimeError(error or "Не удалось авторизовать аккаунт")
            status("Авторизация завершена. Загружаю полноценный трейд...")
            install_trade_cookies_in_dialog(login, trade_url, cookies)
            log_event("Steam trade открыт в авторизованном диалоговом окне", "INFO", login)
        except Exception as exc:
            status("Ошибка: " + str(exc), True)
            log_event("Trade dialog exception: " + str(exc), "ERROR", login)

    threading.Thread(target=worker, daemon=True, name="TradeWindow-" + str(login)).start()
    return window


@app.route("/api/trade/open/<path:login>", methods=["POST"])
def api_open_trade(login):
    login = str(login or "").strip()
    data = request.get_json(silent=True) or {}
    trade_url = parse_trade_url(data.get("trade_url"))
    if not trade_url:
        return jsonify({"ok": False, "message": "Некорректный Trade URL."}), 400
    if not find_account_credentials(login):
        return jsonify({"ok": False, "message": "Аккаунт не найден в logpass.txt."}), 404
    try:
        open_authenticated_trade_window(login, trade_url)
        return jsonify({"ok": True, "message": "Окно открыто, выполняется авторизация: " + login})
    except Exception as exc:
        log_event("Не удалось открыть окно trade offer: " + str(exc), "ERROR", login)
        return jsonify({"ok": False, "message": "Не удалось открыть окно трейда: " + str(exc)}), 500


def steam_cookie_header(cookies):
    pairs = []
    for cookie in cookies or []:
        pair = str(cookie).split(";", 1)[0].strip()
        if "=" in pair:
            pairs.append(pair)
    return "; ".join(pairs)


def wait_for_steam_web_cookies(login, timeout=75):
    cookies = load_steam_web_cookies(login)
    if cookies:
        return cookies, ""
    start_authorization(login)
    deadline = time.time() + timeout
    while time.time() < deadline:
        cookies = load_steam_web_cookies(login)
        if cookies:
            return cookies, ""
        with AUTH_LOCK:
            state = dict(AUTH_STATE.get(login, {}))
        if state.get("auth_status") == "error":
            return [], str(state.get("auth_error") or "Авторизация Steam не удалась")
        time.sleep(0.5)
    return [], "Тайм-аут получения Steam web-сессии"


def steam_device_id(steamid, configured=""):
    if configured:
        return configured
    digest = hashlib.sha1(str(steamid).encode("ascii")).hexdigest()
    return "android:" + "-".join((digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]))


def steam_confirmation_query(steamid, device_id, identity_secret, tag, timestamp):
    secret = base64.b64decode(identity_secret + "=" * (-len(identity_secret) % 4))
    payload = int(timestamp).to_bytes(8, "big") + tag.encode("utf-8")
    signature = base64.b64encode(hmac.new(secret, payload, hashlib.sha1).digest()).decode("ascii")
    return {
        "p": device_id,
        "a": str(steamid),
        "k": signature,
        "t": str(int(timestamp)),
        "m": "react",
        "tag": tag,
    }


CONFIRMATION_WEAR_RE = re.compile(
    r"\s*\((?:Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred|FN|MW|FT|WW|BS)\)\s*$",
    re.I
)


def confirmation_item_base_name(value):
    text = html_unescape(str(value or "")).strip()
    text = re.sub(r"^\d+\s*[x×]\s*","",text,flags=re.I)
    return CONFIRMATION_WEAR_RE.sub("",text).strip().casefold()


def enrich_confirmation_item_names(entry,candidates):
    """Restore explicit exteriors from Steam summary names without guessing them."""
    by_base = {}
    for candidate in candidates or []:
        candidate = html_unescape(str(candidate or "")).strip()
        if not CONFIRMATION_WEAR_RE.search(candidate):
            continue
        by_base.setdefault(confirmation_item_base_name(candidate),[])
        if candidate not in by_base[confirmation_item_base_name(candidate)]:
            by_base[confirmation_item_base_name(candidate)].append(candidate)
    for key in ("item_images","outgoing_items","incoming_items"):
        for image in entry.get(key) or []:
            if not isinstance(image,dict):
                continue
            current = str(image.get("name") or "").strip()
            if not current or CONFIRMATION_WEAR_RE.search(current):
                continue
            matches = by_base.get(confirmation_item_base_name(current),[])
            # Multiple exteriors of the same weapon are ambiguous; leave those
            # unchanged rather than attaching the wrong FN/FT/BS label.
            if len(matches) == 1:
                image["name"] = matches[0]
    return entry


MARKET_ITEM_ICON_CACHE = {}
MARKET_ITEM_ICON_CACHE_LOCK = threading.Lock()


def confirmation_item_exact_key(value):
    text = html_unescape(str(value or "")).strip().casefold()
    return re.sub(r"\s+"," ",text)


def normalize_market_icon_url(value):
    icon = html_unescape(str(value or "")).strip().replace("\\/","/")
    if not icon:
        return ""
    if icon.startswith("//"):
        return "https:"+icon
    if icon.startswith("/"):
        return "https://community.fastly.steamstatic.com"+icon
    if icon.startswith(("https://","http://")):
        return icon
    return "https://community.fastly.steamstatic.com/economy/image/"+icon.lstrip("/")


def market_item_icon_from_html(page_html,expected_name):
    """Read an exact-name item icon from Market search results HTML."""
    target = confirmation_item_exact_key(expected_name)
    rows = list(re.finditer(r"<div\b[^>]*class\s*=\s*([\"'])[^\"']*\bmarket_listing_row\b[^\"']*\1[^>]*>",str(page_html or ""),re.I))
    for index,row in enumerate(rows):
        block = page_html[row.start():rows[index+1].start() if index+1<len(rows) else len(page_html)]
        name_match = re.search(r"class\s*=\s*([\"'])[^\"']*\bmarket_listing_item_name\b[^\"']*\1[^>]*>(.*?)</",block,re.I|re.S)
        if not name_match or confirmation_item_exact_key(market_html_text(name_match.group(2))) != target:
            continue
        image_match = re.search(r"<img\b[^>]*>",block,re.I)
        if not image_match:
            continue
        attrs = {match.group(1).lower():html_unescape(match.group(3)) for match in re.finditer(r"([:\w-]+)\s*=\s*([\"'])(.*?)\2",image_match.group(0),re.S)}
        icon = normalize_market_icon_url(attrs.get("src") or attrs.get("data-src"))
        if icon:
            return icon
    return ""


def market_item_icon_lookup(name):
    """Resolve a real Steam economy icon only by an exact full item name."""
    name = html_unescape(str(name or "")).strip()
    if not name or name == "Предмет" or confirmation_item_count_summary(name):
        return ""
    key = confirmation_item_exact_key(name)
    now = time.time()
    with MARKET_ITEM_ICON_CACHE_LOCK:
        cached = MARKET_ITEM_ICON_CACHE.get(key) or {}
        if cached and now-float(cached.get("at") or 0) < (604800 if cached.get("icon") else 60):
            return str(cached.get("icon") or "")
    icon = ""
    query = urllib.parse.urlencode({"query":name,"start":0,"count":10,"search_descriptions":0,"sort_column":"popular","sort_dir":"desc"})
    headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36","Accept":"application/json","Referer":"https://steamcommunity.com/market/search?q="+urllib.parse.quote(name)}
    try:
        req = urllib.request.Request("https://steamcommunity.com/market/search/render/?"+query,headers=headers)
        with urllib.request.urlopen(req,timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8",errors="replace"))
        for result in payload.get("results") or []:
            if not isinstance(result,dict):
                continue
            description = result.get("asset_description") if isinstance(result.get("asset_description"),dict) else {}
            candidate = result.get("hash_name") or result.get("name") or description.get("market_hash_name") or description.get("name")
            if confirmation_item_exact_key(candidate) != key:
                continue
            icon = normalize_market_icon_url(description.get("icon_url_large") or description.get("icon_url") or result.get("icon_url_large") or result.get("icon_url"))
            if icon:
                break
        if not icon:
            icon = market_item_icon_from_html(str(payload.get("results_html") or ""),name)
    except Exception:
        icon = ""
    with MARKET_ITEM_ICON_CACHE_LOCK:
        MARKET_ITEM_ICON_CACHE[key] = {"at":now,"icon":icon}
    return icon


def fill_missing_confirmation_item_icons(login,entry):
    """Use cached inventory icons; never search Market for count-only summaries."""
    groups = [entry.get(key) or [] for key in ("outgoing_items","incoming_items")]
    combined = entry.get("item_images") or []
    if not any(combined is group for group in groups):
        groups.append(combined)
    with INVENTORY_LOCK:
        inventory_items = []
        prefix = str(login)+":"
        for key,value in INVENTORY_CACHE.items():
            if str(key).startswith(prefix) and isinstance(value,dict):
                inventory_items.extend(list(value.get("items") or []))
    lookups = 0
    allow_market = entry.get("kind") != "trade"
    for group in groups:
        for item in group:
            if not isinstance(item,dict) or item.get("icon"):
                continue
            name = str(item.get("name") or "").strip()
            if not name or name == "Предмет" or confirmation_item_count_summary(name):
                continue
            target = confirmation_item_exact_key(name)
            match = next((candidate for candidate in inventory_items if confirmation_item_exact_key(candidate.get("market_hash_name") or candidate.get("name")) == target and candidate.get("icon")),None)
            if match:
                item["icon"] = str(match.get("icon") or "")
                continue
            if not allow_market or lookups >= 3:
                continue
            lookups += 1
            icon = market_item_icon_lookup(name)
            if icon:
                item["icon"] = icon
    return entry


def confirmation_trade_summary_sides(items):
    """Read Steam's English trade summary when detailed sides are unavailable."""
    outgoing = []
    incoming = []
    def summary_item(value):
        name = str(value or "").strip()
        count = re.fullmatch(r"(\d+)\s*(?:items?|предмет(?:а|ов)?|item\(s\))",name,re.I)
        return {"name":name,"icon":"","amount":int(count.group(1)) if count else 1,"type":"","rarity":""}
    for value in items or []:
        text = html_unescape(str(value or "")).strip()
        match = re.match(r"^You will give up(?:\s+your)?\s+(.+)$",text,re.I)
        if match:
            outgoing.append(summary_item(match.group(1)))
            continue
        match = re.match(r"^For their:\s*(.+)$",text,re.I)
        if not match:
            match = re.match(r"^You will receive(?:\s+their)?\s+(.+)$",text,re.I)
        if match:
            incoming.append(summary_item(match.group(1)))
    return outgoing,incoming


def confirmation_item_count_summary(value):
    """True for Steam's count-only summaries such as '3 items'."""
    text = html_unescape(str(value or "")).strip()
    return bool(re.fullmatch(r"\d+\s*(?:items?|предмет(?:а|ов)?|item\(s\))",text,re.I))


def confirmation_item_rarity(value):
    """Normalize only an explicit Steam item type; never guess from its name."""
    text = re.sub(r"\s+"," ",html_unescape(str(value or "")).strip()).casefold()
    if not text:
        return ""
    if "contraband" in text or "контрабанд" in text:
        return "contraband"
    if "exceedingly rare" in text or "extraordinary" in text or "чрезвычайно редк" in text:
        return "exceedingly"
    if re.search(r"\bcovert\b|тайн(?:ое|ый|ая)",text):
        return "covert"
    if re.search(r"\bclassified\b|засекреч",text):
        return "classified"
    if re.search(r"\brestricted\b|запрещ",text):
        return "restricted"
    if re.search(r"\bmil[ -]?spec\b|армейск",text):
        return "milspec"
    if re.search(r"\bindustrial grade\b|промышленн",text):
        return "industrial"
    if re.search(r"\bconsumer grade\b|\bbase grade\b|ширпотреб|базов(?:ый|ое|ая)",text):
        return "consumer"
    return ""


def confirmation_item_amount(value):
    try:
        return max(1,int(value or 1))
    except (TypeError,ValueError):
        return 1


class SteamTradeItemsHTMLParser(HTMLParser):
    """Read every trade-item container, including items without an image."""
    VOID_TAGS = {"area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"}
    ITEM_CLASSES = {"trade_item","tradeoffer_item","mobileconf_trade_item","mobileconf_tradeoffer_item"}
    NAME_CLASSES = {"trade_item_name","tradeoffer_item_name","mobileconf_trade_item_name","mobileconf_tradeoffer_item_name","market_listing_item_name","item_name"}
    AMOUNT_CLASSES = {"trade_item_amount","tradeoffer_item_amount","mobileconf_trade_item_amount","mobileconf_tradeoffer_item_amount","item_amount"}
    TYPE_CLASSES = {"trade_item_type","tradeoffer_item_type","mobileconf_trade_item_type","mobileconf_tradeoffer_item_type","market_listing_item_type","item_type"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []
        self.side = ""
        self.div_stack = []
        self.current = None
        self.item_depth = 0
        self.name_depth = 0
        self.amount_depth = 0
        self.type_depth = 0
        self.name_parts = []
        self.amount_parts = []
        self.type_parts = []
        self.text_parts = []

    def handle_starttag(self,tag,attrs):
        tag = str(tag).lower()
        data = {str(key).lower():html_unescape(str(value or "")) for key,value in attrs}
        classes = set(str(data.get("class") or "").lower().split())
        if tag == "div":
            previous = self.side
            side_marker = False
            if "tradeoffer_items" in classes or "mobileconf_trade_items" in classes or "mobileconf_tradeoffer_items" in classes:
                if "primary" in classes:
                    self.side = "outgoing"
                    side_marker = True
                elif "secondary" in classes:
                    self.side = "incoming"
                    side_marker = True
            self.div_stack.append((side_marker,previous))
        if self.current is None:
            if tag not in self.VOID_TAGS and (classes & self.ITEM_CLASSES or data.get("data-economy-item")):
                self.current = {"attrs":data,"side":self.side,"name":"","image_name":"","icon":"","amount":1,"type":""}
                self.item_depth = 1
                self.text_parts = []
        else:
            if tag not in self.VOID_TAGS:
                self.item_depth += 1
            if classes & self.NAME_CLASSES:
                self.name_depth = self.item_depth
                self.name_parts = []
            if classes & self.AMOUNT_CLASSES:
                self.amount_depth = self.item_depth
                self.amount_parts = []
            if classes & self.TYPE_CLASSES:
                self.type_depth = self.item_depth
                self.type_parts = []
        if self.current is not None and tag == "img":
            src = data.get("src") or data.get("data-src") or data.get("data-icon-url") or data.get("data-image") or ""
            if not src and data.get("srcset"):
                src = str(data.get("srcset")).split(",",1)[0].strip().split(" ",1)[0]
            src = str(src).strip().replace("\\/","/")
            if "economy/image/" in src and not self.current.get("icon"):
                self.current["icon"] = normalize_market_icon_url(src)
            image_name = str(data.get("data-market-hash-name") or data.get("data-market_hash_name") or data.get("alt") or data.get("title") or data.get("data-name") or "").strip()
            if image_name and not confirmation_item_count_summary(image_name):
                self.current["image_name"] = image_name

    def handle_endtag(self,tag):
        tag = str(tag).lower()
        if self.current is not None:
            if self.name_depth and self.name_depth == self.item_depth:
                self.current["name"] = re.sub(r"\s+"," "," ".join(self.name_parts)).strip()
                self.name_depth = 0
            if self.amount_depth and self.amount_depth == self.item_depth:
                amount_text = " ".join(self.amount_parts)
                amount_match = re.search(r"\d+",amount_text)
                if amount_match:
                    self.current["amount"] = confirmation_item_amount(amount_match.group(0))
                self.amount_depth = 0
            if self.type_depth and self.type_depth == self.item_depth:
                self.current["type"] = re.sub(r"\s+"," "," ".join(self.type_parts)).strip()
                self.type_depth = 0
            if tag not in self.VOID_TAGS:
                self.item_depth -= 1
            if self.item_depth <= 0:
                self.finish_item()
        if tag == "div" and self.div_stack:
            side_marker,previous = self.div_stack.pop()
            if side_marker:
                self.side = previous

    def handle_data(self,data):
        if self.current is None:
            return
        text = str(data or "").strip()
        if not text:
            return
        self.text_parts.append(text)
        if self.name_depth:
            self.name_parts.append(text)
        if self.amount_depth:
            self.amount_parts.append(text)
        if self.type_depth:
            self.type_parts.append(text)

    def finish_item(self):
        current = self.current
        self.current = None
        self.item_depth = self.name_depth = self.amount_depth = self.type_depth = 0
        if not current:
            return
        attrs = current.get("attrs") or {}
        economy = str(attrs.get("data-economy-item") or "")
        economy_match = re.match(r"classinfo/(\d+)/(\d+)(?:/(\d+))?",economy,re.I)
        appid = str(attrs.get("data-appid") or (economy_match.group(1) if economy_match else "") or "")
        classid = str(attrs.get("data-classid") or (economy_match.group(2) if economy_match else "") or "")
        instanceid = str(attrs.get("data-instanceid") or (economy_match.group(3) if economy_match else "") or "")
        assetid = str(attrs.get("data-assetid") or attrs.get("data-asset") or attrs.get("assetid") or "")
        contextid = str(attrs.get("data-contextid") or attrs.get("data-context") or "")
        if not assetid:
            id_match = re.search(r"(?:^|_)(\d+)$",str(attrs.get("id") or ""))
            if id_match:
                assetid = id_match.group(1)
        name = str(current.get("name") or current.get("image_name") or "").strip()
        if not name or confirmation_item_count_summary(name):
            for key in ("data-market-hash-name","data-market_hash_name","data-name","title","alt"):
                candidate = str(attrs.get(key) or "").strip()
                if candidate and not confirmation_item_count_summary(candidate):
                    name = candidate
                    break
        full_text = re.sub(r"\s+"," "," ".join(self.text_parts)).strip()
        if not name and full_text and len(full_text) <= 220 and not confirmation_item_count_summary(full_text):
            name = full_text
        if name and not CONFIRMATION_WEAR_RE.search(name):
            exterior = re.search(r"\b(Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred)\b",full_text,re.I)
            if exterior:
                name += " ("+exterior.group(1)+")"
        if not name and not current.get("icon") and not economy and not assetid:
            return
        item_type = str(current.get("type") or attrs.get("data-type") or attrs.get("data-rarity") or "").strip()
        self.items.append({
            "name":name or "Предмет","icon":str(current.get("icon") or ""),
            "amount":confirmation_item_amount(current.get("amount")),
            "side":str(current.get("side") or ""),"assetid":assetid,
            "appid":appid,"contextid":contextid,"classid":classid,"instanceid":instanceid,
            "type":item_type,"rarity":confirmation_item_rarity(item_type)
        })


def parse_steam_trade_items_html(fragment):
    parser = SteamTradeItemsHTMLParser()
    try:
        parser.feed(str(fragment or ""))
        parser.close()
    except Exception:
        pass
    if parser.current is not None:
        parser.finish_item()
    return parser.items


def steam_json_assignment(source,variable):
    match = re.search(r"\b"+re.escape(variable)+r"\s*=\s*",str(source or ""))
    if not match:
        return None
    try:
        value,_ = json.JSONDecoder().raw_decode(str(source)[match.end():].lstrip())
        return value
    except (ValueError,TypeError,json.JSONDecodeError):
        return None


def parse_tradeoffer_page_html(page_html):
    """Restore exact assets, names and icons from Steam's full trade-offer page."""
    source = str(page_html or "")
    status = steam_json_assignment(source,"g_rgCurrentTradeStatus")
    dom_items = parse_steam_trade_items_html(source)
    by_asset = {str(item.get("assetid")):item for item in dom_items if item.get("assetid")}
    by_class = {}
    for item in dom_items:
        if item.get("classid"):
            by_class[(str(item.get("appid") or ""),str(item.get("classid")),str(item.get("instanceid") or ""))] = item
    descriptions = {}

    def register(description,default_appid="",fallback_key=""):
        if not isinstance(description,dict):
            return
        classid = str(description.get("classid") or "")
        instanceid = str(description.get("instanceid") or "")
        if (not classid or not instanceid) and fallback_key:
            parts = str(fallback_key).split("_")
            if not classid and parts:
                classid = parts[0]
            if not instanceid and len(parts) > 1:
                instanceid = parts[1]
        if not classid:
            return
        appid = str(description.get("appid") or default_appid or "")
        record = dict(description)
        record["appid"] = appid
        for key in ((appid,classid,instanceid),(appid,classid,""),("",classid,instanceid),("",classid,"")):
            descriptions[key] = record

    if isinstance(status,dict):
        root_descriptions = status.get("descriptions") or []
        if isinstance(root_descriptions,dict):
            root_descriptions = list(root_descriptions.values())
        for description in root_descriptions:
            register(description)
    for variable in ("g_rgAppContextData","g_rgPartnerAppContextData","g_rgMyAppContextData","g_rgTheirAppContextData"):
        contexts = steam_json_assignment(source,variable)
        if not isinstance(contexts,dict):
            continue
        for appid,context in contexts.items():
            if not isinstance(context,dict):
                continue
            group = context.get("rgDescriptions") or context.get("descriptions") or {}
            if isinstance(group,dict):
                for key,description in group.items():
                    register(description,appid,key)
            elif isinstance(group,list):
                for description in group:
                    register(description,appid)

    def dom_match(asset,side):
        assetid = str(asset.get("assetid") or asset.get("id") or "")
        if assetid and assetid in by_asset:
            return by_asset[assetid]
        key = (str(asset.get("appid") or ""),str(asset.get("classid") or ""),str(asset.get("instanceid") or ""))
        if key in by_class:
            return by_class[key]
        return next((item for item in dom_items if item.get("side") == side and item.get("classid") and item.get("classid") == str(asset.get("classid") or "")),{})

    def convert(asset,side):
        if not isinstance(asset,dict):
            return None
        appid = str(asset.get("appid") or "")
        classid = str(asset.get("classid") or "")
        instanceid = str(asset.get("instanceid") or "")
        description = descriptions.get((appid,classid,instanceid)) or descriptions.get((appid,classid,"")) or descriptions.get(("",classid,instanceid)) or descriptions.get(("",classid,"")) or {}
        dom = dom_match(asset,side)
        name = str(description.get("market_hash_name") or description.get("name") or asset.get("market_hash_name") or asset.get("name") or dom.get("name") or "Предмет").strip()
        icon = normalize_market_icon_url(description.get("icon_url_large") or description.get("icon_url") or asset.get("icon_url_large") or asset.get("icon_url") or dom.get("icon") or "")
        if confirmation_item_count_summary(name):
            name = str(dom.get("name") or "Предмет")
        item_type = str(description.get("type") or asset.get("type") or dom.get("type") or "").strip()
        return {
            "name":name,"icon":icon,"amount":confirmation_item_amount(asset.get("amount") or dom.get("amount")),
            "assetid":str(asset.get("assetid") or asset.get("id") or dom.get("assetid") or ""),
            "appid":appid,"contextid":str(asset.get("contextid") or dom.get("contextid") or ""),
            "classid":classid,"instanceid":instanceid,"type":item_type,"rarity":confirmation_item_rarity(item_type)
        }

    outgoing = []
    incoming = []
    if isinstance(status,dict) and isinstance(status.get("me"),dict) and isinstance(status.get("them"),dict):
        for asset in (status.get("me",{}).get("assets") or []):
            item = convert(asset,"outgoing")
            if item:
                outgoing.append(item)
        for asset in (status.get("them",{}).get("assets") or []):
            item = convert(asset,"incoming")
            if item:
                incoming.append(item)
    else:
        item_keys = ("name","icon","amount","assetid","appid","contextid","classid","instanceid","type","rarity")
        outgoing = [{key:item.get(key) for key in item_keys} for item in dom_items if item.get("side") == "outgoing"]
        incoming = [{key:item.get(key) for key in item_keys} for item in dom_items if item.get("side") == "incoming"]
    base = parse_confirmation_details_html(source)
    if not isinstance(status,dict) and (base.get("outgoing_items") or base.get("incoming_items")):
        # Offer-list headers are authoritative: received offers may place the
        # incoming side in .primary and the outgoing side in .secondary.
        outgoing = list(base.get("outgoing_items") or [])
        incoming = list(base.get("incoming_items") or [])
    base.update({"outgoing_items":outgoing,"incoming_items":incoming,"item_images":outgoing+incoming})
    base["incoming_only"] = bool(incoming and not outgoing)
    base["outgoing_only"] = bool(outgoing and not incoming)
    return base


def confirmation_trade_entry_needs_offer(entry):
    """A missing thumbnail is not a reason to download the whole offer again."""
    items = list(entry.get("outgoing_items") or [])+list(entry.get("incoming_items") or [])
    if not items:
        return True
    return any(not str(item.get("name") or "").strip() or str(item.get("name") or "") == "Предмет" or confirmation_item_count_summary(item.get("name")) for item in items)


def confirmation_items_score(items):
    score = 0
    for item in items or []:
        name = str(item.get("name") or "")
        if name and name != "Предмет" and not confirmation_item_count_summary(name):
            score += 4
        else:
            score -= 4
        if item.get("icon"):
            score += 2
    return score


def merge_tradeoffer_confirmation_details(entry,offer_details):
    """Prefer the side with real item names/icons, never replace it with a worse summary."""
    for key in ("outgoing_items","incoming_items"):
        candidate = list(offer_details.get(key) or [])
        current = list(entry.get(key) or [])
        if candidate and (not current or confirmation_items_score(candidate) >= confirmation_items_score(current)):
            old_icons = {confirmation_item_exact_key(item.get("name")):str(item.get("icon") or "") for item in current if item.get("icon")}
            for item in candidate:
                if not item.get("icon") and old_icons.get(confirmation_item_exact_key(item.get("name"))):
                    item["icon"] = old_icons[confirmation_item_exact_key(item.get("name"))]
            entry[key] = candidate
    if offer_details.get("avatar"):
        entry["avatar"] = offer_details["avatar"]
    outgoing = list(entry.get("outgoing_items") or [])
    incoming = list(entry.get("incoming_items") or [])
    entry["item_images"] = outgoing+incoming
    entry["incoming_only"] = bool(incoming and not outgoing)
    entry["outgoing_only"] = bool(outgoing and not incoming)
    return entry


def parse_confirmation_details_html(fragment):
    """Extract the two trade sides separately from Steam's details fragment."""
    text = market_html_text(fragment)
    avatar = ""
    avatar_candidates = []
    for image_match in re.finditer(r"<img\b[^>]*>",fragment,re.I):
        tag = image_match.group(0)
        attrs = {match.group(1).lower():html_unescape(match.group(3)) for match in re.finditer(r"([:\w-]+)\s*=\s*([\"'])(.*?)\2",tag,re.S)}
        src = html_unescape(str(attrs.get("src") or attrs.get("data-src") or "").strip()).replace("\\/","/")
        if src.startswith("//"):
            src = "https:"+src
        classes = str(attrs.get("class") or "").lower()
        if not src.startswith(("https://","http://")) or not ("avatar" in classes or "/avatars/" in src or "avatar" in src.lower()):
            continue
        nearby = fragment[max(0,image_match.start()-450):min(len(fragment),image_match.end()+450)].lower()
        score = 0
        if "partner" in classes:
            score += 6
        if "tradeoffer_partner" in nearby or "partner_avatar" in nearby or "tradeoffer partner" in nearby:
            score += 4
        if "playeravatar" in classes:
            score -= 2
        avatar_candidates.append((score,image_match.start(),src))
    if avatar_candidates:
        partner_avatars = [candidate for candidate in avatar_candidates if candidate[0] > 0]
        if partner_avatars:
            avatar = max(partner_avatars,key=lambda candidate:(candidate[0],candidate[1]))[2]
        elif len(avatar_candidates) > 1:
            # Steam renders the account avatar in the page header and the trade
            # partner afterwards. Never use the first/header avatar by default.
            avatar = avatar_candidates[-1][2]

    def extract_items(chunk):
        # Item containers are authoritative: they preserve identical assets and
        # items whose icon failed to load. Image parsing below is only a fallback.
        items = []
        for item in parse_steam_trade_items_html(chunk):
            items.append({
                "name":str(item.get("name") or "Предмет"),"icon":str(item.get("icon") or ""),
                "amount":confirmation_item_amount(item.get("amount")),"assetid":str(item.get("assetid") or ""),
                "appid":str(item.get("appid") or ""),"contextid":str(item.get("contextid") or ""),
                "classid":str(item.get("classid") or ""),"instanceid":str(item.get("instanceid") or ""),
                "type":str(item.get("type") or ""),"rarity":str(item.get("rarity") or "")
            })
        dom_icons = {}
        for item in items:
            if item.get("icon"):
                dom_icons[item["icon"]] = dom_icons.get(item["icon"],0)+1
        for tag in re.findall(r"<img\b[^>]*>",chunk,re.I):
            attrs = {match.group(1).lower():html_unescape(match.group(3)) for match in re.finditer(r"([:\w-]+)\s*=\s*([\"'])(.*?)\2",tag,re.S)}
            src = str(attrs.get("src") or attrs.get("data-src") or attrs.get("data-icon-url") or attrs.get("data-image") or "").strip()
            if not src and attrs.get("srcset"):
                src = str(attrs.get("srcset")).split(",",1)[0].strip().split(" ",1)[0]
            src = html_unescape(src).replace("\\/","/")
            if src.startswith("//"):
                src = "https:"+src
            elif src.startswith("/"):
                src = "https://community.fastly.steamstatic.com"+src
            if not src.startswith(("https://","http://")) or "economy/image/" not in src:
                continue
            if dom_icons.get(src,0) > 0:
                dom_icons[src] -= 1
                continue
            name = str(attrs.get("data-market-hash-name") or attrs.get("data-market_hash_name") or attrs.get("alt") or attrs.get("title") or attrs.get("data-name") or "Предмет").strip() or "Предмет"
            if confirmation_item_count_summary(name):
                name = "Предмет"
            items.append({"name":name,"icon":src,"amount":1,"assetid":""})
        # Some versions render economy icons as CSS backgrounds instead of <img>.
        existing_icons = {str(item.get("icon") or "") for item in items}
        for src in re.findall(r"background(?:-image)?\s*:\s*url\([\"']?([^\"')]+)",chunk,re.I):
            src = html_unescape(src.strip()).replace("\\/","/")
            if src.startswith("//"):
                src = "https:"+src
            elif src.startswith("/"):
                src = "https://community.fastly.steamstatic.com"+src
            if "economy/image/" in src and src not in existing_icons:
                existing_icons.add(src)
                items.append({"name":"Предмет","icon":src,"amount":1,"assetid":""})
        if len(items) == 1 and str(items[0].get("name") or "") == "Предмет":
            visible_name = re.search(
                r"<(?:div|span)\b[^>]*class\s*=\s*([\"'])[^\"']*(?:tradeoffer_item_name|market_listing_item_name|item_name)[^\"']*\1[^>]*>\s*([^<>]+?)\s*</",
                chunk,re.I
            )
            if visible_name:
                items[0]["name"] = html_unescape(visible_name.group(2)).strip()
        if len(items) == 1 and not CONFIRMATION_WEAR_RE.search(str(items[0].get("name") or "")):
            # Market details may keep the short name in alt while rendering the
            # exterior in a sibling element. Read it only for an unambiguous
            # single-item fragment; never infer an exterior from the picture.
            full_name = re.search(
                r">\s*([^<>]{2,180}?\((?:Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred)\))\s*<",
                chunk,re.I
            )
            if full_name:
                items[0]["name"] = html_unescape(full_name.group(1)).strip()
            else:
                exterior = re.search(r">\s*(Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred)\s*<",chunk,re.I)
                if exterior:
                    items[0]["name"] = str(items[0].get("name") or "Предмет")+" ("+exterior.group(1)+")"
        return items

    outgoing_items = []
    incoming_items = []
    gives = bool(re.search(r"\b(?:you|items you)\s+(?:will\s+)?(?:give|are giving|send|lose)\b|\byou have given\b",text,re.I))
    receives = bool(re.search(r"\b(?:you|items you)\s+(?:will\s+)?(?:receive|are receiving|get)\b|\byou have received\b",text,re.I))
    # Steam wraps the sides in .tradeoffer_items.primary/.secondary. Splitting
    # at those wrappers avoids mixing nested .tradeoffer_item_list elements.
    sections = list(re.finditer(r"<div\b[^>]*\bclass\s*=\s*([\"'])[^\"']*\b(?:tradeoffer_items|mobileconf_trade_items|mobileconf_tradeoffer_items)\b[^\"']*\1[^>]*>",fragment,re.I))
    if sections:
        gives = False
        receives = False
    for index,section in enumerate(sections):
        end = sections[index+1].start() if index+1<len(sections) else len(fragment)
        chunk = fragment[section.start():end]
        header_match = re.search(r"<div\b[^>]*\bclass\s*=\s*([\"'])[^\"']*\b(?:tradeoffer_items_header|mobileconf_trade_items_header|mobileconf_tradeoffer_items_header)\b[^\"']*\1[^>]*>(.*?)</div>",chunk,re.I|re.S)
        header = market_html_text(header_match.group(2)) if header_match else ""
        opening = section.group(0).lower()
        header_gives = bool(re.search(r"\byou\s+(?:will\s+)?give\b",header,re.I))
        header_receives = bool(re.search(r"\byou\s+(?:will\s+)?receive\b",header,re.I))
        if header_gives or (not header_receives and "primary" in opening):
            gives = gives or not bool(re.search(r"\bgive(?:\s+up)?\s+0\s+items?\b",header,re.I))
            outgoing_items.extend(extract_items(chunk))
        elif header_receives or (not header_gives and "secondary" in opening):
            receives = receives or not bool(re.search(r"\breceive\s+0\s+items?\b",header,re.I))
            incoming_items.extend(extract_items(chunk))

    unclassified = [] if sections else extract_items(fragment)
    if not sections and incoming_items == outgoing_items == []:
        if receives and not gives:
            incoming_items = unclassified
        elif gives and not receives:
            outgoing_items = unclassified
    if incoming_items or outgoing_items:
        unclassified = []
    assetids = set(re.findall(r"(?:data-assetid|data-asset|assetid)[\"'\s:=]+(\d+)",fragment,re.I))
    return {
        "avatar":avatar,"item_images":outgoing_items+incoming_items+unclassified,
        "outgoing_items":outgoing_items,"incoming_items":incoming_items,
        "assetids":sorted(assetids),
        "incoming_only":bool(receives and not gives),
        "outgoing_only":bool(gives and not receives),
        "market_buyer_pays_cents":market_confirmation_price_cents(text)
    }


ECONOMY_ITEMCLASS_CACHE = {}
ECONOMY_ITEMCLASS_CACHE_LOCK = threading.Lock()


def parse_economy_itemclasshover(page_html):
    """Extract Steam's item JSON from BuildHover without brittle HTML regexes."""
    source = str(page_html or "")
    marker = source.find("BuildHover(")
    if marker < 0:
        return {}
    start = source.find("{",marker)
    if start < 0:
        return {}
    try:
        payload,_ = json.JSONDecoder().raw_decode(source[start:])
        return payload if isinstance(payload,dict) else {}
    except (ValueError,TypeError,json.JSONDecodeError):
        return {}


def fetch_economy_itemclass_description(appid,classid,instanceid,cookies=None):
    """Resolve exact English item metadata from the identifiers in a trade tile."""
    key = (str(appid or ""),str(classid or ""),str(instanceid or "0"))
    if not all(value.isdigit() for value in key):
        return {}
    now = time.time()
    with ECONOMY_ITEMCLASS_CACHE_LOCK:
        cached = ECONOMY_ITEMCLASS_CACHE.get(key) or {}
        if cached and now-float(cached.get("at") or 0) < (604800 if cached.get("data") else 60):
            return dict(cached.get("data") or {})
    query = urllib.parse.urlencode({"content_only":1,"l":"english"})
    url = "https://steamcommunity.com/economy/itemclasshover/"+"/".join(key)+"?"+query
    headers = {
        "Cookie":steam_cookie_header(cookies or []),
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept":"text/html,application/xhtml+xml",
        "Accept-Language":"en-US,en;q=0.9",
        "Referer":"https://steamcommunity.com/mobileconf/conf"
    }
    data = {}
    try:
        req = urllib.request.Request(url,headers=headers)
        with urllib.request.urlopen(req,timeout=8) as response:
            page_html = response.read().decode("utf-8",errors="replace")
        data = parse_economy_itemclasshover(page_html)
    except Exception:
        data = {}
    with ECONOMY_ITEMCLASS_CACHE_LOCK:
        ECONOMY_ITEMCLASS_CACHE[key] = {"at":now,"data":data}
    return data


def enrich_confirmation_items_from_itemclass(login,entry,cookies=None):
    """Turn mobile trade identifiers into exact names, icons and rarity metadata."""
    groups = [entry.get("outgoing_items") or [],entry.get("incoming_items") or []]
    pending = {}
    for group in groups:
        for item in group:
            if not isinstance(item,dict):
                continue
            key = (str(item.get("appid") or ""),str(item.get("classid") or ""),str(item.get("instanceid") or "0"))
            # Always prefer Steam's canonical metadata when identifiers exist:
            # list pages often contain only a short alt name without exterior.
            if all(value.isdigit() for value in key):
                pending.setdefault(key,[]).append(item)
    failures = 0
    if pending:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(6,len(pending))) as pool:
            futures = {key:pool.submit(fetch_economy_itemclass_description,*key,cookies=cookies) for key in pending}
            for key,items in pending.items():
                description = futures[key].result()
                if not description:
                    failures += len(items)
                    continue
                exact_name = str(description.get("market_hash_name") or description.get("name") or "").strip()
                item_type = str(description.get("type") or "").strip()
                icon = normalize_market_icon_url(description.get("icon_url_large") or description.get("icon_url") or "")
                for item in items:
                    if exact_name:
                        item["name"] = exact_name
                    if icon:
                        item["icon"] = icon
                    if item_type:
                        item["type"] = item_type
                        item["rarity"] = confirmation_item_rarity(item_type)
    if failures:
        log_event("Steam не вернул описания предметов itemclasshover: "+str(failures),"WARNING",login)
    entry["item_images"] = list(entry.get("outgoing_items") or [])+list(entry.get("incoming_items") or [])
    return entry


def parse_confirmation_detailspage(payload):
    """Read exact trade assets from Steam's structured mobile detailspage response."""
    if not isinstance(payload,dict):
        return {}
    root = payload
    for _ in range(5):
        next_root = next((root.get(key) for key in ("tradeoffer","offer") if isinstance(root.get(key),dict)),None)
        if next_root is None:
            next_root = next((root.get(key) for key in ("response","details","data") if isinstance(root.get(key),dict) and not any(key in root for key in ("me","them","items_to_give","items_to_receive"))),None)
        if next_root is None or next_root is root:
            break
        root = next_root
    if not isinstance(root,dict):
        return {}

    descriptions = {}
    def register(description,default_appid="",fallback_key=""):
        if not isinstance(description,dict):
            return
        classid = str(description.get("classid") or "")
        instanceid = str(description.get("instanceid") or "0")
        if not classid and fallback_key:
            parts = str(fallback_key).split("_")
            classid = parts[0]
            if len(parts) > 1:
                instanceid = parts[1] or "0"
        if not classid:
            return
        appid = str(description.get("appid") or default_appid or "")
        record = dict(description)
        record["appid"] = appid
        for key in ((appid,classid,instanceid),(appid,classid,""),("",classid,instanceid),("",classid,"")):
            descriptions[key] = record

    def collect_descriptions(value,default_appid=""):
        if isinstance(value,dict):
            for key,child in value.items():
                lowered = str(key).lower()
                if lowered in ("descriptions","rgdescriptions"):
                    entries = child.values() if isinstance(child,dict) else child if isinstance(child,list) else []
                    if isinstance(child,dict):
                        entries = list(child.items())
                    for entry in entries:
                        if isinstance(entry,tuple):
                            fallback_key,description = entry
                        else:
                            fallback_key,description = "",entry
                        register(description,default_appid,fallback_key)
                elif lowered not in ("assets","items_to_give","items_to_receive","items_togive","items_toreceive"):
                    collect_descriptions(child,default_appid)
        elif isinstance(value,list):
            for child in value:
                collect_descriptions(child,default_appid)
    collect_descriptions(payload)

    def side_assets(side):
        direct_keys = ("items_to_give","itemsToGive","items_togive") if side == "outgoing" else ("items_to_receive","itemsToReceive","items_toreceive")
        for key in direct_keys:
            if isinstance(root.get(key),list):
                return root[key]
        side_keys = ("me","my","sender","from") if side == "outgoing" else ("them","their","partner","recipient","to")
        for key in side_keys:
            group = root.get(key)
            if not isinstance(group,dict):
                continue
            for asset_key in ("assets","items"):
                if isinstance(group.get(asset_key),list):
                    return group[asset_key]
        return []

    def convert(asset):
        if not isinstance(asset,dict):
            return None
        source = asset
        if isinstance(asset.get("asset"),dict):
            source = dict(asset["asset"])
            source.update({key:value for key,value in asset.items() if key != "asset"})
        appid = str(source.get("appid") or source.get("app_id") or "")
        classid = str(source.get("classid") or source.get("class_id") or "")
        instanceid = str(source.get("instanceid") or source.get("instance_id") or "0")
        nested = next((source.get(key) for key in ("description","item","classinfo") if isinstance(source.get(key),dict)),{})
        description = descriptions.get((appid,classid,instanceid)) or descriptions.get((appid,classid,"")) or descriptions.get(("",classid,instanceid)) or descriptions.get(("",classid,"")) or nested or {}
        name = str(description.get("market_hash_name") or description.get("name") or source.get("market_hash_name") or source.get("name") or "Предмет").strip()
        item_type = str(description.get("type") or source.get("type") or "").strip()
        icon = normalize_market_icon_url(description.get("icon_url_large") or description.get("icon_url") or source.get("icon_url_large") or source.get("icon_url") or "")
        return {
            "name":name,"icon":icon,"amount":confirmation_item_amount(source.get("amount")),
            "assetid":str(source.get("assetid") or source.get("asset_id") or source.get("id") or ""),
            "appid":appid,"contextid":str(source.get("contextid") or source.get("context_id") or ""),
            "classid":classid,"instanceid":instanceid,"type":item_type,"rarity":confirmation_item_rarity(item_type)
        }

    outgoing = [item for item in (convert(asset) for asset in side_assets("outgoing")) if item]
    incoming = [item for item in (convert(asset) for asset in side_assets("incoming")) if item]
    partner = root.get("partner") if isinstance(root.get("partner"),dict) else {}
    avatar = str(partner.get("avatarfull") or partner.get("avatarmedium") or partner.get("avatar") or "")
    return {
        "avatar":avatar,"outgoing_items":outgoing,"incoming_items":incoming,"item_images":outgoing+incoming,
        "assetids":[item["assetid"] for item in outgoing+incoming if item.get("assetid")],
        "incoming_only":bool(incoming and not outgoing),"outgoing_only":bool(outgoing and not incoming)
    }


def fetch_confirmation_details(login, confirmation_id, ma=None, cookies=None):
    """Load detailed mobile HTML once; React is a fallback, not an extra delay."""
    confirmation_id = str(confirmation_id or "")
    if not confirmation_id.isdigit():
        return {}
    ma = ma or find_mafile_data(login) or {}
    if not ma.get("identity_secret"):
        return {}
    cookies = cookies or load_steam_web_cookies(login)
    if not cookies:
        return {}
    last_details = {}
    last_error = ""
    for platform in ("android","react"):
        timestamp = int(time.time())
        query = steam_confirmation_query(ma["steamid"],steam_device_id(ma["steamid"],ma.get("device_id","")),ma["identity_secret"],"details",timestamp)
        query["m"] = platform
        query["l"] = "english"
        headers = {
            "Cookie":steam_cookie_header(cookies),
            "User-Agent":"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
            "Accept":"application/json","Accept-Language":"en-US,en;q=0.9",
            "X-Requested-With":"com.valvesoftware.android.steam.community",
            "Referer":"https://steamcommunity.com/mobileconf/conf"
        }
        try:
            req = urllib.request.Request("https://steamcommunity.com/mobileconf/details/"+confirmation_id+"?"+urllib.parse.urlencode(query),headers=headers)
            with urllib.request.urlopen(req,timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8",errors="replace"))
            if not isinstance(payload,dict) or payload.get("success") is not True:
                last_error = str((payload or {}).get("message") or "Steam отклонил запрос деталей") if isinstance(payload,dict) else "Некорректный ответ Steam"
                continue
            details = parse_confirmation_details_html(str(payload.get("html") or ""))
            if confirmation_items_score(details.get("item_images")) > confirmation_items_score(last_details.get("item_images")):
                last_details = details
            if details.get("item_images"):
                return details
        except Exception as exc:
            last_error = str(exc)
    if not last_details and last_error:
        log_event("Не удалось получить детали подтверждения "+confirmation_id+": "+last_error,"WARNING",login)
    return last_details


def steam_cookie_value(cookies,name):
    prefix = str(name)+"="
    for cookie in cookies or []:
        pair = str(cookie).split(";",1)[0].strip()
        if pair.startswith(prefix):
            return pair[len(prefix):]
    return ""


def tradeoffer_partner_steamid(page_html):
    source = str(page_html or "")
    for variable in ("g_ulTradePartnerSteamID","g_ulPartnerSteamID","g_steamIDPartner"):
        value = steam_json_assignment(source,variable)
        if value is not None and re.fullmatch(r"\d{17}",str(value)):
            return str(value)
        match = re.search(r"\b"+re.escape(variable)+r"\s*=\s*[\"'](\d{17})[\"']",source)
        if match:
            return match.group(1)
    partner_info = steam_json_assignment(source,"g_rgPartnerInfo")
    if isinstance(partner_info,dict):
        for key in ("steamid","steamID","steam_id"):
            if re.fullmatch(r"\d{17}",str(partner_info.get(key) or "")):
                return str(partner_info[key])
    return ""


def fetch_tradeoffer_inventory_data(url,cookies,referer):
    """Read legacy inventory JSON, including all pages and exact descriptions."""
    descriptions = {}
    assets = {}
    for _ in range(8):
        headers = {
            "Cookie":steam_cookie_header(cookies),
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Accept":"application/json, text/javascript, */*; q=0.01",
            "X-Requested-With":"XMLHttpRequest","Referer":referer
        }
        try:
            req = urllib.request.Request(url,headers=headers)
            with urllib.request.urlopen(req,timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8",errors="replace"))
        except Exception:
            break
        if not isinstance(payload,dict) or payload.get("error"):
            break
        group = payload.get("rgDescriptions") or {}
        if isinstance(group,dict):
            for key,description in group.items():
                if isinstance(description,dict):
                    descriptions[str(key)] = description
        elif isinstance(group,list):
            for description in group:
                if isinstance(description,dict):
                    descriptions[str(description.get("classid") or "")+"_"+str(description.get("instanceid") or "0")] = description
        group = payload.get("rgInventory") or {}
        values = group.values() if isinstance(group,dict) else group if isinstance(group,list) else []
        for asset in values:
            if isinstance(asset,dict):
                assets[str(asset.get("id") or asset.get("assetid") or "")] = asset
        if not payload.get("more"):
            break
        start = str(payload.get("more_start") or "")
        if not start:
            break
        url += ("&" if "?" in url else "?")+"start="+urllib.parse.quote(start)
    return {"assets":assets,"descriptions":descriptions}


def enrich_tradeoffer_items_from_inventory(items,data):
    assets = data.get("assets") or {}
    descriptions = data.get("descriptions") or {}
    by_asset = {}
    for asset in assets.values():
        key = str(asset.get("classid") or "")+"_"+str(asset.get("instanceid") or "0")
        description = descriptions.get(key)
        if description:
            by_asset[str(asset.get("id") or asset.get("assetid") or "")] = description
    for item in items or []:
        key = str(item.get("classid") or "")+"_"+str(item.get("instanceid") or "0")
        description = by_asset.get(str(item.get("assetid") or "")) or descriptions.get(key)
        if not isinstance(description,dict):
            continue
        current_name = str(item.get("name") or "")
        if not current_name or current_name == "Предмет" or confirmation_item_count_summary(current_name):
            name = str(description.get("market_hash_name") or description.get("name") or "").strip()
            if name:
                item["name"] = name
        if not item.get("icon"):
            item["icon"] = normalize_market_icon_url(description.get("icon_url_large") or description.get("icon_url") or "")
        if not item.get("type"):
            item["type"] = str(description.get("type") or "")
            item["rarity"] = confirmation_item_rarity(item["type"])
    return items


def enrich_tradeoffer_from_inventories(login,tradeofferid,cookies,page_html,details):
    """Resolve exact English names through the offer's own/partner inventories."""
    partner = tradeoffer_partner_steamid(page_html)
    sessionid = steam_cookie_value(cookies,"sessionid")
    for side,key in (("outgoing","outgoing_items"),("incoming","incoming_items")):
        items = details.get(key) or []
        def needs_metadata(item):
            name = str(item.get("name") or "")
            return not name or name == "Предмет" or confirmation_item_count_summary(name) or not item.get("type")
        pairs = sorted({(str(item.get("appid") or ""),str(item.get("contextid") or "")) for item in items if item.get("appid") and item.get("contextid") and needs_metadata(item)})
        for appid,contextid in pairs:
            if side == "incoming" and (not partner or not sessionid):
                continue
            if side == "outgoing":
                url = "https://steamcommunity.com/my/inventory/json/"+appid+"/"+contextid+"?l=english"
            else:
                query = urllib.parse.urlencode({"sessionid":sessionid,"partner":partner,"appid":appid,"contextid":contextid,"l":"english"})
                url = "https://steamcommunity.com/tradeoffer/"+str(tradeofferid)+"/partnerinventory/?"+query
            referer = "https://steamcommunity.com/tradeoffer/"+str(tradeofferid)+"/"
            data = fetch_tradeoffer_inventory_data(url,cookies,referer)
            scoped = [item for item in items if str(item.get("appid") or "") == appid and str(item.get("contextid") or "") == contextid]
            enrich_tradeoffer_items_from_inventory(scoped,data)
    details["item_images"] = list(details.get("outgoing_items") or [])+list(details.get("incoming_items") or [])
    return details


def fetch_tradeoffer_api_details(tradeofferid):
    """Optional exact IEconService fallback when the user saved a Web API key."""
    try:
        key = load_steam_api_key()
    except Exception:
        key = ""
    if not key:
        return {}
    query = urllib.parse.urlencode({"key":key,"tradeofferid":str(tradeofferid),"get_descriptions":1,"language":"english"})
    try:
        req = urllib.request.Request("https://api.steampowered.com/IEconService/GetTradeOffer/v1/?"+query,headers={"User-Agent":"SteamAccountManager/1.0","Accept":"application/json"})
        with urllib.request.urlopen(req,timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8",errors="replace"))
    except Exception:
        return {}
    response = payload.get("response") if isinstance(payload,dict) else {}
    offer = response.get("offer") if isinstance(response,dict) else {}
    if not isinstance(offer,dict):
        return {}
    descriptions = {}
    for description in response.get("descriptions") or []:
        if isinstance(description,dict):
            descriptions[(str(description.get("appid") or ""),str(description.get("classid") or ""),str(description.get("instanceid") or "0"))] = description
    def convert(asset):
        appid = str(asset.get("appid") or "")
        classid = str(asset.get("classid") or "")
        instanceid = str(asset.get("instanceid") or "0")
        description = descriptions.get((appid,classid,instanceid)) or descriptions.get((appid,classid,"0")) or {}
        item_type = str(description.get("type") or "")
        return {
            "name":str(description.get("market_hash_name") or description.get("name") or asset.get("market_hash_name") or asset.get("name") or "Предмет"),
            "icon":normalize_market_icon_url(description.get("icon_url_large") or description.get("icon_url") or ""),
            "amount":confirmation_item_amount(asset.get("amount")),"assetid":str(asset.get("assetid") or asset.get("id") or ""),
            "appid":appid,"contextid":str(asset.get("contextid") or ""),"classid":classid,"instanceid":instanceid,
            "type":item_type,"rarity":confirmation_item_rarity(item_type)
        }
    outgoing = [convert(asset) for asset in offer.get("items_to_give") or [] if isinstance(asset,dict)]
    incoming = [convert(asset) for asset in offer.get("items_to_receive") or [] if isinstance(asset,dict)]
    return {
        "avatar":"","outgoing_items":outgoing,"incoming_items":incoming,"item_images":outgoing+incoming,
        "assetids":[item["assetid"] for item in outgoing+incoming if item.get("assetid")],
        "incoming_only":bool(incoming and not outgoing),"outgoing_only":bool(outgoing and not incoming)
    }


def steam_community_cookie_opener(cookies):
    """Keep Set-Cookie updates during redirects instead of looping with a static header."""
    import http.cookiejar
    jar = http.cookiejar.CookieJar()
    values = list(cookies or [])+["Steam_Language=english"]
    seen = set()
    for pair in values:
        name_value = str(pair).split(";",1)[0].strip()
        if "=" not in name_value:
            continue
        name,value = name_value.split("=",1)
        if name in seen:
            continue
        seen.add(name)
        jar.set_cookie(http.cookiejar.Cookie(
            version=0,name=name,value=value,port=None,port_specified=False,
            domain=".steamcommunity.com",domain_specified=True,domain_initial_dot=True,
            path="/",path_specified=True,secure=True,expires=None,discard=True,
            comment=None,comment_url=None,rest={},rfc2109=False
        ))
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


TRADE_OFFER_LIST_CACHE = {}
TRADE_OFFER_LIST_CACHE_LOCK = threading.Lock()


def fetch_tradeoffer_listing_html(login,path,cookies):
    """Load a sent/received offers list once and share it between confirmations."""
    key = (str(login),str(path))
    now = time.time()
    with TRADE_OFFER_LIST_CACHE_LOCK:
        cached = TRADE_OFFER_LIST_CACHE.get(key) or {}
        if cached and now-float(cached.get("at") or 0) < 30:
            return str(cached.get("html") or "")
        headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Accept":"text/html,application/xhtml+xml","Accept-Language":"en-US,en;q=0.9",
            "Referer":"https://steamcommunity.com/tradeoffers/"
        }
        page_html = ""
        try:
            req = urllib.request.Request("https://steamcommunity.com"+path,headers=headers)
            with steam_community_cookie_opener(cookies).open(req,timeout=8) as response:
                final_url = str(response.geturl() or "")
                if "/login/" not in final_url:
                    page_html = response.read().decode("utf-8",errors="replace")
        except Exception as exc:
            log_event("Не удалось открыть список трейдов "+path+": "+str(exc),"WARNING",login)
        TRADE_OFFER_LIST_CACHE[key] = {"at":now,"html":page_html}
        return page_html


def tradeoffer_listing_chunk(page_html,tradeofferid):
    """Cut exactly one offer card from a page that may contain many offers."""
    source = str(page_html or "")
    target = re.search(r"<div\b[^>]*\bid\s*=\s*([\"'])tradeofferid_"+re.escape(str(tradeofferid))+r"\1[^>]*>",source,re.I)
    if not target:
        return ""
    next_offer = re.search(r"<div\b[^>]*\bclass\s*=\s*([\"'])[^\"']*\btradeoffer\b[^\"']*\1[^>]*>",source[target.end():],re.I)
    end = target.end()+next_offer.start() if next_offer else len(source)
    return source[target.start():end]


def fetch_tradeoffer_listing_details(login,tradeofferid,cookies):
    """Read a pending offer directly from Steam's sent/received trade history."""
    for path in ("/tradeoffers/sent/","/tradeoffers/"):
        page_html = fetch_tradeoffer_listing_html(login,path,cookies)
        chunk = tradeoffer_listing_chunk(page_html,tradeofferid)
        if not chunk:
            continue
        details = parse_tradeoffer_page_html(chunk)
        if details.get("outgoing_items") or details.get("incoming_items"):
            return details
    return {}


def fetch_tradeoffer_confirmation_details(login,tradeofferid,cookies=None):
    """Load exact offer assets with a redirect-aware authenticated web session."""
    tradeofferid = str(tradeofferid or "")
    if not tradeofferid.isdigit():
        return {}
    cookies = cookies or load_steam_web_cookies(login)
    if not cookies:
        return {}
    api_details = fetch_tradeoffer_api_details(tradeofferid)
    if api_details.get("outgoing_items") or api_details.get("incoming_items"):
        return api_details
    listing_details = fetch_tradeoffer_listing_details(login,tradeofferid,cookies)
    if listing_details.get("outgoing_items") or listing_details.get("incoming_items"):
        return listing_details
    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept":"text/html,application/xhtml+xml",
        "Accept-Language":"en-US,en;q=0.9",
        "Referer":"https://steamcommunity.com/tradeoffers/"
    }
    try:
        url = "https://steamcommunity.com/tradeoffer/"+tradeofferid+"/"
        req = urllib.request.Request(url,headers=headers)
        opener = steam_community_cookie_opener(cookies)
        with opener.open(req,timeout=10) as response:
            final_url = str(response.geturl() or "")
            page_html = response.read().decode("utf-8",errors="replace")
        if "/login/" in final_url or "g_rgCurrentTradeStatus" not in page_html:
            log_event("Steam не открыл состав trade offer "+tradeofferid+": требуется обновить web-авторизацию","WARNING",login)
            return {}
        details = parse_tradeoffer_page_html(page_html)
        if details.get("outgoing_items") or details.get("incoming_items"):
            return enrich_tradeoffer_from_inventories(login,tradeofferid,cookies,page_html,details)
    except Exception as exc:
        log_event("Не удалось загрузить состав trade offer "+tradeofferid+": "+str(exc),"WARNING",login)
    return {}


def fetch_account_confirmations(login, with_details=True):
    ma = find_mafile_data(login)
    if not ma or not ma.get("identity_secret"):
        return {"ok":False,"message":"В maFile не найден identity_secret."}, 404
    # Prefer the latest webSession saved by authorization. Older maFile cookies
    # can still open mobileconf while causing a login redirect on tradeoffer.
    cookies = load_steam_web_cookies(login)
    if not cookies and ma.get("steam_login_secure") and ma.get("session_id"):
        cookies = ["steamLoginSecure="+ma["steam_login_secure"],"sessionid="+ma["session_id"],"steamid="+str(ma["steamid"])]
    if not cookies:
        return {"ok":False,"message":"В maFile нет активной Session. Авторизуйте аккаунт."}, 409
    timestamp = int(time.time())
    query = steam_confirmation_query(ma["steamid"],steam_device_id(ma["steamid"],ma.get("device_id","")),ma["identity_secret"],"conf",timestamp)
    headers = {"Cookie":steam_cookie_header(cookies),"User-Agent":"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36","Accept":"application/json","X-Requested-With":"com.valvesoftware.android.steam.community","Referer":"https://steamcommunity.com/mobileconf/conf"}
    try:
        req = urllib.request.Request("https://steamcommunity.com/mobileconf/getlist?"+urllib.parse.urlencode(query),headers=headers)
        with urllib.request.urlopen(req,timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return {"ok":False,"message":"Не удалось получить подтверждения: "+str(exc)},502
    if not isinstance(payload,dict) or payload.get("success") is not True:
        detail = str((payload or {}).get("message") or (payload or {}).get("detail") or "Сессия истекла") if isinstance(payload,dict) else "Некорректный ответ Steam"
        return {"ok":False,"message":detail},409
    result = []
    for item in payload.get("conf") or []:
        if not isinstance(item,dict):
            continue
        try:
            kind = int(item.get("type") or 0)
        except (TypeError,ValueError):
            kind = 0
        if kind not in (2,3,12):
            continue
        summary = item.get("summary") or []
        if not isinstance(summary,list):
            summary = [str(summary)] if summary else []
        items = [str(v).strip() for v in summary if str(v).strip()]
        icon = str(item.get("icon") or "").strip()
        if icon.startswith("//"):
            icon = "https:"+icon
        item_images = []
        if kind in (3,12) and icon.startswith(("https://","http://")):
            item_images.append({"name":items[0] if items else "Предмет","icon":icon})
        result.append({
            "id":str(item.get("id") or ""),"key":str(item.get("nonce") or ""),
            "kind":"trade" if kind==2 else "market","confirmation_type":kind,
            "type_name":str(item.get("type_name") or ("Trade Offer" if kind==2 else ("Buy Order" if kind==12 else "Market Listing"))),
            "recipient":str(item.get("headline") or "Steam"),"items":items,"items_count":len(items),
            "created":int(item.get("creation_time") or 0),"creator_id":str(item.get("creator_id") or ""),"icon":icon,
            "avatar":"","item_images":item_images,"outgoing_items":[],"incoming_items":[],
            "incoming_only":False,"outgoing_only":False,"details_loaded":False
        })

    def complete_entry(entry):
        kind = int(entry.get("confirmation_type") or 0)
        items = list(entry.get("items") or [])
        if with_details:
            if kind == 2:
                # Pending offers already contain the authoritative asset lists.
                # Try sent/received history before asking mobileconf for details.
                offer_details = fetch_tradeoffer_confirmation_details(login,entry.get("creator_id"),cookies)
                if offer_details:
                    merge_tradeoffer_confirmation_details(entry,offer_details)
                    entry["details_loaded"] = True
                    enrich_confirmation_items_from_itemclass(login,entry,cookies)
                if confirmation_trade_entry_needs_offer(entry):
                    details = fetch_confirmation_details(login,entry["id"],ma,cookies)
                    if details:
                        merge_tradeoffer_confirmation_details(entry,details)
                        entry["details_loaded"] = True
                        enrich_confirmation_items_from_itemclass(login,entry,cookies)
            else:
                market_needs_details = kind in (3,12) and (
                    not entry.get("item_images") or not any(CONFIRMATION_WEAR_RE.search(str(name)) for name in items)
                )
                if market_needs_details:
                    details = fetch_confirmation_details(login,entry["id"],ma,cookies)
                    if details:
                        entry.update({key:details.get(key) for key in ("avatar","item_images","outgoing_items","incoming_items","incoming_only","outgoing_only")})
                        entry["details_loaded"] = True
        if kind == 2 and not entry.get("outgoing_items") and not entry.get("incoming_items"):
            summary_outgoing,summary_incoming = confirmation_trade_summary_sides(items)
            if summary_outgoing or summary_incoming:
                unclassified = list(entry.get("item_images") or [])
                for target in summary_outgoing+summary_incoming:
                    matches = [image for image in unclassified if confirmation_item_base_name(image.get("name")) == confirmation_item_base_name(target.get("name"))]
                    if len(matches) == 1:
                        target["icon"] = str(matches[0].get("icon") or "")
                entry["outgoing_items"] = summary_outgoing
                entry["incoming_items"] = summary_incoming
                entry["item_images"] = summary_outgoing+summary_incoming
                entry["incoming_only"] = bool(summary_incoming and not summary_outgoing)
                entry["outgoing_only"] = bool(summary_outgoing and not summary_incoming)
        if kind == 2:
            trade_items = list(entry.get("outgoing_items") or [])+list(entry.get("incoming_items") or [])
            if trade_items:
                entry["items_count"] = sum(confirmation_item_amount(image.get("amount")) for image in trade_items)
            unresolved_names = sum(
                confirmation_item_amount(image.get("amount")) for image in trade_items
                if not str(image.get("name") or "").strip() or str(image.get("name") or "") == "Предмет" or confirmation_item_count_summary(image.get("name"))
            )
            if not trade_items or unresolved_names:
                entry["details_error"] = "Steam не вернул состав трейда" if not trade_items else "Steam не вернул точные названия для "+str(unresolved_names)+" предметов"
                log_event(str(entry["details_error"])+", трейд "+str(entry.get("creator_id") or ""),"WARNING",login)
        enrich_confirmation_item_names(entry,items)
        if with_details and kind in (2,3,12):
            fill_missing_confirmation_item_icons(login,entry)
        return entry

    if with_details and result:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(4,len(result))) as pool:
            result = list(pool.map(complete_entry,result))
    else:
        result = [complete_entry(entry) for entry in result]
    return {"ok":True,"login":login,"confirmations":result,"count":len(result)},200


def confirmation_result_message(action,trade_count,market_count,other_count=0):
    """Describe accepted/cancelled operations by their actual Steam types."""
    trade_count = int(trade_count or 0)
    market_count = int(market_count or 0)
    other_count = int(other_count or 0)
    total = trade_count+market_count+other_count
    accepted = action == "accept"
    if total == 1:
        if market_count:
            return "Операция Market принята" if accepted else "Операция Market отменена"
        if trade_count:
            return "Трейд подтверждён" if accepted else "Трейд отменён"
        return "Операция принята" if accepted else "Операция отменена"
    if market_count and not trade_count and not other_count:
        return ("Принято" if accepted else "Отменено")+" операций Market: "+str(market_count)
    if trade_count and not market_count and not other_count:
        return ("Подтверждено" if accepted else "Отменено")+" трейдов: "+str(trade_count)
    parts = []
    if market_count:
        parts.append("Market: "+str(market_count))
    if trade_count:
        parts.append("трейдов: "+str(trade_count))
    if other_count:
        parts.append("других: "+str(other_count))
    return ("Принято" if accepted else "Отменено")+" операций: "+str(total)+" ("+", ".join(parts)+")"


def process_trade_confirmations(login, action, not_before=0, confirmation_ids=None):
    ma = find_mafile_data(login)
    if not ma or not ma.get("identity_secret"):
        return {"ok": False, "message": "В maFile не найден identity_secret."}, 404
    # This maFile format already contains a ready web session. Using it avoids
    # a fresh login and makes confirmation/cancellation nearly immediate.
    cookies = []
    if ma.get("steam_login_secure") and ma.get("session_id"):
        cookies = [
            "steamLoginSecure=" + ma["steam_login_secure"],
            "sessionid=" + ma["session_id"],
            "steamid=" + str(ma["steamid"]),
        ]
    if not cookies:
        cookies = load_steam_web_cookies(login)
    error = ""
    if not cookies:
        cookies, error = refresh_steam_web_cookies_for_trade(login)
    if not cookies:
        return {"ok": False, "message": error or "Нет Steam web-сессии."}, 409
    cookie_header = steam_cookie_header(cookies)
    session_id = str(ma.get("session_id") or "")
    for pair in cookie_header.split("; "):
        if pair.startswith("sessionid="):
            session_id = pair.split("=", 1)[1]
            break
    if not session_id:
        return {"ok": False, "message": "В Steam web-сессии отсутствует sessionid. Обновите авторизацию."}, 409

    timestamp = int(time.time())
    query = steam_confirmation_query(ma["steamid"], steam_device_id(ma["steamid"], ma.get("device_id", "")), ma["identity_secret"], "conf", timestamp)
    url = "https://steamcommunity.com/mobileconf/getlist?" + urllib.parse.urlencode(query)
    headers = {
        "Cookie": cookie_header,
        "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "com.valvesoftware.android.steam.community",
        "Referer": "https://steamcommunity.com/mobileconf/conf",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=25) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return {"ok": False, "message": "Steam Confirmations HTTP " + str(exc.code)}, 502
    except Exception as exc:
        return {"ok": False, "message": "Не удалось получить подтверждения: " + str(exc)}, 502
    if isinstance(payload, dict) and payload.get("needauth"):
        # The saved maFile session may be expired. Refresh only in that case.
        fresh_cookies, refresh_error = refresh_steam_web_cookies_for_trade(login)
        if not fresh_cookies:
            return {"ok":False,"message":"Сессия maFile истекла: "+refresh_error}, 409
        cookie_header = steam_cookie_header(fresh_cookies)
        headers["Cookie"] = cookie_header
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=25) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            return {"ok":False,"message":"Не удалось обновить подтверждения: "+str(exc)}, 502
    if not isinstance(payload, dict) or payload.get("success") is not True:
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("message") or payload.get("detail") or "").strip()
        return {"ok": False, "message": "Steam отклонил запрос подтверждений" + (": "+detail if detail else ". Проверьте сессию maFile.")}, 409

    confirmations = payload.get("conf") or payload.get("confirmations") or []
    if not isinstance(confirmations, list):
        confirmations = []
    # Type 2 is a trade-offer confirmation. Do not touch unrelated market/generic actions.
    if confirmation_ids:
        wanted_ids = {str(value) for value in confirmation_ids}
        trades = [item for item in confirmations if isinstance(item,dict) and str(item.get("id") or "") in wanted_ids]
    else:
        trades = [item for item in confirmations if isinstance(item, dict) and int(item.get("type", 2) or 2) == 2]
    if not_before:
        # Auto mode starts at a fixed activation timestamp. Older pending trades
        # remain untouched; only confirmations created afterwards are accepted.
        trades = [item for item in trades if float(item.get("creation_time") or 0) >= float(not_before)]
    if not trades:
        empty_label = "операций" if confirmation_ids else "трейдов"
        return {"ok": True, "count": 0, "message": "Нет "+empty_label+", ожидающих действия: " + login}, 200

    # An operation needs its own signature: tag=allow for accepting and
    # tag=cancel for rejecting. The conf signature used to obtain the list
    # cannot authorize an operation. Steam expects op=allow (not accept).
    operation_tag = "allow" if action == "accept" else "cancel"
    operation_time = int(time.time())
    operation_query = steam_confirmation_query(
        ma["steamid"],
        steam_device_id(ma["steamid"], ma.get("device_id", "")),
        ma["identity_secret"],
        operation_tag,
        operation_time,
    )
    selected = []
    trade_count = 0
    market_count = 0
    other_count = 0
    for item in trades:
        confirmation_id = str(item.get("id") or item.get("confid") or "")
        confirmation_key = str(item.get("nonce") or item.get("key") or "")
        if confirmation_id and confirmation_key:
            selected.append((confirmation_id, confirmation_key))
            try:
                confirmation_type = int(item.get("type") or 0)
            except (TypeError,ValueError):
                confirmation_type = 0
            if confirmation_type == 2:
                trade_count += 1
            elif confirmation_type in (3,12):
                market_count += 1
            else:
                other_count += 1
    if not selected:
        return {"ok": False, "message": "Steam не вернул ключи подтверждений."}, 502
    form = [("op", operation_tag)] + list(operation_query.items())
    for confirmation_id, confirmation_key in selected:
        form.extend([("cid[]", confirmation_id), ("ck[]", confirmation_key)])
    request_body = urllib.parse.urlencode(form).encode("utf-8")
    post_headers = dict(headers)
    post_headers.update({"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "https://steamcommunity.com"})
    try:
        req = urllib.request.Request("https://steamcommunity.com/mobileconf/multiajaxop", data=request_body, headers=post_headers, method="POST")
        with urllib.request.urlopen(req, timeout=25) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return {"ok": False, "message": "Steam operation HTTP " + str(exc.code)}, 502
    except Exception as exc:
        return {"ok": False, "message": "Не удалось выполнить операцию: " + str(exc)}, 502
    if not isinstance(result, dict) or result.get("success") is not True:
        detail = ""
        if isinstance(result, dict):
            detail = str(result.get("message") or result.get("detail") or "").strip()
        if result is not None and isinstance(result, dict) and result.get("needauth"):
            detail = "Сессия Steam истекла. Нажмите «Авторизовать» и повторите."
        return {"ok": False, "message": "Steam отклонил операцию" + (": " + detail if detail else ".")}, 409
    count = len(selected)
    message = confirmation_result_message(action,trade_count,market_count,other_count)
    log_event(message,"INFO",login)
    return {"ok":True,"count":count,"trade_count":trade_count,"market_count":market_count,"message":message},200


@app.route("/api/confirmations/<path:login>", methods=["GET", "POST"])
def api_trade_confirmations(login):
    login = str(login or "").strip()
    if request.method == "GET":
        result, status = fetch_account_confirmations(login)
        return jsonify(result), status
    data = request.get_json(silent=True) or {}
    action = str(data.get("action") or "").strip()
    if action not in ("accept", "cancel"):
        return jsonify({"ok": False, "message": "Неизвестное действие."}), 400
    if not find_account_credentials(login):
        return jsonify({"ok": False, "message": "Аккаунт не найден."}), 404
    ids = data.get("confirmation_ids") if isinstance(data.get("confirmation_ids"),list) else None
    result, status = process_trade_confirmations(login, action, confirmation_ids=ids)
    return jsonify(result), status


@app.route("/api/accounts/<path:login>", methods=["DELETE"])
def api_delete_account(login):
    wanted = str(login or "").strip().casefold()
    if not wanted or not LOGPASS_FILE.exists():
        return jsonify({"ok": False, "message": "Аккаунт или logpass.txt не найден."}), 404
    try:
        raw = None
        for encoding in ("utf-8-sig", "utf-8", "cp1251"):
            try:
                raw = LOGPASS_FILE.read_text(encoding=encoding)
                break
            except UnicodeDecodeError:
                continue
        if raw is None:
            return jsonify({"ok": False, "message": "Не удалось прочитать logpass.txt."}), 500
        kept, removed_lines = [], []
        for line in raw.splitlines(keepends=True):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and ":" in stripped:
                name = stripped.split(":", 1)[0].strip()
                if name.casefold() == wanted:
                    removed_lines.append(stripped)
                    continue
            kept.append(line)
        if not removed_lines:
            return jsonify({"ok": False, "message": "Аккаунт не найден в logpass.txt."}), 404
        # Archive the complete original login:password line before removing it.
        # Do not include maFile secrets or other account data in removed.txt.
        separator = ""
        if REMOVED_FILE.exists() and REMOVED_FILE.stat().st_size:
            with REMOVED_FILE.open("rb") as archive:
                archive.seek(-1, 2)
                if archive.read(1) not in (b"\n", b"\r"):
                    separator = "\n"
        with REMOVED_FILE.open("a", encoding="utf-8", newline="\n") as archive:
            archive.write(separator + "\n".join(removed_lines) + "\n")
        tmp = LOGPASS_FILE.with_suffix(".tmp")
        tmp.write_text("".join(kept), encoding="utf-8")
        tmp.replace(LOGPASS_FILE)
        with AUTH_LOCK:
            AUTH_STATE.pop(login, None)
        with MARKED_LOCK:
            MARKED_ACCOUNTS.discard(login)
        save_account_cache()
        save_marked_accounts()
        log_event("Аккаунт удалён из панели и сохранён в removed.txt", "INFO", login)
        accounts, _, _ = read_logpass(force=True)
        return jsonify({"ok": True, "accounts": accounts})
    except OSError as exc:
        return jsonify({"ok": False, "message": "Ошибка удаления: " + str(exc)}), 500


def load_steam_api_key():
    try:
        if not STEAM_API_KEY_FILE.exists():
            return ""
        return _dpapi_unprotect(STEAM_API_KEY_FILE.read_bytes()).decode("utf-8").strip()
    except Exception:
        return ""


def save_steam_api_key(key):
    value = str(key or "").strip()
    if not re.fullmatch(r"[0-9A-Fa-f]{32}", value):
        return False
    try:
        encrypted = _dpapi_protect(value.encode("ascii"))
        tmp = STEAM_API_KEY_FILE.with_suffix(".tmp")
        tmp.write_bytes(encrypted)
        tmp.replace(STEAM_API_KEY_FILE)
        return True
    except Exception:
        return False


@app.route("/api/bans/key", methods=["POST"])
def api_save_ban_key():
    data = request.get_json(silent=True) or {}
    if not save_steam_api_key(data.get("key", "")):
        return jsonify({"ok":False,"message":"Некорректный Steam Web API ключ: нужны 32 шестнадцатеричных символа."}), 400
    return jsonify({"ok":True})


def fetch_account_limitations(login, steamid):
    result = {"limited_account":False,"trade_hold":False,"market_hold":False}
    try:
        req = urllib.request.Request("https://steamcommunity.com/profiles/"+steamid+"/?xml=1",headers={"User-Agent":"AccountManager/1.0"})
        with urllib.request.urlopen(req,timeout=10) as response:
            xml = response.read().decode("utf-8",errors="replace")
        limited = re.search(r"<isLimitedAccount>\s*([01])\s*</isLimitedAccount>",xml,re.I)
        result["limited_account"] = bool(limited and limited.group(1)=="1")
    except Exception:
        pass
    ma = find_mafile_data(login) or {}
    if ma.get("steam_login_secure"):
        cookies = ["steamLoginSecure="+ma["steam_login_secure"]]
        if ma.get("session_id"): cookies.append("sessionid="+ma["session_id"])
        try:
            req = urllib.request.Request("https://steamcommunity.com/profiles/"+steamid+"/tradeoffers/?l=english",headers={"Cookie":steam_cookie_header(cookies),"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req,timeout=10) as response:
                html = response.read().decode("utf-8",errors="replace").lower()
            result["trade_hold"] = any(x in html for x in ("trade hold","trade holds","escrow period"))
            result["market_hold"] = "market hold" in html or "market restriction" in html
        except Exception:
            pass
    return result


@app.route("/api/bans", methods=["POST"])
def api_check_bans():
    data = request.get_json(silent=True) or {}
    requested = data.get("logins", [])
    if not isinstance(requested, list):
        return jsonify({"ok":False,"message":"Некорректный список аккаунтов."}), 400
    logins = list(dict.fromkeys(str(v).strip() for v in requested if str(v).strip()))
    if not logins:
        return jsonify({"ok":False,"message":"Сначала выберите аккаунты."}), 400
    key = load_steam_api_key()
    if not key:
        return jsonify({"ok":False,"key_required":True,"message":"Для проверки нужен Steam Web API ключ."}), 428

    id_to_login = {}
    skipped = []
    for login in logins:
        ma = find_mafile_data(login)
        steamid = str((ma or {}).get("steamid") or "").strip()
        if re.fullmatch(r"\d{17}", steamid):
            id_to_login[steamid] = login
        else:
            skipped.append(login)
    if not id_to_login:
        return jsonify({"ok":False,"message":"Не найдены SteamID64 в maFiles выбранных аккаунтов."}), 400

    players = []
    ids = list(id_to_login)
    try:
        for offset in range(0, len(ids), 100):
            query = urllib.parse.urlencode({"key":key,"steamids":",".join(ids[offset:offset+100])})
            req = urllib.request.Request(
                "https://api.steampowered.com/ISteamUser/GetPlayerBans/v1/?" + query,
                headers={"User-Agent":"AccountManager/1.0","Accept":"application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
            batch = payload.get("players") if isinstance(payload, dict) else None
            if not isinstance(batch, list):
                raise RuntimeError("Steam вернул пустой ответ GetPlayerBans")
            players.extend(batch)
    except urllib.error.HTTPError as exc:
        message = "Steam Web API HTTP " + str(exc.code)
        if exc.code in (401, 403):
            message += ". Проверьте Steam Web API ключ."
        return jsonify({"ok":False,"message":message}), 502
    except Exception as exc:
        return jsonify({"ok":False,"message":"Ошибка проверки банов: " + str(exc)}), 502

    valid = [p for p in players if isinstance(p, dict) and str(p.get("SteamId") or "") in id_to_login]
    checked_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        limitation_values = list(pool.map(lambda player: fetch_account_limitations(id_to_login[str(player.get("SteamId"))],str(player.get("SteamId"))),valid))
    limitations_by_id = {str(player.get("SteamId")):limitations for player,limitations in zip(valid,limitation_values)}
    for player in valid:
        steamid = str(player.get("SteamId") or "")
        account_login = id_to_login[steamid]
        log_event("Проверка банов: Community="+str(bool(player.get("CommunityBanned")))+", VAC="+str(bool(player.get("VACBanned")))+", Game="+str(int(player.get("NumberOfGameBans") or 0)), "INFO", account_login)
        with AUTH_LOCK:
            AUTH_STATE.setdefault(account_login, {}).update({
                "community_banned":bool(player.get("CommunityBanned")),
                "vac_banned":bool(player.get("VACBanned")),
                "game_banned":int(player.get("NumberOfGameBans") or 0) > 0,
                "trade_banned":str(player.get("EconomyBanned") or "none").lower() not in ("","none","false"),
                **limitations_by_id.get(str(player.get("SteamId")),{}),
                "bans_updated":checked_at,
            })
    save_account_cache()
    community = sum(1 for p in valid if bool(p.get("CommunityBanned")))
    vac = sum(1 for p in valid if bool(p.get("VACBanned")))
    game = sum(1 for p in valid if int(p.get("NumberOfGameBans") or 0) > 0)
    trade = sum(1 for p in valid if str(p.get("EconomyBanned") or "none").lower() not in ("","none","false"))
    limited = sum(1 for p in valid if limitations_by_id.get(str(p.get("SteamId")),{}).get("limited_account"))
    holds = sum(1 for p in valid if limitations_by_id.get(str(p.get("SteamId")),{}).get("trade_hold") or limitations_by_id.get(str(p.get("SteamId")),{}).get("market_hold"))
    checked = len(valid)
    failed = len(logins) - checked
    log_event("Проверка банов: checked="+str(checked)+", community="+str(community)+", vac="+str(vac)+", game="+str(game))
    return jsonify({
        "ok":True,"checked":checked,"community_banned":community,
        "vac_banned":vac,"game_banned":game,"trade_banned":trade,"limited_account":limited,
        "trade_market_hold":holds,"failed":failed,"skipped":len(skipped)
    })


@app.route("/api/levels", methods=["POST"])
def api_get_levels():
    data = request.get_json(silent=True) or {}
    requested = data.get("logins", [])
    if not isinstance(requested, list):
        return jsonify({"ok": False, "message": "Некорректный список аккаунтов."}), 400
    logins = list(dict.fromkeys(str(value).strip() for value in requested if str(value).strip()))
    if not logins:
        return jsonify({"ok": False, "message": "Сначала выберите аккаунт."}), 400
    accounts, _, exists = read_logpass()
    if not exists:
        return jsonify({"ok": False, "message": "logpass.txt не найден."}), 404
    existing = {account["login"] for account in accounts}
    unknown = next((login for login in logins if login not in existing), None)
    if unknown:
        return jsonify({"ok": False, "message": "Аккаунт не найден: " + unknown}), 404
    started, busy = [], []
    for login in logins:
        if start_authorization(login):
            started.append(login)
        else:
            busy.append(login)
    if not started and busy:
        return jsonify({"ok": False, "message": "Выбранные аккаунты уже авторизуются.", "started": [], "busy": busy}), 409
    return jsonify({"ok": True, "started": started, "busy": busy})


@app.route("/api/accounts/mark", methods=["POST"])
def api_mark_accounts():
    data = request.get_json(silent=True) or {}
    requested = data.get("logins", [])
    marked = data.get("marked", True)
    if not isinstance(requested, list) or not isinstance(marked, bool):
        return jsonify({"ok": False, "message": "Некорректные параметры отметки."}), 400
    logins = list(dict.fromkeys(str(value).strip() for value in requested if str(value).strip()))
    if not logins:
        return jsonify({"ok": False, "message": "Не выбран ни один аккаунт."}), 400
    accounts, _, exists = read_logpass()
    if not exists:
        return jsonify({"ok": False, "message": "logpass.txt не найден."}), 404
    existing = {account["login"] for account in accounts}
    unknown = [login for login in logins if login not in existing]
    if unknown:
        return jsonify({"ok": False, "message": "Аккаунт не найден: " + unknown[0]}), 404
    with MARKED_LOCK:
        if marked:
            MARKED_ACCOUNTS.update(logins)
        else:
            MARKED_ACCOUNTS.difference_update(logins)
    if not save_marked_accounts():
        return jsonify({"ok": False, "message": "Не удалось записать marked_accounts.json."}), 500
    log_event(("Отмечены" if marked else "Снята отметка") + ": " + ", ".join(logins))
    accounts, _, _ = read_logpass()
    return jsonify({"ok": True, "marked": marked, "logins": logins, "accounts": accounts})


@app.route("/api/accounts/<path:login>/status")
def api_account_status(login):
    """Return one account during authorization without building the full list."""
    login = str(login or "").strip()
    logins,_,exists = _read_logpass_entries()
    if not exists or login not in logins:
        return jsonify({"ok":False,"message":"Аккаунт не найден."}),404
    return jsonify({"ok":True,"account":build_account_snapshot(login,logins.index(login)+1)})


@app.route("/api/accounts/runtime", methods=["POST"])
def api_accounts_runtime():
    """Return only live process states without reading accounts or saved sessions."""
    data = request.get_json(silent=True) or {}
    requested = data.get("logins", [])
    if not isinstance(requested, list):
        return jsonify({"ok": False, "message": "Некорректный список аккаунтов."}), 400
    logins = list(dict.fromkeys(
        str(value).strip() for value in requested if str(value).strip()
    ))
    runtime = {}
    for login in logins:
        runtime[login] = {
            "steam_running": steam_process_alive(login),
            "booster_status": booster_status(login).get("status", "idle"),
            "farm_status": farm_status(login).get("status", "idle")
        }
    return jsonify({"ok": True, "runtime": runtime})


@app.route("/api/accounts")
def api_accounts():
    force = str(request.args.get("refresh") or "").lower() in ("1","true","yes")
    accounts, invalid, exists = read_logpass(force=force)
    return jsonify({
        "accounts": accounts,
        "count": len(accounts),
        "invalid_lines": invalid,
        "file_exists": exists
    })


def find_free_port(start=5000, limit=50):
    import socket
    for port in range(start, start + limit):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            pass
        finally:
            sock.close()
    raise RuntimeError("Не удалось найти свободный локальный порт")


def run_server(port):
    app.run(
        host="127.0.0.1",
        port=port,
        debug=False,
        use_reloader=False,
        threaded=True
    )


def load_window_position():
    try:
        value = json.loads(WINDOW_POSITION_FILE.read_text(encoding="utf-8"))
        x, y = int(value["x"]), int(value["y"])
        # Validate against the full virtual desktop, including monitors left of
        # or above the primary display (their coordinates can be negative).
        user32 = ctypes.windll.user32
        left = int(user32.GetSystemMetrics(76))
        top = int(user32.GetSystemMetrics(77))
        width = int(user32.GetSystemMetrics(78))
        height = int(user32.GetSystemMetrics(79))
        right, bottom = left + width, top + height
        visible = x + 1280 >= left + 180 and x <= right - 180 and y + 720 >= top + 80 and y <= bottom - 80
        return (x,y) if visible else None
    except Exception:
        return None


def save_window_position(x, y):
    try:
        _write_json_object(WINDOW_POSITION_FILE,{"x":int(x),"y":int(y)})
    except Exception:
        pass


class DesktopBridge:
    """Small native bridge for desktop-only folder selection."""

    def choose_steam_path(self):
        try:
            import webview
            windows = list(getattr(webview,"windows",[]) or [])
            if not windows:
                return {"ok":False,"message":"Окно менеджера недоступно"}
            current = _steam_path()
            directory = str(current.parent) if current.parent.is_dir() else ""
            selected = windows[0].create_file_dialog(
                webview.FOLDER_DIALOG,
                directory=directory,
                allow_multiple=False
            )
            if not selected:
                return {"ok":True,"cancelled":True}
            value = selected[0] if isinstance(selected,(list,tuple)) else selected
            path = validate_steam_path(Path(value) / "steam.exe")
            return {"ok":True,"cancelled":False,"steam_path":str(path)}
        except ValueError as exc:
            return {"ok":False,"message":"В выбранной папке не найден steam.exe. Выберите каталог установки Steam."}
        except Exception as exc:
            return {"ok":False,"message":"Не удалось выбрать папку Steam: "+str(exc)}


if __name__ == "__main__":
    WEBVIEW_DEBUG_PORT = find_free_port(9222, 150)
    os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        "--remote-debugging-port=" + str(WEBVIEW_DEBUG_PORT) + " --remote-allow-origins=*"
    )
    import webview
    # pywebview itself must enable this setting for EdgeChromium. Setting only
    # the WebView2 environment variable is not reliable across installations.
    webview.settings["REMOTE_DEBUGGING_PORT"] = WEBVIEW_DEBUG_PORT

    # Every app instance gets its own local port, so an old instance cannot
    # accidentally serve the new window.
    SERVER_PORT = find_free_port(5000, 50)
    SERVER_URL = f"http://127.0.0.1:{SERVER_PORT}"
    server = threading.Thread(target=run_server, args=(SERVER_PORT,), daemon=True)
    server.start()

    # Wait until this exact Flask instance responds.
    import urllib.request
    for _ in range(40):
        try:
            with urllib.request.urlopen(SERVER_URL + "/api/accounts", timeout=0.25) as response:
                if response.status == 200:
                    break
        except Exception:
            time.sleep(0.25)

    window_options = {
        "width":1280,
        "height":720,
        "min_size":(1280,720),
        "resizable":False,
        "fullscreen":False
    }
    saved_position = load_window_position()
    if saved_position:
        window_options["x"], window_options["y"] = saved_position
    if auto_session_status().get("enabled"):
        start_auto_session_reload()
    main_window = webview.create_window("GSM 1.0.2",SERVER_URL + "/",js_api=DesktopBridge(),**window_options)

    import atexit
    atexit.register(stop_all_activity_boosters)

    position_lock = threading.Lock()
    position_state = {"timer":None,"x":saved_position[0] if saved_position else None,"y":saved_position[1] if saved_position else None}

    def flush_window_position():
        with position_lock:
            timer = position_state.get("timer")
            if timer:
                timer.cancel()
            position_state["timer"] = None
            x, y = position_state.get("x"), position_state.get("y")
        if x is not None and y is not None:
            save_window_position(x,y)

    def window_moved(x, y):
        with position_lock:
            position_state["x"], position_state["y"] = int(x), int(y)
            timer = position_state.get("timer")
            if timer:
                timer.cancel()
            timer = threading.Timer(0.4,flush_window_position)
            timer.daemon = True
            position_state["timer"] = timer
            timer.start()

    def window_closed():
        flush_window_position()
        stop_all_activity_boosters()

    main_window.events.moved += window_moved
    main_window.events.closed += window_closed
    webview.start(gui="edgechromium")