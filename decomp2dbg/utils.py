from typing import Optional, Tuple, Any
import platform
import struct
from functools import lru_cache
import pathlib
import os

LEFT_ARROW                             = " \u2190 "
RIGHT_ARROW                            = " \u2192 "
DOWN_ARROW                             = "\u21b3"
HORIZONTAL_LINE                        = "\u2500"
VERTICAL_LINE                          = "\u2502"
CROSS                                  = "\u2718 "
TICK                                   = "\u2713 "
ANSI_SPLIT_RE                          = r"(\033\[[\d;]*m)"


class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal": "\033[0m",
        "gray": "\033[1;38;5;240m",
        "light_gray": "\033[0;37m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "pink": "\033[35m",
        "cyan": "\033[36m",
        "bold": "\033[1m",
        "underline": "\033[4m",
        "underline_off": "\033[24m",
        "highlight": "\033[3m",
        "highlight_off": "\033[23m",
        "blink": "\033[5m",
        "blink_off": "\033[25m",
    }

    @staticmethod
    def redify(msg: str) -> str:        return Color.colorify(msg, "red")
    @staticmethod
    def greenify(msg: str) -> str:      return Color.colorify(msg, "green")
    @staticmethod
    def blueify(msg: str) -> str:       return Color.colorify(msg, "blue")
    @staticmethod
    def yellowify(msg: str) -> str:     return Color.colorify(msg, "yellow")
    @staticmethod
    def grayify(msg: str) -> str:       return Color.colorify(msg, "gray")
    @staticmethod
    def light_grayify(msg: str) -> str: return Color.colorify(msg, "light_gray")
    @staticmethod
    def pinkify(msg: str) -> str:       return Color.colorify(msg, "pink")
    @staticmethod
    def cyanify(msg: str) -> str:       return Color.colorify(msg, "cyan")
    @staticmethod
    def boldify(msg: str) -> str:       return Color.colorify(msg, "bold")
    @staticmethod
    def underlinify(msg: str) -> str:   return Color.colorify(msg, "underline")
    @staticmethod
    def highlightify(msg: str) -> str:  return Color.colorify(msg, "highlight")
    @staticmethod
    def blinkify(msg: str) -> str:      return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text: str, attrs: str) -> str:
        """Color text according to the given attributes."""

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg:   msg.append(colors["highlight_off"])
        if colors["underline"] in msg:   msg.append(colors["underline_off"])
        if colors["blink"] in msg:       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)


def get_terminal_size() -> Tuple[int, int]:
    """Return the current terminal size."""
    if platform.system() == "Windows":
        from ctypes import windll, create_string_buffer
        hStdErr = -12
        herr = windll.kernel32.GetStdHandle(hStdErr)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(herr, csbi)
        if res:
            _, _, _, _, _, left, top, right, bottom, _, _ = struct.unpack("hhhhHhhhhhh", csbi.raw)
            tty_columns = right - left + 1
            tty_rows = bottom - top + 1
            return tty_rows, tty_columns
        else:
            return 600, 100
    else:
        import fcntl
        import termios
        try:
            tty_rows, tty_columns = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234"))
            return tty_rows, tty_columns
        except OSError:
            return 600, 100


def pprint(*args: str, end="\n", sep=" ", **kwargs: Any) -> None:
    """Wrapper around print(), using string buffering feature."""
    parts = args
    print(*parts, sep=sep, end=end, **kwargs)
    return


def titlify(text: str, color: Optional[str] = None, msg_color: Optional[str] = None) -> str:
    """Print a centered title."""
    cols = get_terminal_size()[1]
    nb = (cols - len(text) - 2) // 2
    if color is None:
        color = "gray"
    if msg_color is None:
        msg_color = "cyan"

    msg = [Color.colorify(f"{HORIZONTAL_LINE * nb} ", color),
           Color.colorify(text, msg_color),
           Color.colorify(f" {HORIZONTAL_LINE * nb}", color)]
    return "".join(msg)


def err(msg: str) -> None:
    pprint(f"{Color.colorify('[!]', 'bold red')} {msg}")


def warn(msg: str) -> None:
    pprint(f"{Color.colorify('[*]', 'bold yellow')} {msg}")


def ok(msg: str) -> None:
    pprint(f"{Color.colorify('[+]', 'bold green')} {msg}")


def info(msg: str) -> None:
    pprint(f"{Color.colorify('[+]', 'bold blue')} {msg}")


def gef_pystring(x: bytes) -> str:
    """Returns a sanitized version as string of the bytes list given in input."""
    res = str(x, encoding="utf-8")
    substs = [("\n", "\\n"), ("\r", "\\r"), ("\t", "\\t"), ("\v", "\\v"), ("\b", "\\b"), ]
    for x, y in substs: res = res.replace(x, y)
    return res