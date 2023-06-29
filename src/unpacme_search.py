import base64
import binascii

import ida_idaapi
import ida_kernwin
import idaapi
import ida_diskio
import ida_bytes
import idc
import ida_ua
import json
import logging
import requests
import keyring
from datetime import datetime
import webbrowser
import os

from PyQt5.QtCore import Qt, QByteArray
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QGridLayout, QFormLayout, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, QCheckBox, QFrame
from PyQt5.QtGui import QColor, QPixmap, QPainter, QIcon, QFontMetrics, QGuiApplication


logger = logging.getLogger("UnpacMeSearch")
logger.setLevel(logging.INFO)

UPMS_ICON_32_ENCODED = b'iVBORw0KGgoAAAANSUhEUgAAACAAAABICAYAAACX3ffDAAAKtmlDQ1BJQ0MgUHJvZmlsZQAASImVlwdUU+kSgP9700N' \
                    b'CC4QiJfTeWwApIbQASq82QhIglBATgoLYkMUVWFFERLAs6KqIgo0qNkSxLYoF7AuyiKjrYkFUVN4FDmF333nvnTfnTO' \
                    b'bL3Pnnn/nP/c+ZCwBZgy0UpsHyAKQLMkVhfl60mNg4Gm4YYIEKgIEy0GdzxEJGSEgQQGTW/l0+9gJoyt6xmMr178//q' \
                    b'yhweWIOAFAIwglcMScd4VOIfuQIRZkAoI4gfr0VmcIpvoWwkggpEOHfpzhphj9NccI0o0nTMRFhTIRpAOBJbLYoCQCS' \
                    b'OeKnZXGSkDykqR6sBVy+AOFchN3T0zO4CLcjbIzECBGeyk9P+EuepL/lTJDmZLOTpDzTy7TgvfliYRo7+/88jv8t6Wm' \
                    b'S2T0MESUli/zDEKuFnNn91IxAKQsSFgbPMp87HT/NyRL/yFnmiJlxs8xlewdK16YtDJrlRL4vS5onkxUxyzyxT/gsiz' \
                    b'LCpHslipiMWWaL5vaVpEZK/ck8ljR/TnJE9Cxn8aMWzrI4NTxwLoYp9YskYdL6eQI/r7l9faW9p4v/0i+fJV2bmRzhL' \
                    b'+2dPVc/T8CYyymOkdbG5Xn7zMVESuOFmV7SvYRpIdJ4Xpqf1C/OCpeuzUReyLm1IdIzTGEHhMwyCAEikAFowBvwgRgI' \
                    b'QRpgg2zkfwziQVZn8lZmTjXFzBBmi/hJyZk0BnLbeDSWgGNpTrO1trUDYOruzrwa76nTdxKiXpvzbagFwK11cnLy9Jw' \
                    b'vALlTx+MBIDbO+YyXACA/DMCVdo5ElDXjQ0/9YAARyAEloIZUrAeMgQWwBY7AFXgCHxAAgkEEiAVLAQckg3SklxUgF6' \
                    b'wHBaAIbAHbQSXYC/aBQ+AoOAGaQTu4AC6D6+AWuAcegX4wBF6BUfARTEAQhIPIEAVSg7QhA8gMsoXokDvkAwVBYVAsF' \
                    b'A8lQQJIAuVCG6AiqBSqhKqhWug41ApdgK5CPdADaAAagd5BX2AUTIKVYE3YELaC6TADDoQj4CVwErwczoHz4c1wBVwD' \
                    b'H4Gb4Avwdfge3A+/gsdQACWDoqJ0UBYoOoqJCkbFoRJRItQaVCGqHFWDqke1obpQd1D9qNeoz2gsmoKmoS3Qrmh/dCS' \
                    b'ag16OXoMuRleiD6Gb0J3oO+gB9Cj6O4aM0cCYYVwwLEwMJgmzAlOAKcccwDRiLmHuYYYwH7FYLBVrhHXC+mNjsSnYVd' \
                    b'hi7G5sA/Y8tgc7iB3D4XBqODOcGy4Yx8Zl4gpwO3FHcOdwt3FDuE94Gbw23hbvi4/DC/B5+HL8YfxZ/G38MH6CIE8wI' \
                    b'LgQgglcQjahhLCf0Ea4SRgiTBAViEZEN2IEMYW4nlhBrCdeIj4mvpeRkdGVcZYJleHLrJOpkDkmc0VmQOYzSZFkSmKS' \
                    b'FpMkpM2kg6TzpAek92Qy2ZDsSY4jZ5I3k2vJF8lPyZ9kKbKWsixZruxa2SrZJtnbsm/kCHIGcgy5pXI5cuVyJ+Vuyr2' \
                    b'WJ8gbyjPl2fJr5KvkW+X75McUKAo2CsEK6QrFCocVriq8UMQpGir6KHIV8xX3KV5UHKSgKHoUJoVD2UDZT7lEGVLCKh' \
                    b'kpsZRSlIqUjip1K40qKyrbK0cpr1SuUj6j3E9FUQ2pLGoatYR6gtpL/aKiqcJQ4alsUqlXua0yrjpP1VOVp1qo2qB6T' \
                    b'/WLGk3NRy1Vbatas9oTdbS6qXqo+gr1PeqX1F/PU5rnOo8zr3DeiXkPNWANU40wjVUa+zRuaIxpamn6aQo1d2pe1Hyt' \
                    b'RdXy1ErRKtM6qzWiTdF21+Zrl2mf035JU6YxaGm0ClonbVRHQ8dfR6JTrdOtM6FrpBupm6fboPtEj6hH10vUK9Pr0Bv' \
                    b'V19ZfoJ+rX6f/0IBgQDdINthh0GUwbmhkGG240bDZ8IWRqhHLKMeozuixMdnYw3i5cY3xXROsCd0k1WS3yS1T2NTBNN' \
                    b'm0yvSmGWzmaMY3223WY44xdzYXmNeY91mQLBgWWRZ1FgOWVMsgyzzLZss3VvpWcVZbrbqsvls7WKdZ77d+ZKNoE2CTZ' \
                    b'9Nm887W1JZjW2V7145s52u31q7F7q29mT3Pfo/9fQeKwwKHjQ4dDt8cnRxFjvWOI076TvFOu5z66Er0EHox/YozxtnL' \
                    b'ea1zu/NnF0eXTJcTLn+6Wrimuh52fTHfaD5v/v75g266bmy3ard+d5p7vPvP7v0eOh5sjxqPZ556nlzPA57DDBNGCuM' \
                    b'I442XtZfIq9FrnOnCXM08743y9vMu9O72UfSJ9Kn0eeqr65vkW+c76ufgt8rvvD/GP9B/q38fS5PFYdWyRgOcAlYHdA' \
                    b'aSAsMDKwOfBZkGiYLaFsALAhZsW/B4ocFCwcLmYBDMCt4W/CTEKGR5yOlQbGhIaFXo8zCbsNywrnBK+LLww+EfI7wiS' \
                    b'iIeRRpHSiI7ouSiFkfVRo1He0eXRvfHWMWsjrkeqx7Lj22Jw8VFxR2IG1vks2j7oqHFDosLFvcuMVqycsnVpepL05ae' \
                    b'WSa3jL3sZDwmPjr+cPxXdjC7hj2WwErYlTDKYXJ2cF5xPbll3BGeG6+UN5zollia+CLJLWlb0kiyR3J58ms+k1/Jf5v' \
                    b'in7I3ZTw1OPVg6mRadFpDOj49Pr1VoChIFXRmaGWszOgRmgkLhP3LXZZvXz4qChQdEEPiJeKWTCVkSLohMZb8IBnIcs' \
                    b'+qyvq0ImrFyZUKKwUrb2SbZm/KHs7xzfllFXoVZ1VHrk7u+tyB1YzV1WugNQlrOtbqrc1fO7TOb92h9cT1qet/zbPOK' \
                    b'837sCF6Q1u+Zv66/MEf/H6oK5AtEBX0bXTduPdH9I/8H7s32W3auel7IbfwWpF1UXnR12JO8bWfbH6q+Glyc+Lm7hLH' \
                    b'kj1bsFsEW3q3emw9VKpQmlM6uG3BtqYyWllh2Yfty7ZfLbcv37uDuEOyo78iqKJlp/7OLTu/ViZX3qvyqmrYpbFr067' \
                    b'x3dzdt/d47qnfq7m3aO+Xn/k/36/2q26qMawp34fdl7Xv+f6o/V2/0H+pPaB+oOjAt4OCg/2Hwg511jrV1h7WOFxSB9' \
                    b'dJ6kaOLD5y66j30ZZ6i/rqBmpD0TFwTHLs5fH4470nAk90nKSfrD9lcGpXI6WxsAlqym4abU5u7m+JbelpDWjtaHNta' \
                    b'zxtefpgu0571RnlMyVniWfzz06eyzk3dl54/vWFpAuDHcs6Hl2MuXi3M7Sz+1LgpSuXfS9f7GJ0nbvidqX9qsvV1mv0' \
                    b'a83XHa833XC40firw6+N3Y7dTTedbrbccr7V1jO/5+xtj9sX7njfuXyXdff6vYX3enoje+/3Le7rv8+9/+JB2oO3D7M' \
                    b'eTjxa9xjzuPCJ/JPypxpPa34z+a2h37H/zID3wI1n4c8eDXIGX/0u/v3rUP5z8vPyYe3h2he2L9pHfEduvVz0cuiV8N' \
                    b'XE64I/FP7Y9cb4zak/Pf+8MRozOvRW9HbyXfF7tfcHP9h/6BgLGXv6Mf3jxHjhJ7VPhz7TP3d9if4yPLHiK+5rxTeTb' \
                    b'23fA78/nkyfnBSyRezpUQCFKJyYCMC7gwCQYwGgIDMEcdHMbD0t0Mz3wDSB/8Qz8/e0OAJQj5ipEYl5HoBjiBquA0DO' \
                    b'E4Cp8SjCE8B2dlKdnYOnZ/YpwSJfL/VWmvJy2PshS8E/ZWae/0vd/7RgKqs9+Kf9F1uNDCpTAs42AAAAlmVYSWZNTQA' \
                    b'qAAAACAAFARIAAwAAAAEAAQAAARoABQAAAAEAAABKARsABQAAAAEAAABSASgAAwAAAAEAAgAAh2kABAAAAAEAAABaAA' \
                    b'AAAAAAAJAAAAABAAAAkAAAAAEAA5KGAAcAAAASAAAAhKACAAQAAAABAAAAIKADAAQAAAABAAAASAAAAABBU0NJSQAAA' \
                    b'FNjcmVlbnNob3Tx3tJyAAAACXBIWXMAABYlAAAWJQFJUiTwAAAC1WlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPHg6' \
                    b'eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNi4wLjAiPgogICA8cmRmOlJ' \
                    b'ERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cm' \
                    b'RmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgICAgICAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY' \
                    b'29tL2V4aWYvMS4wLyIKICAgICAgICAgICAgeG1sbnM6dGlmZj0iaHR0cDovL25zLmFkb2JlLmNvbS90aWZmLzEuMC8i' \
                    b'PgogICAgICAgICA8ZXhpZjpQaXhlbFhEaW1lbnNpb24+MzI8L2V4aWY6UGl4ZWxYRGltZW5zaW9uPgogICAgICAgICA' \
                    b'8ZXhpZjpVc2VyQ29tbWVudD5TY3JlZW5zaG90PC9leGlmOlVzZXJDb21tZW50PgogICAgICAgICA8ZXhpZjpQaXhlbF' \
                    b'lEaW1lbnNpb24+NzI8L2V4aWY6UGl4ZWxZRGltZW5zaW9uPgogICAgICAgICA8dGlmZjpSZXNvbHV0aW9uVW5pdD4yP' \
                    b'C90aWZmOlJlc29sdXRpb25Vbml0PgogICAgICAgICA8dGlmZjpZUmVzb2x1dGlvbj4xNDQ8L3RpZmY6WVJlc29sdXRp' \
                    b'b24+CiAgICAgICAgIDx0aWZmOlhSZXNvbHV0aW9uPjE0NDwvdGlmZjpYUmVzb2x1dGlvbj4KICAgICAgICAgPHRpZmY' \
                    b'6T3JpZW50YXRpb24+MTwvdGlmZjpPcmllbnRhdGlvbj4KICAgICAgPC9yZGY6RGVzY3JpcHRpb24+CiAgIDwvcmRmOl' \
                    b'JERj4KPC94OnhtcG1ldGE+CibWx0MAAAKaSURBVGgF7Zm9bhNBEMdn9s5OzkAaCp4AUfMIiIYnoADT8dUgpFAhUaRGg' \
                    b'vAOfIiSGCQIFQ2iQUpHlUegQNjEZ93eDjNH1lycu83eGXGFdwuftd6Z/29mZ2dPCT4c7t+BVR64eeWAVjkBEDLQeQbU' \
                    b'ShegBB+2INRAqIHOa6BzgM4bYSjCzmsgAIRTEGogZKDzDIRj2PkWBICQgZCB0IhCDXSegRg7LsOlMqBK9DlBqz/5tga' \
                    b'I2JIVv/LHREAihBKOf1pbAfQiAGPo7WmYXgbCuyyXlrPhLw/QGGB9AJDlNFL9wfWt92d/PvmYvMwM3m4L0QhAIk8PaB' \
                    b'T1B8PHIxzbSJ/tJs9zwlttILwBRFznsLMobiGefkheFBAI0ybb4QVQiGvaUf3kRjlyK26fAmE0Z6IBxIkAIp5reKMmA' \
                    b'6e4hZCa0Dne9IVwAoh4xuKnZhz55797bsXqntu7yStfiFoA2Ufe89fj78nVrU84qROrmxcIY2CISD9cDQIfHP7TSjqZ' \
                    b'bSYiboC+AdEmRWpMGiMkymmc7G1/wWmdqMzfv5ReiBM6xw6MVpT1DFzj6XvctCo54ipnhlcT4Xlubu+MhijGos/+oo3' \
                    b'ZRV6/X2Vj56I184idDmdsgjn7QWkbRae0S448KwFkBSL05MllIN9Bc9NiDp+Bst5mkw36/L12zGugZHBsMUkE/peNH+' \
                    b'ahyhzgmOp/mmgEEGftrlxXLHMA131e5JRrIlvXZ1zO2vxmAfi0uaNjwF6WRhttRFw29hQgyztq9Y8LI6v+8bAZ8HKrP' \
                    b'CBPcrS41d4AckxTk/PryHJjcau9AURWkbSYJQcdfQtrBLCkdKV5APDOgGw+F6LcTY3GYtUvGsfy1uMzCgCFxQ3pWs8R' \
                    b'rZV9soGzcH8DwbrYx3Lr9SEAAAAASUVORK5CYII='

UPMS_MENU_ICON_ENCODED = b'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAP' \
                         b'oAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAhGVYSWZNTQAqAAAACAAFARIAAwAAAAEAAQAAARoABQAAAAEAAABK' \
                         b'ARsABQAAAAEAAABSASgAAwAAAAEAAgAAh2kABAAAAAEAAABaAAAAAAAAAEgAAAABAAAASAAAAAEAA6ABAAMAAAABAA' \
                         b'EAAKACAAQAAAABAAAAIKADAAQAAAABAAAAIAAAAABfvA/wAAAACXBIWXMAAAsTAAALEwEAmpwYAAACyGlUWHRYTUw6' \
                         b'Y29tLmFkb2JlLnhtcAAAAAAAPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIE' \
                         b'NvcmUgNi4wLjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRm' \
                         b'LXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgICAgICAgICB4bWxucz' \
                         b'p0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgICAgICAgICAgeG1sbnM6ZXhpZj0iaHR0cDov' \
                         b'L25zLmFkb2JlLmNvbS9leGlmLzEuMC8iPgogICAgICAgICA8dGlmZjpZUmVzb2x1dGlvbj43MjwvdGlmZjpZUmVzb2' \
                         b'x1dGlvbj4KICAgICAgICAgPHRpZmY6UmVzb2x1dGlvblVuaXQ+MjwvdGlmZjpSZXNvbHV0aW9uVW5pdD4KICAgICAg' \
                         b'ICAgPHRpZmY6WFJlc29sdXRpb24+NzI8L3RpZmY6WFJlc29sdXRpb24+CiAgICAgICAgIDx0aWZmOk9yaWVudGF0aW' \
                         b'9uPjE8L3RpZmY6T3JpZW50YXRpb24+CiAgICAgICAgIDxleGlmOlBpeGVsWERpbWVuc2lvbj4zMjwvZXhpZjpQaXhl' \
                         b'bFhEaW1lbnNpb24+CiAgICAgICAgIDxleGlmOkNvbG9yU3BhY2U+MTwvZXhpZjpDb2xvclNwYWNlPgogICAgICAgIC' \
                         b'A8ZXhpZjpQaXhlbFlEaW1lbnNpb24+MzI8L2V4aWY6UGl4ZWxZRGltZW5zaW9uPgogICAgICA8L3JkZjpEZXNjcmlw' \
                         b'dGlvbj4KICAgPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4Ko+jingAAAlJJREFUWAntlrtu1UAQhv/xhSRIpOUJEDWPEE' \
                         b'W8AgUcOkA0NBQ0UKRJkNLwEFxESQ5IFAGJBtEg0VHxCEhEJMQkttf8c8IcG8uXtUGJkLLF2fWemfm/nd0dW+5fLgqc' \
                         b'YAtOUHsmfQrwf2cgkPIE8SiPOsyjMxDS0xX4SNk9BRFBBacE6xuNAohDIHd4GUdYJcBtivysZqNPtPr/YIDFs8Bhjm' \
                         b'm6hGtrr+X7+lt5mhW4NRZiEICuPNnHNFvCZHMqu7aSh9vyOC9wcwyEN4CKpw5bdXGD2NiWJ78hkiHb4QUwE8+wlS7i' \
                         b'enXlJm69Qrh8lglviF4AFc8yvEiTbnGD0DPBA3qDz14QnQAqfkjxKKP4+3LPTayt33gjz3whWgF0H7Mcz79+w5W1d7' \
                         b'LXJtY2rxCZw4RhdroKhNjrWCuZFRMVZ5H5zLm7EmCX+xoGBfL9BJ8efZCkTVTn760UF+MY5+HgXICUflcZ7g7LZCNH' \
                         b'1BSM4qD4BXq8KhxCrXp8/rGwjEu0/9LkY3NRhAeRYJLSRRxnhZdH1RvlgUYADUaHeNYfjbXQt26X2lkjqKiYZZPzZ9' \
                         b'rE1WcetOJgseY9g2oG+NvfGMfLziLNAWziuPtBAFE6bHU+i5kDdKVYc8rUxgchzvkEHWJjAHoFO/eOgLE7wPKQ4D62' \
                         b'dgv0krRclDKM64EsLf1HlgEvDxaVXsi+QPWt9gbQa5o48HPk71p9q70BVPZfZEDDVJfwx0P1j+ManwJ4Z0CPfyjgJ8' \
                         b'qwVj/1de9Iv3p8mgIE4dEbssuedgu1mJ1X9xeol7VOGchwfwAAAABJRU5ErkJggg=='

UPMS_ICON_32 = ida_kernwin.load_custom_icon(data=base64.b64decode(UPMS_ICON_32_ENCODED), format="png")
UPMS_MENU_ICON = ida_kernwin.load_custom_icon(data=base64.b64decode(UPMS_MENU_ICON_ENCODED), format="png")

if len(logger.handlers) > 0:
    logger.handlers = []

log_stream = logging.StreamHandler()
formatter = logging.Formatter('UnpacMeSearch:%(levelname)s:%(message)s')
log_stream.setFormatter(formatter)

# probably bug here?
logger.addHandler(log_stream)

BAD_OFFSETS = [0xffffffff, 0xffffffffffffffff]


class SearchPreview(QDialog):
    def __init__(self, search_list, code_block, parent=None):
        super(SearchPreview, self).__init__(parent)

        self.setWindowTitle("Search Preview")
        self.resize(640, 480)
        layout = QVBoxLayout()
        self.edit_search = QTextEdit(self)
        self.edit_search.setMinimumWidth(300)
        self.edit_codeblock = QTextEdit(self)
        self.edit_codeblock.setReadOnly(True)
        self.edit_codeblock.setText(code_block)
        self.edit_codeblock.setLineWrapMode(QTextEdit.NoWrap)

        self.edit_codeblock.setFixedWidth(320)

        self.btn_search = QPushButton("Search", self)
        self.btn_search.clicked.connect(self.accept)
        self.btn_cancel = QPushButton("Cancel", self)
        self.btn_cancel.clicked.connect(self.reject)

        search_query = "\n".join(search_list)

        self.edit_search.setText(search_query)

        layout_view = QHBoxLayout()

        layout_view.setAlignment(Qt.AlignTop)
        layout_view.addWidget(self.edit_search)
        layout_view.addWidget(self.edit_codeblock)
        layout_view.addStretch(1)

        layout_buttons = QHBoxLayout()
        layout_buttons.addWidget(self.btn_cancel)
        layout_buttons.addWidget(self.btn_search)

        layout.addLayout(layout_view)
        layout.addLayout(layout_buttons)
        self.setLayout(layout)

    def get_search_pattern(self):
        return self.edit_search.toPlainText().replace("\n", "")


class GoodwareView(QDialog):
    def __init__(self, sha256, metadata, parent=None):
        super(GoodwareView, self).__init__(parent)

        self.setWindowTitle("Goodware Details")
        self.resize(600, 300)
        layout = QVBoxLayout()
        form_layout = QFormLayout()

        self.lbl_sha256 = QLabel("SHA256:")
        self.lbl_sha256_val = QLabel(metadata['sha256'])

        self.lbl_name = QLabel("Name:")
        self.lbl_name_val = QLabel(metadata['name'])

        self.lbl_size = QLabel("Size:")
        self.lbl_size_val = QLabel(str(metadata['size']))

        self.lbl_type = QLabel("Type:")
        self.lbl_type_val = QLabel(metadata['type'])

        self.lbl_subsystem = QLabel("Subsystem:")
        self.lbl_subsystem_val = QLabel(metadata['subsytem'])

        self.lbl_machine_type = QLabel("Machine Type:")
        self.lbl_machine_type_val = QLabel(metadata['machine_type'])

        self.lbl_linker_version = QLabel("Linker Version:")
        self.lbl_linker_version_val = QLabel(metadata['linker_version'])


        form_layout.addRow(self.lbl_sha256, self.lbl_sha256_val)
        form_layout.addRow(self.lbl_name, self.lbl_name_val)
        form_layout.addRow(self.lbl_size, self.lbl_size_val)
        form_layout.addRow(self.lbl_type, self.lbl_type_val)
        form_layout.addRow(self.lbl_subsystem, self.lbl_subsystem_val)
        form_layout.addRow(self.lbl_machine_type, self.lbl_machine_type_val)
        form_layout.addRow(self.lbl_linker_version, self.lbl_linker_version_val)

        if 'metadata' in metadata.keys():
            if 'StringInfo' in metadata['metadata'].keys():
                for prop, prop_val in metadata['metadata']['StringInfo'].items():
                    lbl = QLabel(prop)
                    lbl_val = QLabel(prop_val)
                    form_layout.addRow(lbl, lbl_val)

        self.btn_search = QPushButton("Ok", self)
        self.btn_search.clicked.connect(self.accept)

        layout_buttons = QHBoxLayout()
        layout_buttons.addWidget(self.btn_search)

        layout.addLayout(form_layout)
        layout.addLayout(layout_buttons)

        self.setLayout(layout)


class UnpacMeSearchConfigDialog(QDialog):
    def __init__(self, config, parent=None):
        super(UnpacMeSearchConfigDialog, self).__init__(parent)
        self.config = config
        self.setWindowTitle("UnpacMe Search Config")
        self.resize(320, 240)

        layout = QVBoxLayout()

        form_layout = QFormLayout()

        self.lbl_api_key = QLabel("API Key:")
        self.w_api_key = QLineEdit()
        self.w_api_key.setEchoMode(QLineEdit.Password)
        self.w_api_key.setFixedWidth(300)
        self.w_api_key.setText(self.config['api_key'])

        self.lbl_loglevel = QLabel("Log Level:")

        self.cmb_loglevels = QComboBox()
        self.cmb_loglevels.addItems(['DEBUG', "INFO", "ERROR"])
        self.cmb_loglevels.setEditable(False)

        self.lbl_preview = QLabel("Search Preview:")

        self.chk_preview = QCheckBox()
        self.chk_preview.setChecked(self.config['preview'])

        self.lbl_wildcard = QLabel("Auto Wildcard:")
        self.chk_wildcard = QCheckBox()
        self.chk_wildcard.setChecked(self.config['auto'])

        self.lbl_goodware = QLabel("Search Goodware:")
        self.chk_goodware = QCheckBox()
        self.chk_goodware.setChecked(self.config['goodware'])

        form_layout.addRow(self.lbl_api_key, self.w_api_key)
        form_layout.addRow(self.lbl_loglevel, self.cmb_loglevels)
        form_layout.addRow(self.lbl_preview, self.chk_preview)
        form_layout.addRow(self.lbl_wildcard, self.chk_wildcard)
        form_layout.addRow(self.lbl_goodware, self.chk_goodware)

        self.btn_search = QPushButton("Save", self)
        self.btn_search.clicked.connect(self.accept)
        self.btn_cancel = QPushButton("Cancel", self)
        self.btn_cancel.clicked.connect(self.reject)

        layout_buttons = QHBoxLayout()
        layout_buttons.addWidget(self.btn_cancel)
        layout_buttons.addWidget(self.btn_search)

        layout.addLayout(form_layout)
        layout.addLayout(layout_buttons)

        self.setLayout(layout)

    def get_config(self):
        self.config['goodware'] = self.chk_goodware.isChecked()
        self.config['auto'] = self.chk_wildcard.isChecked()
        self.config['preview'] = self.chk_preview.isChecked()
        self.config['loglevel'] = self.cmb_loglevels.currentText()
        self.config['api_key'] = self.w_api_key.text()
        return self.config


class UnpacMeResultWidget(idaapi.PluginForm):

    def __init__(self, search_term: str, results: dict):
        super(UnpacMeResultWidget, self).__init__()
        self.search_term = search_term
        self.results = results
        self.goodware_hashes = []
        self.id_map = {}

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        # self.FormSetTitle("UnpacMe Results")
        self.PopulateForm()

    def handle_click(self, item):

        if item.column() == 4:

            if self.id_map[item.text()]['malware']:
                webbrowser.open(f"https://www.unpac.me/results/{self.id_map[item.text()]['id']}?hash={item.text()}")
                return

            gwv = GoodwareView(item.text(), self.id_map[item.text()]['metadata'])
            gwv.exec_()

        elif item.column() == 1:

            if 'Unknown' == item.text() or item.text() == '':
                logger.warning("No family")
                return

            term = f'malware:"{item.text()}"'.encode("ascii")
            webbrowser.open(f'https://www.unpac.me/search?terms={base64.b64encode(term).decode("ascii")}')

    def PopulateForm(self):

        goodware_matches = 0
        unknown_matches = 0
        malicious_matches = 0

        layout = QVBoxLayout()

        summary_pane = QHBoxLayout()
        summary_pane.setAlignment(Qt.AlignLeft)

        summary_layout = QFormLayout()

        lbl_logo = QLabel()
        lbl_logo.setGeometry(10, 10, 100, 100)

        pixmap = QPixmap()
        pixmap.loadFromData(QByteArray(base64.b64decode(UPMS_ICON_32_ENCODED)))
        lbl_logo.setPixmap(pixmap)
        summary_pane.addWidget(lbl_logo)

        search_term = self.search_term
        if len(self.search_term) > 16:
            search_term = self.search_term[:16] + "..."

        btn_copy = QPushButton("Copy Pattern")
        btn_copy.clicked.connect(self.copy_text_to_clipboard)

        summary_layout.addRow(QLabel("Search Term:"), QLabel(search_term))
        summary_layout.addRow(QLabel("Matches:"), QLabel(f"{self.results['result_count']}"))
        summary_layout.addRow(QLabel("First Seen:"), QLabel(f"{datetime.fromtimestamp(self.results['first_seen']).strftime('%Y-%m-%d')}"))
        summary_layout.addRow(QLabel("Last Seen:"),
                              QLabel(f"{datetime.fromtimestamp(self.results['last_seen']).strftime('%Y-%m-%d')}"))

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        summary_layout.addRow(line)
        summary_layout.addRow(btn_copy)
        summary_layout.setVerticalSpacing(0)
        summary_pane.addLayout(summary_layout)

        result_table = QTableWidget()
        result_table.setRowCount(0)
        result_table.setColumnCount(6)
        result_table.itemDoubleClicked.connect(self.handle_click)
        result_table.setSortingEnabled(True)
        result_table.setMinimumHeight(600)

        result_table.setHorizontalHeaderLabels(["Classification",
                                                "Malware Family",
                                                "Labels",
                                                "Threat Type",
                                                "SHA256",
                                                "Last Seen"])

        results = self.results['results']
        last_row = 0
        for row, result in enumerate(results):
            last_row = row
            result_table.insertRow(row)
            try:
                self.id_map[result['sha256']] = {
                    'id': result["analysis"][0]["id"],
                    'malware': True
                }
            except Exception as wtf:
                print(wtf)

            sha256_item = QTableWidgetItem(result['sha256'])
            sha256_item.setToolTip("View latest Analysis on UnpacMe")

            result_table.setItem(row, 4, QTableWidgetItem(sha256_item))
            result_table.setItem(row, 5, QTableWidgetItem(str(datetime.fromtimestamp(result['last_seen']).strftime('%Y-%m-%d'))))
            malware_family = []
            classification_type = ""
            threat_type = ""
            labels = []
            family_lower = []
            for entry in result['malwareid']:

                try:
                    if entry['malware_family'].lower() not in family_lower:
                        family_lower.append(entry['malware_family'].lower())
                        malware_family.append(entry['malware_family'])
                except AttributeError:
                    logger.debug("No malware family")

                if entry['type'] == 'unpacme':
                    if not classification_type:
                        classification_type = entry['classification_type']

                    if not threat_type:
                        threat_type = entry['threat_type']
                labels.append(entry['name'])
            try:
                family_str = "\n".join([x.capitalize() for x in set(malware_family)])
            except TypeError:
                family_str = ""

            label_str = "\n".join(list(set(labels)))
            if not label_str:
                label_str = ""
            family_widget = QTableWidgetItem(family_str)
            family_widget.setToolTip("Search for malware family on UnpacMe.")
            result_table.setItem(row, 1, family_widget)
            result_table.setItem(row, 2, QTableWidgetItem(label_str))

            # if there is no set classificaiton type, but
            # there are applied labels (i.e. malpedia) set the classification type to malicious
            if not classification_type:
                if family_str:
                    classification_type = "MALICIOUS"

            if classification_type == "MALICIOUS":
                ct_widget = QTableWidgetItem(classification_type)
                # ff0000
                ct_widget.setBackground(QColor(255, 0, 0))
                malicious_matches += 1
            else:
                classification_type = "UNKNOWN"
                ct_widget = QTableWidgetItem(classification_type)
                # 6c757d
                ct_widget.setBackground(QColor(108, 117, 125))
                unknown_matches += 1

            ct_widget.setForeground(QColor(255, 255, 255))

            result_table.setItem(row, 0, ct_widget)
            result_table.setItem(row, 3, QTableWidgetItem(threat_type))

        if self.results['goodware_results']:
            self.goodware_row_start = last_row + 1
            for row, result in enumerate(self.results['goodware_results'], start=last_row + 1):
                self.goodware_hashes.append(result['sha256'])

                self.id_map[result['sha256']] = {
                    'malware': False,
                    'metadata': result
                }

                result_table.insertRow(row)
                ct_widget = QTableWidgetItem("GOODWARE")
                # 228B22
                ct_widget.setBackground(QColor(34, 139, 34))
                ct_widget.setForeground(QColor(255, 255, 255))
                result_table.setItem(row, 0, ct_widget)
                sha256_item = QTableWidgetItem(result['sha256'])
                sha256_item.setToolTip("View details...")
                result_table.setItem(row, 4, sha256_item)
                goodware_matches += 1

        result_table.resizeRowsToContents()
        result_table.setEditTriggers(QTableWidget.NoEditTriggers)

        header = result_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

        count_summary_layout = QFormLayout()

        gwc = QLabel(f"{goodware_matches}")
        gwc.setStyleSheet("background-color: #228B22; padding: 5px; color: #ffffff;")

        uc = QLabel(f"{unknown_matches}")
        uc.setStyleSheet("background-color: #6c757d; padding: 5px; color: #ffffff;")

        mc = QLabel(f"{malicious_matches}")
        mc.setStyleSheet("background-color: #ff0000; padding: 5px; color: #ffffff;")

        count_summary_layout.addRow(QLabel("Goodware:"), gwc)
        count_summary_layout.addRow(QLabel("Unknown:"), uc)
        count_summary_layout.addRow(QLabel("Malicious:"), mc)

        summary_pane.addLayout(count_summary_layout)

        # Add the summary pane to the main layout
        layout.addLayout(summary_pane, Qt.AlignLeft)

        layout.addWidget(result_table, Qt.AlignLeft)
        layout.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        layout.addStretch(1)

        self.parent.setLayout(layout)

    def copy_text_to_clipboard(self):

        clipboard = QGuiApplication.clipboard()
        clipboard.setText(self.search_term)

        logger.info(f"Text copied to clipboard: {self.search_term}")

    def OnClose(self, form):
        pass


class UnpacMeSearch(object):
    """

    """
    def __init__(self, api_key):
        self.api_key = f"Key {api_key}"
        self.base_site = "https://api.unpac.me/api/"
        self.api_version = "v1"
        self.search_endpoint = "/private/search/term/"
        self.search_types = {"hex": "string.hex",
                             "ascii": "string.ascii",
                             "wide": "string.wide"
                             }

    def search(self, data: str, type: str, search_goodware=False) -> dict:
        try:

            ida_kernwin.show_wait_box("Searching...")

            url = f"{self.base_site}{self.api_version}{self.search_endpoint}{self.search_types[type]}"

            auth_header = {'Authorization': self.api_key}
            logger.debug(f"URL: {url}")
            search_data = {'value': data}
            logger.debug(f"Search Data: {search_data}")

            search_response = requests.post(url, json=search_data, headers=auth_header)
            ida_kernwin.replace_wait_box("Processing results.")
            logger.debug(f"Status: {search_response.status_code}")

            if search_response.status_code == 404:
                jres = search_response.json()
                if "warning" in jres.keys():
                    idc.warning(jres['warning'])
                idc.warning("No results found for the pattern.")
                return {}

            if search_response.status_code != 200:
                logger.error(f"Error in search...try again {search_response.status_code}")
                idc.warning(f"Unexpected response from UnpacMe...please try again. Code: {search_response.status_code}")
                return {}

            search_results = search_response.json()

            if not search_goodware:
                search_results['goodware_results'] = []
                search_results['matched_goodware_files'] = 0
                return search_results

            logger.debug("Searching Goodware")
            ida_kernwin.replace_wait_box("Searching goodware...")
            search_data['repo_type'] = 'goodware'
            gw_result = requests.post(url, json=search_data, headers=auth_header)
            ida_kernwin.replace_wait_box("Processing results...")

            if gw_result.status_code == 200:
                search_results['goodware_results'] = gw_result.json()['goodware_results']
                search_results['matched_goodware_files'] = gw_result.json()['matched_goodware_files']
            elif gw_result.status_code == 404:
                search_results['goodware_results'] = []
                search_results['matched_goodware_files'] = 0
            else:
                logger.error(f"Error while searching ..{gw_result.status_code}")
                idc.warning("Unexpected response from UnpacMe...please try again")
                search_results['goodware_results'] = []
                search_results['matched_goodware_files'] = 0

            return search_results
        except Exception as ex:
            logger.error(f"Error making request {ex}")
            idc.warning(f"Unexpected error UnpacMe...please try again. {ex}")
        finally:
            ida_kernwin.hide_wait_box()


class SearchHandler(ida_kernwin.action_handler_t):

    def __init__(self, preview, auto_wildcard, search_goodware):
        ida_kernwin.action_handler_t.__init__(self)

        self.unpacme_search = None

        self.preview = preview
        self.auto_wildcard = auto_wildcard
        self.search_goodware = search_goodware

        # https://www.hex-rays.com/products/ida/support/idadoc/276.shtml
        self.wildcard_types = [ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_far, ida_ua.o_near]
        self.result_widget = None

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def activate(self, ctx):
        # Delay loading of the UnpacMeSearch class until we need it
        # This prevents possible password prompt on IDA startup to access the keystore
        if self.unpacme_search is None:
            self.unpacme_search = UnpacMeSearch(keyring.get_password('unpacme', 'api_key'))

        start = idc.read_selection_start()
        end = idc.read_selection_end()

        if start in BAD_OFFSETS or end in BAD_OFFSETS:
            logger.debug("Nothing selected")
            idc.warning("Nothing Selected!")
            return

        if start > end:
            logger.debug("Start is greater than end")
            idc.warning("Start is greater than end")
            return

        offset = start

        code_block = ""

        search_bytes = []
        iterations = 0
        logger.debug(f'Start: {hex(start)} End: {hex(end)}')

        while offset < end:
            iterations += 1
            if iterations > 100:
                break
            instr_string = []
            try:
                cur_offset = offset
                flags = ida_bytes.get_full_flags(cur_offset)

                if not ida_bytes.is_code(flags):
                    logger.debug("Processing as data")
                    ibytes = idc.get_bytes(cur_offset, idc.get_item_size(cur_offset), 0)
                    for b in ibytes:
                        instr_string.append("{0:02x}".format(b))
                    continue

                ins = ida_ua.insn_t()
                idaapi.decode_insn(ins, cur_offset)
                instruction_size = ins.size

                logger.debug("------------------------------")
                logger.debug(f"Current Offset: {hex(cur_offset)}")
                logger.debug("Instruction Size: %d" % instruction_size)
                logger.debug(f"Bytes: {binascii.hexlify(idc.get_bytes(cur_offset, instruction_size, 0))}")
                logger.debug(f"Flags: {flags}")
                logger.debug(idc.generate_disasm_line(cur_offset, 0))
                logger.debug("------------------------------")

                op1 = ins.ops[0]
                op2 = ins.ops[1]

                ibytes = idc.get_bytes(cur_offset, ins.size, 0)
                code_block += " ".join("{0:02x}".format(b) for b in bytearray(ibytes))
                if len(ibytes) <= 4:
                    code_block += "\t"

                logger.debug(idc.generate_disasm_line(offset, 0))
                code_block += f"\t{idc.generate_disasm_line(offset, 0)}\n"

                if (op1.type not in self.wildcard_types and op2.type not in self.wildcard_types) or not self.auto_wildcard:
                    logger.debug("No wildcards")
                    ibytes = idc.get_bytes(cur_offset, instruction_size, 0)
                    for b in ibytes:
                        instr_string.append("{0:02x}".format(b))
                    continue

                if op1.type in self.wildcard_types:
                    logger.debug("Wildcarding op1")

                    # wild card instruction
                    if op1.offb == 0 and op2.offb == 0:
                        logger.debug("Wildcarding entire instruction")
                        instr_string.append("?? " * int(instruction_size))
                        continue

                    # wildcard instruction with op1
                    if op2.offb > 0:
                        op1_size = op2.offb - op1.offb
                    else:
                        op1_size = instruction_size - op1.offb
                    logger.debug(f"op1_size: {op1_size}")

                    if op1.offb == 0:
                        instr_string.append("?? " * int(op1_size))
                    else:
                        logger.debug("Getting op")
                        logger.debug(f"ibytes: {ibytes}")
                        for b in ibytes[:op1.offb]:
                            instr_string.append("{0:02x}".format(b))

                        instr_string.append("?? " * int(op1_size))

                    # continue
                    if op2.offb > 0:
                        if op2.type in self.wildcard_types:
                            logger.debug("Wildcarding op2")
                            instr_string.append("?? " * int(instruction_size - op2.offb))
                        else:
                            for b in ibytes[op2.offb:]:
                                instr_string.append("{0:02x}".format(b))

                    continue

                # Check of op2 neds to be wildcarded
                if op2.type in self.wildcard_types:
                    logger.debug("Wildcarding op2")

                    if op2.offb == 0:
                        logger.debug("Wildcarding op2")
                        instr_string.append("?? " * ins.size)
                        continue

                    # emit all bytes up to the start of op2
                    # cases where op1 needs to be wildcared are already handled
                    for b in ibytes[:op2.offb]:
                        instr_string.append("{0:02x}".format(b))

                    op2_size = instruction_size - op2.offb
                    instr_string.append("?? " * int(op2_size))
            except Exception as ex:
                logger.error(f"Exception: {ex}")
            finally:
                search_bytes.append(' '.join(instr_string))

                # TODO: Fix this. For undefined bytes or data, we can just grab the range as bytes.
                next_offset = idc.next_head(offset, end + 32)

                logger.debug(f"Next Offset: {hex(next_offset)}")

                #if next_offset < bad_offset and next_offset >= end:
                if next_offset not in BAD_OFFSETS and next_offset >= end:
                    break

                #if next_offset >= bad_offset:
                if next_offset in BAD_OFFSETS:
                    logger.debug("IDA has wrong offset..manually set")
                    offset += 1
                else:
                    offset = next_offset

                logger.debug(f"Next Offset: {hex(offset)}")

        hex_str = ' '.join(search_bytes)
        logger.debug(f"Search Bytes: {hex_str}")

        if self.preview:
            dialog = SearchPreview(search_bytes, code_block)
            preview_result = dialog.exec_()

            if preview_result == QDialog.Accepted:
                hex_str = dialog.get_search_pattern()
                result = self.unpacme_search.search(hex_str, "hex", self.search_goodware)
            else:
                return
        else:
            result = self.unpacme_search.search(hex_str, "hex", self.search_goodware)

        if result:


            label_map = {}
            classification_map = {}

            for r in result['results']:
                classification_type = ""
                family = ""
                for entry in r['malwareid']:

                    label = entry['malware_family']
                    if not family:
                        family = label

                    classification = entry['classification_type']
                    if classification:
                        classification_type = classification

                if not classification_type:
                    classification_type = 'UNKNOWN'

                if family in label_map:
                    label_map[family] += 1
                else:
                    label_map[family] = 1

                if classification_type in classification_map:
                    classification_map[classification_type] += 1
                else:
                    classification_map[classification_type] = 1
            try:
                classification_map['GOODWARE'] = result['matched_goodware_files']
            except KeyError:
                classification_map['GOODWARE'] = 0

            result['label_map'] = label_map
            result['classification_map'] = classification_map
            logger.info(classification_map)
            logger.info(label_map)

            if self.result_widget:
                self.result_widget.Close(ida_kernwin.PluginForm.WCLS_CLOSE_LATER)

            self.result_widget = UnpacMeResultWidget(hex_str, result)
            self.result_widget.Show("UnpacMe Search")
            if "warning" in result.keys():
                idc.warning(result['warning'])

        return True

    def term(self):
        pass


class UnpacMeByteSearchPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP

    comment = "UnpacMe Search"
    help = "UnpacMe Byte Search"
    wanted_name = "UnpacMe Byte Search"
    wanted_hotkey = ""

    _version = 1.01

    def _banner(self):
        return f"""
        ##################
        UnpacMe Search\n
        Version: {UnpacMeByteSearchPlugin._version}\n\n
        ##################
        """

    def init(self):
        try:
            ida_kernwin.msg(self._banner())
            logger.debug("Loading config..")
            self.config = self.load_configuration()
            logger.setLevel(logging._checkLevel(self.config['loglevel'].upper()))

            self.search_handler = SearchHandler(self.config['preview'], self.config['auto'], self.config['goodware'])

            if self.config.pop('default', False):
                logger.info("Running default configuration")
                self.edit_config()

            logger.debug("== UnpacMe Search Config ==")
            for c in self.config:
                logger.debug(f" -> {c}: {self.config[c]}")

            self.actions = [
                ida_kernwin.action_desc_t(
                    "unpacme_search",
                    "UnpacMe Byte Search",
                    self.search_handler,
                    "Shift-Alt-s",
                    "UnpacMe Byte Search",
                    UPMS_MENU_ICON)
            ]

            for action_desc in self.actions:
                ida_kernwin.register_action(action_desc)

            ida_kernwin.attach_action_to_menu(
                "Edit/Plugins/",
                "unpacme_search",
                ida_kernwin.SETMENU_APP
            )

            self.menus = Menus()
            self.menus.hook()
            logger.info("UnpacmeSearchPlugin initialized.")

        except Exception as ex:
            logger.error('Error initializing UnpacmeSearchPlugin %s' % ex)
            idc.warning('Error initializing UnpacmeSearchPlugin %s' % ex)

        return ida_idaapi.PLUGIN_KEEP

    def save_configuration(self, config_name='unpacme_search.cfg'):
        path = ida_diskio.get_user_idadir()
        config_path = os.path.join(path, config_name)

        with open(config_path, 'w') as outf:
            outf.write(json.dumps(self.config))

    def load_configuration(self, config_name='unpacme_search.cfg'):
        path = ida_diskio.get_user_idadir()
        config_path = os.path.join(path, config_name)

        if not os.path.exists(config_path):
            logger.info("No config file!")

            return {
                'default': True,
                'loglevel': 'INFO',
                'preview': True,
                'auto': True,
                'goodware': True
            }

        with open(config_path, 'r') as inf:
            config_data = json.loads(inf.read())

        return config_data

    def edit_config(self):
        logger.debug("Loading config")
        config = self.load_configuration()
        config.pop('default', None)

        logger.debug("Getting API Key")
        config['api_key'] = keyring.get_password("unpacme", "api_key")
        if not config['api_key']:
            logger.warning("No API Key found!")

        config_handler = UnpacMeSearchConfigDialog(config)
        config_result = config_handler.exec_()
        logger.debug("Config dialog closed")

        if config_result == QDialog.Accepted:
            logger.debug("Getting updated config")
            config = config_handler.get_config()
            key = config.pop('api_key')
            logger.debug(config)
            logger.info("Saving config")
            if key:
                keyring.set_password("unpacme", "api_key", key)
            self.config = config
            self.save_configuration()

            # set these so we don't have to reload
            self.search_handler.auto_wildcard = config['auto']
            self.search_handler.preview = config['preview']
            self.search_handler.search_goodware = config['goodware']
            logger.setLevel(logging._checkLevel(config['loglevel'].upper()))

        return

    def run(self, arg):
        self.edit_config()
        return

    def term(self):
        if self.actions:
            for action_desc in self.actions:
                ida_kernwin.unregister_action(action_desc.name)


class Menus(ida_kernwin.UI_Hooks):

    def finish_populating_widget_popup(self, form, popup):

        if ida_kernwin.get_widget_type(form) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(form, popup, "unpacme_search", "UnpacMe Byte Search")


def PLUGIN_ENTRY():
    return UnpacMeByteSearchPlugin()