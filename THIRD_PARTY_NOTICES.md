# Third-Party Notices

AbyssPeek 本体のソースコードは [MIT License](LICENSE) です。
配布物(Windows 版 exe / zip)には以下のサードパーティ製ソフトウェアが含まれます。

## Qt for Python (PySide6 / Shiboken6) および Qt

- ライセンス: **GNU Lesser General Public License v3.0 (LGPLv3)**
  (PySide6 は LGPL-3.0-only / GPL-2.0-only / GPL-3.0-only から選択可能。本アプリは LGPLv3 を選択)
- Copyright (C) The Qt Company Ltd. and other contributors.
- 全文: [licenses/LGPL-3.0.txt](licenses/LGPL-3.0.txt)
  (LGPLv3 は GPLv3 の追加条項のため [licenses/GPL-3.0.txt](licenses/GPL-3.0.txt) も同梱)
- ソースコードの入手先:
  - PySide6 / Shiboken6: <https://code.qt.io/cgit/pyside/pyside-setup.git/>
    (PyPI: <https://pypi.org/project/PySide6/>)
  - Qt: <https://download.qt.io/official_releases/qt/> / <https://code.qt.io/>

exe には PySide6 / Qt の共有ライブラリ (DLL) が変更なしで含まれています。
AbyssPeek のソースコードは全て本リポジトリで公開しているため、別バージョンや改変した
PySide6 / Qt に差し替えたい場合は、README の「ソースからの起動」または
「自分で exe 化する場合」の手順で、任意の PySide6 を使って実行・再ビルドできます。
Qt のバージョン情報はアプリの「ヘルプ → Qt について」から確認できます。

## Python

- ライセンス: Python Software Foundation License Version 2
- exe には Python ランタイムが含まれます。Python および Python 同梱ライブラリ
  (OpenSSL など)のライセンス全文は、配布 zip の `licenses/LICENSE-Python.txt` に
  収録しています(ビルドに使用した Python の `LICENSE.txt` の写し)。
- <https://docs.python.org/3/license.html>

## PyInstaller(ビルドツール)

- ライセンス: GPLv2 with Bootloader Exception
- exe の起動部分 (bootloader) に使われています。例外条項により、生成された exe は
  任意のライセンスで配布できます。
- <https://github.com/pyinstaller/pyinstaller>

## IPv4 地域テーブルのデータ

`src/services/geoip.py` の IPv4 /8 地域テーブルは、
[ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks)
(CC0 1.0 Universal)の国別割当データを `tools/generate_geoip_table.py` で集計して作成しました。
元データは 5 つの地域インターネットレジストリ (AFRINIC / APNIC / ARIN / LACNIC / RIPE NCC)
が公開している delegated 統計です。CC0 のため表示義務はありませんが、出典として記載します。
