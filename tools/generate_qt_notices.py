"""licenses/Qt-third-party-notices.txt (Qt 同梱サードパーティ製コンポーネントの表記) を生成する。

Windows 版 exe には PySide6-Essentials の Qt ライブラリ (Qt Core / Gui / Widgets /
Network / Svg と各種プラグイン) が含まれ、その中には FreeType・libpng・PCRE2 など
Qt 以外のサードパーティ製コンポーネントが組み込まれている。これらのライセンスは
バイナリ配布時に著作権表示とライセンス文の同梱を求めるため、Qt ソースに含まれる
公式の帰属情報 (qt_attribution.json) と各コンポーネントのライセンスファイルから
表記を組み立てる。

使い方:
    # 1) requirements-build.txt で固定している Qt と同じバージョンのソースを取得
    for r in qtbase qtimageformats qtsvg; do
        git clone --depth 1 --branch v6.11.2 https://github.com/qt/$r.git
    done
    # 2) 表記ファイルを再生成
    python tools/generate_qt_notices.py 6.11.2 qtbase qtimageformats qtsvg
"""

import json
from pathlib import Path
import re
import sys

OUTPUT = Path(__file__).resolve().parents[1] / "licenses" / "Qt-third-party-notices.txt"

# exe に含まれないもの (ビルドツール・テスト・Windows 以外のプラットフォーム専用・
# 同梱しない Qt モジュール用) を除外する。リポジトリ内パスの前方一致。
EXCLUDED_PATHS = (
    "cmake/",                            # ビルドシステム
    "src/testinternal/",                 # テスト
    "src/testlib/",                      # Qt Test
    "src/3rdparty/android",              # Android
    "src/3rdparty/gradle",               # Android ビルド
    "src/3rdparty/forkfd",               # Unix 専用
    "src/3rdparty/pixman",               # ARM NEON 専用
    "src/3rdparty/sqlite",               # Qt SQL (非同梱)
    "src/3rdparty/wasm",                 # WebAssembly
    "src/3rdparty/wayland",              # Linux (Wayland)
    "src/3rdparty/xcb",                  # Linux (X11)
    "src/corelib/kernel",                # macOS 専用のイベントディスパッチャ
    "src/dbus",                          # Qt D-Bus (Windows では非同梱)
    "src/plugins/platforms/cocoa",       # macOS
)


def load_components(repo: Path) -> list[dict]:
    components = []
    for path in sorted(repo.glob("**/qt_attribution.json")):
        rel_dir = path.parent.relative_to(repo).as_posix() + "/"
        if ".git/" in rel_dir or rel_dir.startswith(EXCLUDED_PATHS):
            continue
        data = json.loads(path.read_text(encoding="utf-8"), strict=False)
        for item in data if isinstance(data, list) else [data]:
            if "tools" in item.get("QtParts", []):
                continue
            names = [item["LicenseFile"]] if "LicenseFile" in item else item.get("LicenseFiles", [])
            files = [path.parent / name for name in names]
            if not files:
                # 個別のライセンスファイルが無いものはリポジトリ共通の LICENSES/ の全文を使う
                ids = re.split(r"\s+(?:AND|OR|WITH)\s+|[()]", item["LicenseId"])
                files = [repo / "LICENSES" / f"{lid.strip()}.txt" for lid in ids if lid.strip()]
            item["_license_texts"] = [
                f.read_text(encoding="utf-8", errors="replace").strip() for f in files
            ]
            item["_repo"] = repo.name
            components.append(item)
    return components


def format_notices(qt_version: str, components: list[dict]) -> str:
    rule = "=" * 78
    lines = [
        f"Qt {qt_version} に含まれるサードパーティ製コンポーネント",
        f"Third-party components included in Qt {qt_version}",
        "",
        "AbyssPeek の Windows 版 exe に同梱している Qt ライブラリ (PySide6-Essentials) には、",
        "以下のサードパーティ製コンポーネントが含まれます。各コンポーネントの著作権表示と",
        "ライセンス文を、Qt ソースの帰属情報 (qt_attribution.json) から転記しています。",
        "",
        "The Qt libraries bundled with the AbyssPeek Windows executable contain the",
        "following third-party components. Copyright notices and license texts are taken",
        "from the attribution files (qt_attribution.json) in the Qt sources.",
        "",
        "Portions of this software are copyright (C) The FreeType Project",
        "(www.freetype.org). All rights reserved.",
        "",
        "収録コンポーネント / Components:",
    ]
    for item in components:
        lines.append(f"  - {item['Name']} ({item['LicenseId']})")

    for item in components:
        lines += ["", rule, item["Name"], rule]
        if item.get("Version"):
            lines.append(f"Version: {item['Version']}")
        lines.append(f"License: {item['License']} ({item['LicenseId']})")
        if item.get("Homepage"):
            lines.append(f"Homepage: {item['Homepage']}")
        lines.append(f"Used in: {item['QtUsage'].strip()} [{item['_repo']}]")
        copyright_text = item.get("Copyright", "")
        if isinstance(copyright_text, list):
            copyright_text = "\n".join(copyright_text)
        if copyright_text.strip():
            lines += ["", copyright_text.strip()]
        for text in item["_license_texts"]:
            lines += ["", text]
    return "\n".join(lines) + "\n"


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    qt_version = sys.argv[1]
    components: list[dict] = []
    for repo_arg in sys.argv[2:]:
        repo = Path(repo_arg)
        if not (repo / "LICENSES").is_dir():
            raise SystemExit(f"{repo} は Qt のソースリポジトリではありません")
        components += load_components(repo)
    components.sort(key=lambda item: item["Name"].lower())
    OUTPUT.write_text(format_notices(qt_version, components), encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT} ({len(components)} components)")


if __name__ == "__main__":
    main()
