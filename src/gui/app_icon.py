"""アプリケーションアイコン。

assets/icon/ に生成済みの画像があればそれを読み込み、
見つからない場合はその場で描画して生成する(単一ファイル配布などの保険)。
生成スクリプトは tools/generate_icon.py。
"""

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)

from src.utils.paths import project_root

ICON_DIR = project_root() / "assets" / "icon"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)

_DEEP_CENTER = "#16355e"
_DEEP_EDGE = "#0a101d"
_EYE_SOCKET = "#0c1a30"
_ACCENT = "#38bdf8"
_ACCENT_DEEP = "#0e9ada"
_PUPIL = "#071220"
_HIGHLIGHT = "#d9f3ff"


def paint_app_icon(size: int) -> QPixmap:
    """「深淵を覗く目」アイコンを指定サイズで描画する(256 基準の座標系)。"""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    scale = size / 256.0
    painter.scale(scale, scale)

    # 背景の円(深海のグラデーション + シアンのリング)
    background = QRadialGradient(QPointF(128, 104), 160)
    background.setColorAt(0.0, QColor(_DEEP_CENTER))
    background.setColorAt(1.0, QColor(_DEEP_EDGE))
    painter.setBrush(background)
    ring_width = 12
    painter.setPen(QPen(QColor(_ACCENT), ring_width))
    margin = ring_width / 2 + 2
    painter.drawEllipse(QPointF(128, 128), 128 - margin, 128 - margin)

    # 目のアーモンド形(上下の二次曲線)
    eye = QPainterPath()
    eye.moveTo(34, 128)
    eye.quadTo(128, 34, 222, 128)
    eye.quadTo(128, 222, 34, 128)
    painter.setBrush(QColor(_EYE_SOCKET))
    painter.setPen(QPen(QColor(_ACCENT), 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawPath(eye)

    # 虹彩
    iris = QRadialGradient(QPointF(120, 118), 54)
    iris.setColorAt(0.0, QColor(_ACCENT))
    iris.setColorAt(1.0, QColor(_ACCENT_DEEP))
    painter.setBrush(iris)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(QPointF(128, 128), 47, 47)

    # 瞳孔とハイライト
    painter.setBrush(QColor(_PUPIL))
    painter.drawEllipse(QPointF(128, 128), 21, 21)
    painter.setBrush(QColor(_HIGHLIGHT))
    painter.drawEllipse(QPointF(112, 112), 9, 9)

    painter.end()
    return pixmap


def load_app_icon() -> QIcon:
    icon = QIcon()
    for size in ICON_SIZES:
        path = ICON_DIR / f"abysspeek_{size}.png"
        if path.exists():
            icon.addFile(str(path))
    if icon.availableSizes():
        return icon

    # アセットが無い環境では描画で代替する
    fallback = QIcon()
    for size in ICON_SIZES:
        fallback.addPixmap(paint_app_icon(size))
    return fallback
