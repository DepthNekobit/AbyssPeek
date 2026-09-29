"""カスタムウィジェット: 矢印型の「変換」ボタン。"""

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QAbstractButton


class ConvertArrowButton(QAbstractButton):
    """右向き矢印の形をした「変換」ボタン。"""

    def __init__(self, text: str = "変 換", parent=None):
        super().__init__(parent)
        self.setText(text)
        self.setFixedSize(148, 84)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("左のヘッダーをデコード・解析します (Ctrl+Enter)")
        self._palette_colors = {
            "accent": "#38bdf8",
            "accent_hover": "#5ecbfa",
            "accent_pressed": "#1e9fdc",
            "accent_text": "#04121d",
            "muted": "#8494b8",
            "surface3": "#1a2438",
        }

    def set_palette_colors(self, palette: dict) -> None:
        self._palette_colors = palette
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 (Qt API)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        colors = self._palette_colors
        if not self.isEnabled():
            fill = QColor(colors["surface3"])
            text_color = QColor(colors["muted"])
        elif self.isDown():
            fill = QColor(colors["accent_pressed"])
            text_color = QColor(colors["accent_text"])
        elif self.underMouse():
            fill = QColor(colors["accent_hover"])
            text_color = QColor(colors["accent_text"])
        else:
            fill = QColor(colors["accent"])
            text_color = QColor(colors["accent_text"])

        width = float(self.width())
        height = float(self.height())
        margin = 3.0
        head_width = width * 0.32
        shaft_half = height * 0.26
        center_y = height / 2.0
        shaft_right = width - head_width

        path = QPainterPath()
        path.moveTo(QPointF(margin, center_y - shaft_half))
        path.lineTo(QPointF(shaft_right, center_y - shaft_half))
        path.lineTo(QPointF(shaft_right, margin))
        path.lineTo(QPointF(width - margin, center_y))
        path.lineTo(QPointF(shaft_right, height - margin))
        path.lineTo(QPointF(shaft_right, center_y + shaft_half))
        path.lineTo(QPointF(margin, center_y + shaft_half))
        path.closeSubpath()

        painter.setPen(QPen(fill.darker(112), 1.4))
        painter.setBrush(fill)
        painter.drawPath(path)

        if self.hasFocus():
            focus_pen = QPen(fill.lighter(150), 1.2, Qt.PenStyle.DashLine)
            painter.setPen(focus_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)

        font = QFont(self.font())
        font.setPointSize(12)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(text_color)
        text_rect = QRectF(margin, 0, shaft_right - margin + head_width * 0.28, height)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, self.text())

    def enterEvent(self, event) -> None:  # noqa: N802
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802
        self.update()
        super().leaveEvent(event)
