from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
import sys


class ClientGui(QWidget):
    _people: list[bytes]
    _people_container: QStackedWidget
    _max_per_page: int
    _page_indicator: QWidget
    _page_indicator_circles: list[QLabel]
    _register_container: QWidget

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._people = []
        self._people_container = QStackedWidget(parent=self)
        self._max_per_page = 18 - 1

        self._page_indicator = QWidget(parent=self)
        self._page_indicator.setLayout(QHBoxLayout(self._page_indicator))
        self._page_indicator_circles = []

        self._add_new_page()

        self.setLayout(QVBoxLayout(self))
        self.layout().addWidget(self._people_container)
        self.layout().addWidget(self._page_indicator)

        policy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)

        self._register_container = None
        self.show()

    def show_register(self, func):
        self._register_container = QWidget()
        self._register_container.setLayout(QVBoxLayout(self._register_container))
        self._register_container.layout().addWidget(QLabel("Register", parent=self._register_container))
        self._register_container.layout().addWidget(QLineEdit(parent=self._register_container, placeholderText="Username"))
        self._register_container.layout().addWidget(QPushButton("Register", parent=self._register_container, clicked=func))
        self._register_container.show()

    def hide_register(self):
        if self._register_container:
            self._register_container.hide()

    def add_person(self, name: bytes, profile_picture: bytes) -> None:
        current_page = self._people_container.currentWidget()
        current_people_on_page = current_page.layout().count()

        if current_people_on_page == self._max_per_page:
            self._add_new_page()
            self._set_page_index(self._people_container.count() - 1)

        current_page.layout().addWidget(PersonGui(name, profile_picture, parent=self), current_people_on_page // 6, current_people_on_page % 6)

    def _add_new_page(self) -> None:
        spacing = min(16, self.width() // 16)

        widget = QWidget()
        widget.setLayout(QGridLayout(widget, spacing=spacing, contentsMargins=QMargins(spacing, spacing, spacing, spacing)))
        self._people_container.addWidget(widget)

        circle = QPushButton(parent=self._page_indicator, clicked=lambda: self._set_page_index(self._page_indicator_circles.index(circle)))
        circle.setFixedSize(16, 16)
        circle.setStyleSheet("background-color: #c0c0c0; border-radius: 8px;")
        self._page_indicator_circles.append(circle)
        self._page_indicator.layout().addWidget(circle)

    def event(self, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Wheel:
            if event.angleDelta().y() > 0:
                self._set_page_index(self._people_container.currentIndex() + 1)
            else:
                self._set_page_index(self._people_container.currentIndex() - 1)
        if event.type() == QEvent.Type.MouseButtonPress:
            if event.buttons() == Qt.MouseButton.XButton1:
                self._set_page_index(self._people_container.currentIndex() - 1)
            elif event.buttons() == Qt.MouseButton.XButton2:
                self._set_page_index(self._people_container.currentIndex() + 1)
        return super().event(event)

    def _set_page_index(self, index: int) -> None:
        index = max(0, min(index, self._people_container.count() - 1))
        self._page_indicator_circles[self._people_container.currentIndex()].setStyleSheet("background-color: #c0c0c0; border-radius: 8px;")
        self._page_indicator_circles[index].setStyleSheet("background-color: #808080; border-radius: 8px;")
        self._people_container.setCurrentIndex(index)


class PersonGui(QWidget):
    _name: bytes
    _profile_picture: bytes
    _hover_animation: QVariantAnimation

    def __init__(self, name: bytes, image_bytes: bytes, parent: QWidget = None):
        super().__init__(parent)
        self._name = name
        self._profile_picture = image_bytes
        self._hover_animation = None

        size_policy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        size_policy.setHeightForWidth(True)
        self.setSizePolicy(size_policy)
        self.setGraphicsEffect(QGraphicsDropShadowEffect(blurRadius=32, color=QColor(192, 192, 192, 192), offset=QPointF(0, 0), parent=self))

        self._create_hover_animation()

    def _create_hover_animation(self) -> None:
        self._hover_animation = QVariantAnimation(self, startValue=QColor("white"), endValue=QColor(224, 224, 224), duration=150)
        self._hover_animation.valueChanged.connect(self.repaint)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._hover_animation.currentValue())

        painter.drawRoundedRect(0, 0, self.width(), self.height(), 16, 16)
        pixmap = QPixmap()
        pixmap.loadFromData(self._profile_picture)
        pixmap.scaled(self.width() // 2, self.height() // 2)
        painter.drawPixmap(self.width() // 2 - pixmap.width() // 2, self.height() // 2 - pixmap.height() // 2, pixmap)

        font = QFont()
        font.setPointSize(min(self.width() // 8, 16))
        font.setBold(True)
        painter.setFont(font)

        painter.setPen(QPen(QColor(128, 128, 128)))
        painter.drawText(0, self.height() // 4, self.width(), self.height(), Qt.AlignmentFlag.AlignCenter, self._name.decode())

    def sizeHint(self) -> QSize:
        return QSize(self.width(), self.width())

    def heightForWidth(self, width: int) -> int:
        return width

    def event(self, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Enter:
            self._hover_animation.stop()
            self._hover_animation.setDirection(QVariantAnimation.Direction.Forward)
            self._hover_animation.start()
        elif event.type() == QEvent.Type.Leave:
            self._hover_animation.stop()
            self._hover_animation.setDirection(QVariantAnimation.Direction.Backward)
            self._hover_animation.start()
        return super().event(event)

#
# if __name__ == "__main__":
#     app = QApplication(sys.argv)
#     sys.excepthook = lambda *args: sys.__excepthook__(*args)
#     window = ClientGui()
#
#     for x in range(100):
#         window.add_person(b"Person-" + str(x).encode(), b"")
#
#     window.show()
#
#     sys.exit(app.exec())
