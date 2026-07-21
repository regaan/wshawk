"""Stable console facade shared by current and compatibility entry points."""

from ._version_info import __version__
from .logger import Colors, SUCCESS_LEVEL, VULN_LEVEL, get_logger, setup_logging


if not get_logger().handlers:
    setup_logging()


class Logger:
    @staticmethod
    def banner() -> None:
        print(
            f"{Colors.CYAN}{Colors.BOLD}WSHawk{Colors.END}\n"
            f"{Colors.YELLOW}WebSocket Security Scanner v{__version__}{Colors.END}\n"
            f"{Colors.BLUE}{'=' * 40}{Colors.END}"
        )

    @staticmethod
    def info(message) -> None:
        get_logger().info(message)

    @staticmethod
    def success(message) -> None:
        get_logger().log(SUCCESS_LEVEL, message)

    @staticmethod
    def warning(message) -> None:
        get_logger().warning(message)

    @staticmethod
    def error(message) -> None:
        get_logger().error(message)

    @staticmethod
    def vuln(message) -> None:
        get_logger().log(VULN_LEVEL, message)


__all__ = ["Colors", "Logger"]
