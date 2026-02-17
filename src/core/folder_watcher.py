"""
Folder watcher for scheduled/automatic encryption of new files.
Requires: pip install watchdog
"""

import os
import threading
from typing import Callable, Optional

from core.logger import get_logger

try:
    from watchdog.observers import Observer #type: ignore
    from watchdog.events import FileSystemEventHandler #type: ignore
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


class EncryptOnCreateHandler(FileSystemEventHandler):
    """Encrypts new files when they appear in the watched folder."""

    def __init__(self, on_new_file: Callable[[str], None], extensions: Optional[set] = None):
        super().__init__()
        self.on_new_file = on_new_file
        self.extensions = extensions or {".txt", ".pdf", ".doc", ".docx", ".xlsx", ".json"}
        self._logger = get_logger()

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        ext = os.path.splitext(path)[1].lower()
        if ext in self.extensions and not path.endswith(".enc"):
            self._logger.info("Folder watcher detected new file '%s'", path)
            self.on_new_file(path)


def start_folder_watch(
    folder: str,
    on_new_file: Callable[[str], None],
    extensions: Optional[set] = None,
) -> Optional[object]:
    """
    Start watching a folder. When a new file appears, calls on_new_file(path).
    Returns the Observer if started, None if watchdog not installed.
    """
    if not HAS_WATCHDOG:
        return None
    logger = get_logger()
    handler = EncryptOnCreateHandler(on_new_file, extensions)
    observer = Observer()
    observer.schedule(handler, folder, recursive=False)
    observer.start()
    logger.info("Started folder watcher on '%s'", folder)
    return observer


def stop_folder_watch(observer: object) -> None:
    if observer and HAS_WATCHDOG:
        logger = get_logger()
        observer.stop()
        observer.join(timeout=2)
        logger.info("Stopped folder watcher")