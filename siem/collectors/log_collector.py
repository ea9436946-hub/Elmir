import logging
import os
import time
from pathlib import Path
from threading import Thread, Event
from typing import Callable

logger = logging.getLogger(__name__)


class FileLogCollector:
    """Tails one or more log files and calls the callback for each new line."""

    def __init__(self, paths: list[str], callback: Callable[[str, str], None], poll_interval: float = 5.0):
        self.paths = [Path(p) for p in paths]
        self.callback = callback
        self.poll_interval = poll_interval
        self._stop_event = Event()
        self._threads: list[Thread] = []

    def start(self):
        for path in self.paths:
            t = Thread(target=self._tail, args=(path,), daemon=True, name=f"tail-{path.name}")
            t.start()
            self._threads.append(t)
        logger.info("FileLogCollector started, watching %d file(s)", len(self.paths))

    def stop(self):
        self._stop_event.set()

    def _tail(self, path: Path):
        if not path.exists():
            logger.warning("Log file not found, will retry: %s", path)

        inode = None
        file_obj = None
        pos = 0

        while not self._stop_event.is_set():
            try:
                if not path.exists():
                    time.sleep(self.poll_interval)
                    continue

                stat = os.stat(path)
                current_inode = stat.st_ino

                if file_obj is None or current_inode != inode:
                    if file_obj:
                        file_obj.close()
                    file_obj = open(path, "r", errors="replace")
                    # Read last 200 lines on startup, then tail from there
                    file_obj.seek(0, 2)
                    end = file_obj.tell()
                    # Seek back ~16KB to get recent lines
                    file_obj.seek(max(0, end - 16384))
                    file_obj.readline()  # discard partial first line
                    pos = file_obj.tell()
                    inode = current_inode
                    logger.debug("Opened %s (inode %d)", path, inode)

                file_obj.seek(pos)
                for line in file_obj:
                    if line.endswith("\n") or line:
                        self.callback(line, str(path))
                pos = file_obj.tell()

            except Exception as e:
                logger.error("Error tailing %s: %s", path, e)
                file_obj = None

            time.sleep(self.poll_interval)

        if file_obj:
            file_obj.close()
