import sys
import types

import pytest


class FakeDevice:
    """Stand-in for hid.Device: records outgoing data, returns queued replies."""

    def __init__(self, vid=0, pid=0, path=None):
        self.vid = vid
        self.pid = pid
        self.path = path
        self.manufacturer = 'FTDI'
        self.product = 'FT260'
        self.writes = []            # data passed to write()
        self.feature_writes = []    # data passed to send_feature_report()
        self.feature_reports = {}   # report_id -> bytes returned by get_feature_report()
        self.read_queue = []        # bytes returned by read(), in order
        self.read_calls = []        # (size, timeout) per read() call

    def write(self, data):
        self.writes.append(bytes(data))
        return len(data)

    def send_feature_report(self, data):
        self.feature_writes.append(bytes(data))
        return len(data)

    def get_feature_report(self, report_id, size):
        return self.feature_reports[report_id]

    def read(self, size, timeout=None):
        self.read_calls.append((size, timeout))
        return self.read_queue.pop(0) if self.read_queue else b''


# Replace the real hid module so tests run without hidapi or hardware.
_fake_hid = types.ModuleType('hid')
_fake_hid.Device = FakeDevice
_fake_hid.enumerate = lambda *args, **kwargs: []
sys.modules['hid'] = _fake_hid


@pytest.fixture
def ft260(monkeypatch):
    import ft260py
    monkeypatch.setattr(ft260py.time, 'sleep', lambda _s: None)
    return ft260py.Ft260py(VID=0x0403, PID=0x6030)


@pytest.fixture
def dev(ft260):
    return ft260.device
