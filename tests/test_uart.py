import pytest


def uart_reply(text):
    """Build a UART input report: [report_id, length, data...]."""
    data = text.encode()
    return bytes([0xF0, len(data)]) + data


def test_baud_rate_to_little_endian(ft260):
    assert ft260.baud_rate_to_little_endian(230400) == [0x00, 0x84, 0x03, 0x00]


@pytest.mark.parametrize('baud, expected', [
    (9600, [0x80, 0x25, 0x00, 0x00]),
    (19200, [0x00, 0x4B, 0x00, 0x00]),
    (230400, [0x00, 0x84, 0x03, 0x00]),
])
def test_set_uart_speed(ft260, dev, baud, expected):
    ft260.set_uart_speed(baud)
    assert dev.feature_writes == [bytes([0xA1, 0x42] + expected)]


@pytest.mark.parametrize('mode', [0, 1, 2, 3, 4])
def test_set_uart_mode(ft260, dev, mode):
    ft260.set_uart_mode(mode)
    assert dev.feature_writes == [bytes([0xA1, 0x03, mode])]


@pytest.mark.parametrize('mode', [-1, 5, 99])
def test_set_uart_mode_rejects_invalid(ft260, dev, mode):
    with pytest.raises(ValueError):
        ft260.set_uart_mode(mode)
    assert dev.feature_writes == []


def test_get_uart_status(ft260, dev):
    # flow_ctrl=4, 115200 baud, 8 data bits, even parity, 2 stop bits, no break
    dev.feature_reports[0xE0] = bytes([0xE0, 4, 0x00, 0xC2, 0x01, 0x00, 8, 2, 2, 0])
    assert ft260.get_uart_status() == {
        'report_id': 0xE0,
        'flow_ctrl': 4,
        'data_bit': 8,
        'parity': 2,
        'stop_bit': 2,
        'breaking': 0,
        'baud_rate': 115200,
    }


def test_uart_read_prints_text(ft260, dev, capsys):
    dev.read_queue.append(uart_reply('hello'))
    ft260.uart_read(64)
    assert 'TEXT response: hello' in capsys.readouterr().out
    assert dev.read_calls == [(64, 1)]


def test_uart_read_quiet_when_not_verbose(ft260, dev, capsys):
    dev.read_queue.append(uart_reply('hello'))
    ft260.uart_read(64, verbose=False)
    assert capsys.readouterr().out == ''


def _run_always_read(ft260, dev, chunks):
    """Feed chunks to uart_always_read; it stops when read() raises."""
    queue = list(chunks)

    def fake_read(size, timeout=None):
        if not queue:
            raise OSError('device closed')
        return queue.pop(0)

    dev.read = fake_read
    ft260.uart_always_read()


def test_uart_always_read_splits_messages_on_newline(ft260, dev, capsys):
    _run_always_read(ft260, dev, [uart_reply('one\ntwo\n')])
    out = capsys.readouterr().out
    assert 'UART output: one' in out
    assert 'UART output: two' in out


def test_uart_always_read_joins_partial_chunks(ft260, dev, capsys):
    _run_always_read(ft260, dev, [uart_reply('hel'), uart_reply('lo\n')])
    assert 'UART output: hello' in capsys.readouterr().out


def test_uart_always_read_waits_for_newline(ft260, dev, capsys):
    _run_always_read(ft260, dev, [uart_reply('no newline yet')])
    assert 'UART output' not in capsys.readouterr().out


def test_uart_always_read_stops_on_read_error(ft260, dev, capsys):
    _run_always_read(ft260, dev, [])
    assert 'Error reading from device' in capsys.readouterr().out
