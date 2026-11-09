import pytest

from ft260py import FLAG_STOP_AND_START

ADDR = 0x50


def read_reply(*data):
    """Build an I2C read input report: [report_id, length, data...]."""
    return bytes([0xD0, len(data), *data])


# ---------- configuration / status ----------

@pytest.mark.parametrize('speed_hz, lsb, msb', [
    (100_000, 0x64, 0x00),
    (400_000, 0x90, 0x01),
    (1_000_000, 0xE8, 0x03),
])
def test_set_i2c_speed(ft260, dev, speed_hz, lsb, msb):
    ft260.set_i2c_speed(speed_hz)
    assert dev.feature_writes == [bytes([0xA1, 0x22, lsb, msb])]


@pytest.mark.parametrize('speed_hz', [59_999, 3_400_001])
def test_set_i2c_speed_out_of_range_falls_back_to_100k(ft260, dev, speed_hz):
    ft260.set_i2c_speed(speed_hz)
    assert dev.feature_writes == [bytes([0xA1, 0x22, 0x64, 0x00])]


def test_reset_i2c(ft260, dev):
    ft260.reset_i2c()
    assert dev.feature_writes == [bytes([0xA1, 0x20])]


def test_get_i2c_status_decodes_flags_and_speed(ft260, dev):
    # bits: error(1), no_ack(2), controller_idle(5); speed 400 kHz
    dev.feature_reports[0xC0] = bytes([0xC0, 0b0010_0110, 0x90, 0x01, 0x00])
    status = ft260.get_i2c_status()
    assert status == {
        'controller_busy': False,
        'error_condition': True,
        'no_ack': True,
        'data_no_ack': False,
        'arbitration_lost': False,
        'controller_idle': True,
        'bus_busy': False,
        'baudrate_hz': 400_000,
    }


# ---------- writes ----------

def test_write_byte_to_register(ft260, dev):
    ft260.write_byte_to_register(ADDR, 0x05, 0xAB)
    assert dev.writes == [bytes([0xD0, ADDR, FLAG_STOP_AND_START, 2, 0x05, 0xAB])]


def test_write_byte_uses_register_zero(ft260, dev):
    ft260.write_byte(ADDR, 0x11)
    assert dev.writes == [bytes([0xD0, ADDR, FLAG_STOP_AND_START, 2, 0x00, 0x11])]


def test_write_2bytes_to_register_is_little_endian(ft260, dev):
    ft260.write_2bytes_to_register(ADDR, 0x05, 0x138A)
    assert dev.writes == [bytes([0xD0, ADDR, FLAG_STOP_AND_START, 3, 0x05, 0x8A, 0x13])]


def test_write_4bytes_to_register_is_little_endian(ft260, dev):
    ft260.write_4bytes_to_register(ADDR, 0x02, 0x1D9A882F)
    assert dev.writes == [
        bytes([0xD1, ADDR, FLAG_STOP_AND_START, 5, 0x02, 0x2F, 0x88, 0x9A, 0x1D])
    ]


@pytest.mark.parametrize('data', [
    [1, 2, 3],
    bytes([1, 2, 3]),
    bytearray([1, 2, 3]),
])
def test_write_bytes_to_register_accepts_list_bytes_bytearray(ft260, dev, data):
    ft260.write_bytes_to_register(ADDR, 0x02, data)
    assert dev.writes == [bytes([0xD8, ADDR, FLAG_STOP_AND_START, 4, 0x02, 1, 2, 3])]


def test_write_bytes_to_register_truncates_to_32(ft260, dev):
    ft260.write_bytes_to_register(ADDR, 0x00, list(range(40)))
    sent = dev.writes[0]
    assert sent[3] == 33               # register + 32 data bytes
    assert list(sent[5:]) == list(range(32))


def test_write_bytes_to_register_rejects_bad_type(ft260):
    with pytest.raises(ValueError):
        ft260.write_bytes_to_register(ADDR, 0x00, 'abc')


def test_i2c_master_write(ft260, dev):
    written = ft260.i2c_master_write(ADDR, [0xAA, 0xBB])
    assert written == 2
    assert dev.writes == [bytes([0xD8, ADDR, FLAG_STOP_AND_START, 2, 0xAA, 0xBB])]


def test_i2c_master_write_truncates_to_32(ft260, dev):
    assert ft260.i2c_master_write(ADDR, bytes(40)) == 32


def test_i2c_master_write_rejects_bad_type(ft260):
    with pytest.raises(ValueError):
        ft260.i2c_master_write(ADDR, 123)


# ---------- reads ----------

def test_read_byte_from_register_sends_pointer_then_read_request(ft260, dev):
    dev.read_queue.append(read_reply(0x42))
    assert ft260.i2c_read_byte_from_register(ADDR, 0x05) == 0x42
    assert dev.writes == [
        bytes([0xD0, ADDR, FLAG_STOP_AND_START, 1, 0x05]),   # set register pointer
        bytes([0xC2, ADDR, FLAG_STOP_AND_START, 1, 0]),      # read request, 1 byte
    ]


def test_read_byte_uses_register_zero(ft260, dev):
    dev.read_queue.append(read_reply(0x7F))
    assert ft260.i2c_read_byte(ADDR) == 0x7F
    assert dev.writes[0] == bytes([0xD0, ADDR, FLAG_STOP_AND_START, 1, 0x00])


def test_read_2bytes_from_register_is_little_endian(ft260, dev):
    dev.read_queue.append(read_reply(0x8A, 0x13))
    assert ft260.i2c_read_2bytes_from_register(ADDR, 0x05) == 0x138A


def test_read_4bytes_from_register_is_little_endian(ft260, dev):
    dev.read_queue.append(read_reply(0x2F, 0x88, 0x9A, 0x1D))
    assert ft260.i2c_read_4bytes_from_register(ADDR, 0x02) == 0x1D9A882F


def test_read_bytes_from_register_returns_payload(ft260, dev):
    data = [0xA7, 0x11, 0x99, 0x2F, 0x33]
    dev.read_queue.append(read_reply(*data))
    assert ft260.i2c_read_bytes_from_register(ADDR, 0x02, len(data)) == bytes(data)


def test_read_bytes_from_register_8_or_more_uses_16bit_length(ft260, dev):
    data = list(range(10))
    dev.read_queue.append(read_reply(*data))
    assert ft260.i2c_read_bytes_from_register(ADDR, 0x00, 10) == bytes(data)
    assert dev.writes[1][:5] == bytes([0xC2, ADDR, FLAG_STOP_AND_START, 10, 0])


def test_i2c_master_read_short(ft260, dev):
    dev.read_queue.append(read_reply(1, 2, 3))
    assert ft260.i2c_master_read(ADDR, 3) == bytes([1, 2, 3])
    assert dev.writes == [bytes([0xC2, ADDR, FLAG_STOP_AND_START, 3, 0])]


def test_i2c_master_read_uses_length_from_reply(ft260, dev):
    dev.read_queue.append(read_reply(1, 2) + b'\x00' * 10)   # trailing padding
    assert ft260.i2c_master_read(ADDR, 2) == bytes([1, 2])


def test_i2c_master_read_8_or_more_uses_16bit_length(ft260, dev):
    data = list(range(8))
    dev.read_queue.append(read_reply(*data))
    assert ft260.i2c_master_read(ADDR, 8) == bytes(data)
    assert dev.writes[0][:5] == bytes([0xC2, ADDR, FLAG_STOP_AND_START, 8, 0])
