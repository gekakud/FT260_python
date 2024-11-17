import sys
import os

hidlib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hidapi/x64'))
sys.path.append(hidlib_path)

from ft260py import *

SLV_ADDR = 0x50
ft260_dev = PyFt260(VID=0x0403, PID=0x6030)
print(ft260_dev.get_i2c_status())
ft260_dev.print_device_info()
ft260_dev.set_i2c_speed(speed_hz=600000)
print(ft260_dev.get_i2c_status())

# write/read 1 byte as value test
ft260_dev.write_byte(address=SLV_ADDR, value=253)
ft260_dev.read_byte(SLV_ADDR, verbose=True)

for i in range(10):
    ft260_dev.write_byte_to_register(address=SLV_ADDR, register=0x5, value=i)
    ft260_dev.read_byte_from_register(SLV_ADDR, 0x5, verbose=True)

# write/read 2 bytes as value test
# 5002 is 0x138A
# 13 8A is 19 138
expected_value = 5002
ft260_dev.write_2bytes_to_register(SLV_ADDR, 0x5, expected_value)
actual_value = ft260_dev.read_2bytes_from_register(SLV_ADDR, 0x5, verbose=True)
if expected_value != actual_value:
    print("Error: 2 bytes read does not match 2 bytes written")
    raise Exception("Error: 2 bytes read does not match 2 bytes written")
ft260_dev.read_byte_from_register(SLV_ADDR, 0x5, verbose=True)
ft260_dev.read_byte_from_register(SLV_ADDR, 0x6, verbose=True)


# write/read 4 bytes as value test
# 496,666,671 is 1D 9A 88 2F
# 1D 9A 88 2F is 29 154 136 47
expected_value = 496666671
ft260_dev.write_4bytes_to_register(SLV_ADDR, 0x2, expected_value)
actual_value = ft260_dev.read_4bytes_from_register(SLV_ADDR, 0x2, verbose=True)
if expected_value != actual_value:
    print("Error: 4 bytes read does not match 4 bytes written")
    raise Exception("Error: 4 bytes read does not match 4 bytes written")

# ft260_dev.read_byte_from_register(SLV_ADDR, 0x2, verbose=True)
# ft260_dev.read_byte_from_register(SLV_ADDR, 0x3, verbose=True)
# ft260_dev.read_byte_from_register(SLV_ADDR, 0x4, verbose=True)
# ft260_dev.read_byte_from_register(SLV_ADDR, 0x5, verbose=True)

expected_value = 27987
ft260_dev.write_4bytes_to_register(SLV_ADDR, 0x2, expected_value)
actual_value = ft260_dev.read_4bytes_from_register(SLV_ADDR, 0x2, verbose=True)
if expected_value != actual_value:
    print("Error: 4 bytes read does not match 4 bytes written")
    raise Exception("Error: 4 bytes read does not match 4 bytes written")

# write/read sequence of bytes
# 0xa7 11 99 2f 33
test_bytes_to_write = bytes([0xa7, 0x11, 0x99, 0x2f, 0x33])
print(f'list:{list(test_bytes_to_write)}')
ft260_dev.write_bytes_to_register(SLV_ADDR, 0x2, test_bytes_to_write)
bytes_read = ft260_dev.read_bytes_from_register(SLV_ADDR, 0x2, len(test_bytes_to_write), verbose=True)
if test_bytes_to_write != bytes_read:
    print("Error: bytes read does not match bytes written")
    raise Exception("Error: bytes read does not match bytes written")

# test_bytes_to_write = bytes([0xa7, 0x11, 0x99, 0x2f, 0x33, 0x44, 0x41, 0x46, 0x24, 0x54, 0xA4, 0xC4, 0xF4, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0xb7, 0x21, 0x19, 0x5f, 0x23, 0xbb, 0xbc, 0xbd, 0xae, 0xf3])
# test_bytes_to_write = bytes([0xa7, 0x11, 0x99, 0x2f, 0x33, 0x44, 0x41, 0x46, 0xA1, 0x33])
test_bytes_to_write = bytes([0xa7, 0x11, 0x99, 0x2f, 0x33, 0x44, 0x41, 0x46])
print(f'list:{list(test_bytes_to_write)}')
ft260_dev.write_bytes_to_register(SLV_ADDR, 0x0, test_bytes_to_write)
bytes_read = ft260_dev.read_bytes_from_register(SLV_ADDR, 0x0, len(test_bytes_to_write), verbose=True)
# bytes_read = ft260_dev.read_bytes_from_register(SLV_ADDR, 0x0, 4, verbose=True)
# bytes_read = ft260_dev.read_bytes_from_register(SLV_ADDR, 0x4, 4, verbose=True)
# bytes_read = ft260_dev.read_bytes_from_register(SLV_ADDR, 0x2, 4, verbose=True)
if test_bytes_to_write != bytes_read:
    print("Error: bytes read does not match bytes written")
    raise Exception("Error: bytes read does not match bytes written")

print("All tests passed")