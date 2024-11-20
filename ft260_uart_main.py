import sys
import os

hidlib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hidapi/x64'))
sys.path.append(hidlib_path)

from ft260py import *
from hid import enumerate

VID=0x0403
PID=0x6030

devices = enumerate()
for device in devices:
    if device['vendor_id'] == VID and device['product_id'] == PID:
        print(f"Device Found: {device}")


ft260_dev = Ft260py(VID=0x0403, PID=0x6030)
# ft260_dev.set_uart_speed(baudrate=230400)
ft260_dev.uart_always_read()
    