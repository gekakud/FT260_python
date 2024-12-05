import sys
import os

hidlib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hidapi/x64'))
sys.path.append(hidlib_path)

from ft260py import *
from hid import enumerate

VID=0x0403
PID=0x6030

devices = enumerate()
# path=b'\\\\?\\HID#VID_0403&PID_6030&MI_01#8&2e836aa1&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}'
path = ''
for device in devices:
    if device['vendor_id'] == VID and device['product_id'] == PID:
        print(f"Device Found: {device}")
        # Interface 1 is UART
        # Interface 0 is I2C
        if device['interface_number'] == 1:
            path = device['path']
            break

# Specify the path of the device
ft260_dev = Ft260py(VID=0x0403, PID=0x6030, path=path)
ft260_dev.set_uart_speed(baudrate=230400)

print(ft260_dev.get_uart_status())

ft260_dev.uart_always_read()
    