import sys
import os

hidlib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hidapi/x64'))
sys.path.append(hidlib_path)

from ft260py import *

SLV_ADDR = 0x50
ft260_dev = Ft260py(VID=0x0403, PID=0x6030)

print(ft260_dev.get_uart_status())

