import sys
import os

hidlib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hidapi/x64'))
sys.path.append(hidlib_path)

from ft260py import *

ft260_dev = Ft260py(VID=0x0403, PID=0x6030)

print(ft260_dev.get_system_report())

ft260_dev.gpio_read()
ft260_dev.gpio_write()
ft260_dev.gpio_read()