import sys
import os
import time

hidlib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hidapi/x64'))
sys.path.append(hidlib_path)

from ft260py import *

# Specify the path of the device
ft260_dev = Ft260py(VID=0x0403, PID=0x6030)

print(ft260_dev.get_system_report())
# switch UART pins to GPIO
ft260_dev.set_uart_mode(mode=0)

print(ft260_dev.gpio_read(GpioEx.PD))
ft260_dev.gpio_write(GpioEx.PD, GpioValue.HIGH)
print(ft260_dev.gpio_read(GpioEx.PD))
time.sleep(1)
ft260_dev.gpio_write(GpioEx.PD, GpioValue.LOW)
print(ft260_dev.gpio_read(GpioEx.PD))

