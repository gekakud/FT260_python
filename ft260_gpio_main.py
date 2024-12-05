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
# ft260_dev.select_gpioG_function(function=2)

# ft260_dev.gpio_write_all(0x00)
# time.sleep(1)
# ft260_dev.gpio_write_all()

# FT260_Tx -> Sabre_Rx - not in use
ft260_dev.gpio_init(GpioEx.PD, GpioDir.OUTPUT)
print(ft260_dev.gpio_read(GpioEx.PD))
ft260_dev.gpio_write(GpioEx.PD, GpioValue.HIGH)
print(ft260_dev.gpio_read(GpioEx.PD))
time.sleep(1)
ft260_dev.gpio_write(GpioEx.PD, GpioValue.LOW)
print(ft260_dev.gpio_read(GpioEx.PD))

# FT260_Rx <- Sabre_Tx
# ft260_dev.gpio_init(GpioEx.PC, GpioDir.OUTPUT)
# print(ft260_dev.gpio_read(GpioEx.PC))
# ft260_dev.gpio_write(GpioEx.PC, GpioValue.HIGH)
# print(ft260_dev.gpio_read(GpioEx.PC))
# time.sleep(1)
# ft260_dev.gpio_write(GpioEx.PC, GpioValue.LOW)
# print(ft260_dev.gpio_read(GpioEx.PC))