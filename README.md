# FT260py Library README
[![tests](https://github.com/gekakud/FT260_python/actions/workflows/tests.yml/badge.svg)](https://github.com/gekakud/FT260_python/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)

## Overview
The FT260py library is a Python wrapper for the FTDI FT260 controller, supporting both I²C and UART communication protocols. It provides high-level methods to interact with connected devices using the HID protocol. The library simplifies tasks such as configuring the FT260, setting communication parameters, and performing read/write operations with connected peripherals.
The library simplifies tasks such as configuring the FT260, setting I²C speed, and performing read/write operations with connected I²C slave devices. Same for UART.

This library is built on the hid module, which interfaces with the hidapi library for HID communication.

## Features
- Initialize and configure the FT260 device.
- Read and write data to/from I²C slave devices.
- Support for single-byte, multi-byte, and register-based I²C operations.
- Get I²C bus status and error handling.
- Reset and configure I²C speed dynamically.
- Receive data over UART.
- Support for handling newline-terminated messages.
- Init, Read, Write GPIO pins
## Requirements
- Python 3.10 or later
- FTDI FT260 device
- hidapi library (included via the hid module)
## Installation
Install the hidapi Python wrapper:

```bash
pip install -r requirements.txt
```
### Usage example
Initialize the Library
```python
from ft260py import Ft260py, Gpio, GpioEx, GpioDir, GpioValue
```

Create an instance with Vendor ID (VID) and Product ID (PID)
```python
ft260 = Ft260py(VID=0x0403, PID=0x6030)
```
Print Device Information
```python
ft260.print_device_info()
```
Configure I²C Speed. Set the I²C clock speed (in Hz):
```python
ft260.set_i2c_speed(speed_hz=100000)  # Set speed to 100 kHz
```
I²C read / write (slave address 0x50, register 0x05)
```python
ft260.write_byte_to_register(address=0x50, register=0x05, value=42)
value = ft260.i2c_read_byte_from_register(0x50, 0x05)
```
UART. Set the baud rate and read incoming lines (the UART is HID interface 1, so pass its `path`, see `ft260_uart_main.py`):
```python
ft260.set_uart_speed(baudrate=230400)
ft260.uart_always_read()
```
GPIO. Switch the UART pins to GPIO first, then set direction, write and read:
```python
ft260.set_uart_mode(mode=0)
ft260.gpio_init(GpioEx.PD, GpioDir.OUTPUT)
ft260.gpio_write(GpioEx.PD, GpioValue.HIGH)
print(ft260.gpio_read(GpioEx.PD))
```

## Example scripts
- `ft260_i2c_main.py` - I²C write/read self-test
- `ft260_uart_main.py` - UART line reader
- `ft260_gpio_main.py` - GPIO toggle demo

## Tests
The unit tests use a fake HID device, so no hardware is needed:
```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Contributing
Pull requests are welcome! Bug fixes, new FT260 features, tests, and docs are all appreciated. For larger changes, please open an issue first to discuss the idea. Please run the tests before opening a PR.

## License
MIT - see [LICENSE](LICENSE).
