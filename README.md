# FT260py Library README
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
## Requirements
- Python 3.6 or later
- FTDI FT260 device
- hidapi library (included via the hid module)
## Installation
Install the hidapi Python wrapper:

```bash
pip install hid
```
### Usage example
Initialize the Library
```python
from ft260py import FT260py
```

Create an instance with Vendor ID (VID) and Product ID (PID)
```python
ft260 = FT260py(VID=0x0403, PID=0x6030)
```
Print Device Information
```python
ft260.print_device_info()
```
Configure I²C Speed. Set the I²C clock speed (in Hz):
```python
ft260.set_i2c_speed(speed_hz=100000)  # Set speed to 100 kHz
```
