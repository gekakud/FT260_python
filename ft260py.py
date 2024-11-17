import sys, os, time
hidlib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hidapi/x64'))
sys.path.append(hidlib_path)
import hid


version = '1.0.0'
# FTDI User Guide https://www.ftdichip.cn/Support/Documents/AppNotes/AN_394_User_Guide_for_FT260.pdf

class PyFt260():
    ''' Python wrapper for the FTDI FT260 I²C master controller '''
    def __init__(self, VID=0, PID=0):
        self.VID = VID
        self.PID = PID
        self.device = hid.Device(vid=VID, pid=PID)

    def print_device_info(self):
        ''' Print device information '''
        print(f'Vendor ID: {hex(self.VID)} (Hex: {hex(self.VID)}, Decimal: {self.VID})')
        print(f'Product ID: {hex(self.PID)} (Hex: {hex(self.PID)}, Decimal: {self.PID})')

        print(f'Device manufacturer: {self.device.manufacturer}')
        print(f'Product Name: {self.device.product}')


    def get_i2c_status(self) -> dict:
        ''' Get I2C status '''
        # Offset Field Description
        # Byte 0 Report ID 0xC0
        # Byte 1 bus status I2C bus status:
        #  bit 0 = controller busy: all other status bits invalid
        #  bit 1 = error condition
        #  bit 2 = slave address was not acknowledged during last 
        # operation
        #  bit 3 = data not acknowledged during last operation
        #  bit 4 = arbitration lost during last operation
        #  bit 5 = controller idle
        #  bit 6 = bus busy
        # Byte 2 speed_LSB The speed of I2C transmission. It ranges from 60K bps to 3400K bps. 
        # Clock Speed is the frequency of the I²C bus clock in kilohertz (kHz).
        # It’s a two-byte number
        # Byte 3 speed_MSB
        # Byte 4 reserved reserved

        report = self.device.get_feature_report(0xC0, 100)

        # Bit definitions for I²C status byte
        status_flags = {
            'controller_busy': 0,
            'error_condition': 1,
            'no_ack': 2,
            'data_no_ack': 3,
            'arbitration_lost': 4,
            'controller_idle': 5,
            'bus_busy': 6
        }

        # Extract each status flag from byte 1 of the report
        i2c_status = {
            flag: bool(report[1] & (1 << bit))
            for flag, bit in status_flags.items()
        }

        # Calculate baud rate from LSB and MSB of the speed in bytes 2 and 3
        baudrate_khz = (report[2] | report[3] << 8) * 1000  # Convert to Hz
        i2c_status['baudrate_hz'] = baudrate_khz

        return i2c_status

    def reset_i2c(self):
        ''' Reset I2C master controller '''
        # Offset Field Description
        # Byte 0 Report ID 0xA1
        # Byte 1 request 0x20: I²C Reset
        # The request will reset the I2C master controller.

        print('Resetting I2C...')
        self.device.send_feature_report([0xA1, 0x20])
        
    def set_i2c_speed(self, speed_hz:int = 100000):
        ''' Set I²C speed in Hertz (Hz). Range: 60000 Hz to 3400000 Hz '''
        # Offset Field Description
        # Byte 0 Report ID 0xA1
        # Byte 1 request 0x22: Set I²C Clock Speed
        # Byte 2 speed_LSB The speed of I2C clock, whose range is from 60K bps to 3400K bps.
        # Byte 3 speed_MSB
        # Clock Speed is the frequency of the I²C bus clock in kilohertz (KHz). It’s a two-byte number. For 
        # example, if the target clock speed is 100K, the LSB will be 0x64 and the MSB will be 0x00. If the 
        # target clock speed is 1000K (1M), the LSB will be 0xE8 and the MSB will be 0x03. If the given 
        # clock speed is not supported, the clock speed will fallback to 100K.

        # Validate speed range
        if speed_hz < 60000 or speed_hz > 3400000:
            print("Unsupported I²C clock speed; falling back to 100KHz (100000 Hz)")
            speed_hz = 100000  # fallback speed if out of range

        speed_khz = speed_hz // 1000
        # Calculate LSB and MSB of speed in kilohertz
        LSB = speed_khz & 0xFF  # Least Significant Byte
        MSB = (speed_khz >> 8) & 0xFF  # Most Significant Byte

        # Debug output in both Hz and hex
        print(f"Setting I²C clock speed to {speed_hz} Hz (LSB: {hex(LSB)}, MSB: {hex(MSB)})")

        # Construct data packet
        data_bytes = bytes([0xA1, 0x22, LSB, MSB])
        self.device.send_feature_report(data_bytes)

    def write_byte(self, address:int, value:int) -> None:
        ''' Write a single byte to I²C device '''
        self.write_byte_to_register(address, 0, value)

    def write_byte_to_register(self, address:int, register:int, value:int) -> None:
        ''' Write a single byte to a register on an I²C device '''
        # Offset Field Description
        # Byte 0 Report ID 0xD0 – 0xDE
        # The report ID determines the length of the data payload, in multiples 
        # of 4 bytes.
        # 0xD0 : maximum data size is 4 bytes
        # 0xD1 : maximum data size is 8 bytes
        # 0xD2 : maximum data size is 12 bytes
        # ...
        # 0xDE : maximum data size is 60 bytes
        # Byte 1 slaveAddr The address (7-bit) of the I²C slave device
        # Byte 2 flag The I²C condition to be sent with this I2C transaction:
        #  0: None
        #  0x02: START
        #  0x03: Repeated_START
        # Repeated_START will not send master code in HS mode
        #  0x04: STOP
        #  0x06: START_AND_STOP
        # Byte 3 length The length of valid data of payload. 
        # Byte 4 to
        # Byte 63
        # data The data payload. 
        # The maximum size of the data payload is determined by the report 
        # ID: (Report ID - 0xD0 + 1) * 4 bytes.

        # Data Interpretation by the Slave: The slave device understands the first byte after receiving the slave address as the register it should write to. 
        # This is not something the FT260 enforces or understands; it’s simply a matter of following the protocol that the specific slave device expects.
        payload = bytes([0xD0, address, 0x06, 2, register, value])
        self.device.write(payload)

    def write_2bytes_to_register(self, address:int, register:int, value:int):
        ''' Write two bytes to a register on an I²C device '''
        # Offset Field Description
        # Byte 0 Report ID 0xD0 – 0xDE
        # The report ID determines the length of the data payload, in multiples 
        # of 4 bytes.
        # 0xD0 : maximum data size is 4 bytes
        # 0xD1 : maximum data size is 8 bytes
        # 0xD2 : maximum data size is 12 bytes
        # ...
        # 0xDE : maximum data size is 60 bytes
        # Byte 1 slaveAddr The address (7-bit) of the I²C slave device
        # Byte 2 flag The I²C condition to be sent with this I2C transaction:
        #  0: None
        #  0x02: START
        #  0x03: Repeated_START
        # Repeated_START will not send master code in HS mode
        #  0x04: STOP
        #  0x06: START_AND_STOP
        # Byte 3 length The length of valid data of payload. 
        # Byte 4 to
        # Byte 63
        # data The data payload. 
        # The maximum size of the data payload is determined by the report 
        # ID: (Report ID - 0xD0 + 1) * 4 bytes.

        # Data Interpretation by the Slave: The slave device understands the first byte after receiving the slave address as the register it should write to. 
        # This is not something the FT260 enforces or understands; it’s simply a matter of following the protocol that the specific slave device expects.

        # Extract each byte from the 4-byte integer in little-endian order
        byte_0 = (value) & 0xFF            # Least significant byte
        byte_1 = (value >> 8) & 0xFF       # Next byte
        payload = bytes([0xD0, address, 0x06, 3, register, byte_0, byte_1])
        self.device.write(payload)

    def write_4bytes_to_register(self, address:int, register:int, value:int):
        # Extract each byte from the 4-byte integer in little-endian order
        byte_0 = (value) & 0xFF            # Least significant byte
        byte_1 = (value >> 8) & 0xFF       # Next byte
        byte_2 = (value >> 16) & 0xFF      # Third byte
        byte_3 = (value >> 24) & 0xFF      # Most significant byte
        payload = bytes([0xD1, address, 0x06, 5, register, byte_0, byte_1, byte_2, byte_3])
        self.device.write(payload)

    def write_bytes_to_register(self, address:int, register:int, data_bytes:bytes | list | bytearray):
        ''' Write a sequence of bytes to a register on an I²C device  - Maximum 32 bytes
            if the data_bytes is more than 32 bytes, it will be truncated to 32 bytes '''
        input_type = type(data_bytes)
        #  if input type is not one of the expected types, convert to list of bytes
        if input_type != bytes and input_type != bytearray and input_type != list:
            print(f'Invalid data type: {input_type}. Expected types: list, bytearray, bytes')
            raise ValueError(f'Invalid data type: {input_type}. Expected types: list, bytearray, bytes')
            
        if input_type != list:
            #  convert to list of bytes
            data_bytes = list(data_bytes)

        if len(data_bytes) > 32:
            print("Data bytes is more than 32 bytes, truncating to 32 bytes")
            data_bytes = data_bytes[:32]
        payload = bytes([0xD8, address, 0x06, len(data_bytes) + 1, register] + data_bytes)
        self.device.write(payload)

    def read_from_register(self, address:int, register:int, length:int):
        ''' Read a specified number of bytes from a register on an I²C device :
            # Byte 0 Report ID 0xD0 - 0xDE
            # The actual value depends on the length of the data payload.
            # Byte 1 length The length of valid data of payload.
            # Byte 2 to Byte 63 The data payload
        '''
        # specify the register by first writing to the slave device before initiating a read
        BYTES_TO_READ = length
        specify_register = bytes([0xD0, address, 0x06, 1, register])
        time.sleep(0.005)
        self.device.write(specify_register)
        time.sleep(0.001)
        # Send an I²C read request
        # Offset Field Description
        # Byte 0 Report ID 0xC2
        # Byte 1 slaveAddr The address (7-bit) of the I²C slave device 
        # Byte 2 flag The I2C condition will be sent with this I2C transaction
        #  0: None
        #  0x02: START
        #  0x03: Repeated_START
        # Repeated_START will not send master code in HS mode
        #  0x04: STOP
        #  0x06: START_AND_STOP
        # Byte 3 and byte 4
        # length The number of bytes requested from the slave device.
        # The byte order is little endian.

        read_code = 0xD0
        if BYTES_TO_READ >= 8:
            read_code = 0xDE
            BYTES_TO_READ = (BYTES_TO_READ).to_bytes(2, byteorder='little')
                                               # byte3           # byte4
            send = bytes([0xC2, address, 0x06, BYTES_TO_READ[0], BYTES_TO_READ[1], 0])
        else:
                                               # byte3 + # byte4
            send = bytes([0xC2, address, 0x06, BYTES_TO_READ, 0])
            
                                           
        self.device.write(send)

        # Read the response from the device
        # Offset Field Description
        # Byte 0 Report ID 0xD0 – 0xDE
        # The actual value depends on the length of the data payload.
        # Byte 1 length The length of valid data of payload.
        # Byte 2 to
        # Byte 63
        # data The data payload
        time.sleep(0.001)
        raw_response = self.device.read(read_code)
        return raw_response

    def read_byte(self, address, verbose:bool = False) -> int:
        ''' Read a single byte from I²C device '''
        response = self.read_byte_from_register(address, 0, verbose)
        return response

    def read_byte_from_register(self, address:int, register:int, verbose:bool = False) -> int:
        ''' Read a single byte from a register on an I²C device '''
        response = self.read_from_register(address, register, length=1)

        if verbose:
            print(f"Report ID: {hex(response[0])} (Hex: {hex(response[0])}, Decimal: {response[0]})")
            print(f"Length of valid data: {hex(response[1])} (Hex: {hex(response[1])}, Decimal: {response[1]})")
            print(f"DATA response: {hex(response[2])} (Hex: {hex(response[2])}, Decimal: {response[2]})")
        return response[2]

    def read_2bytes_from_register(self, address:int, register:int, verbose:bool = False) -> int:
        ''' Read a single byte from a register on an I²C device '''
        response = self.read_from_register(address, register, length=2)

        # Big-endian (index 2 is the most significant byte)
        two_bytes_value_big_endian = (response[2] << 8) | response[3]
        # Little-endian (index 2 is the least significant byte)
        two_bytes_value_little_endian = response[2] | (response[3] << 8)

        if verbose:
            print(f"Report ID: {hex(response[0])} (Hex: {hex(response[0])}, Decimal: {response[0]})")
            print(f"Length of valid data: {hex(response[1])} (Hex: {hex(response[1])}, Decimal: {response[1]})")
            print(f"DATA response: {hex(two_bytes_value_little_endian)} (Hex: {hex(two_bytes_value_little_endian)}, Decimal: {two_bytes_value_little_endian})")
        return two_bytes_value_little_endian

    def read_4bytes_from_register(self, address:int, register:int, verbose:bool = False) -> int:
        ''' Read a single byte from a register on an I²C device '''
        response = self.read_from_register(address, register, length=4)

        # Construct a 4-byte integer in little-endian order
        four_bytes_value_little_endian = response[2] | (response[3] << 8) | (response[4] << 16) | (response[5] << 24)

        if verbose:
            print(f"Report ID: {hex(response[0])} (Hex: {hex(response[0])}, Decimal: {response[0]})")
            print(f"Length of valid data: {hex(response[1])} (Hex: {hex(response[1])}, Decimal: {response[1]})")
            print(f"DATA response: {hex(four_bytes_value_little_endian)} (Hex: {hex(four_bytes_value_little_endian)}, Decimal: {four_bytes_value_little_endian})")
        return four_bytes_value_little_endian

    def read_bytes_from_register(self, address:int, register:int, length:int, verbose:bool = False) -> bytes:
        ''' Read a specified number of bytes from a register on an I²C device '''
        response = self.read_from_register(address, register, length=length)
        # reverse order of bytes to read in same order as written
        data_bytes = response[2:2+length]
        data_bytes_list = list(data_bytes)
        if verbose:
            print(f"Report ID: {hex(response[0])} (Hex: {hex(response[0])}, Decimal: {response[0]})")
            print(f"Length of valid data: {hex(response[1])} (Hex: {hex(response[1])}, Decimal: {response[1]})")
            print(f"DATA response: {data_bytes} (List of Decimal: {data_bytes_list})")

        return data_bytes
    