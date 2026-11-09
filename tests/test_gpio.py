import pytest

from ft260py import Gpio, GpioEx, GpioDir, GpioValue


def set_gpio_report(dev, values=0, dirs=0, ex_values=0, ex_dirs=0):
    dev.feature_reports[0xB0] = bytes([0xB0, values, dirs, ex_values, ex_dirs])


def test_gpio_read_all_data_decodes_every_pin(ft260, dev):
    set_gpio_report(dev, values=0b0101, dirs=0b0011, ex_values=0b1000_0001, ex_dirs=0b1111_0000)
    data = ft260.gpio_read_all_data()

    assert len(data) == len(Gpio) + len(GpioEx)
    assert data['P0'] == {'value': GpioValue.HIGH, 'direction': GpioDir.OUTPUT}
    assert data['P1'] == {'value': GpioValue.LOW, 'direction': GpioDir.OUTPUT}
    assert data['P2'] == {'value': GpioValue.HIGH, 'direction': GpioDir.INPUT}
    assert data['P3'] == {'value': GpioValue.LOW, 'direction': GpioDir.INPUT}
    assert data['PA'] == {'value': GpioValue.HIGH, 'direction': GpioDir.INPUT}
    assert data['PH'] == {'value': GpioValue.HIGH, 'direction': GpioDir.OUTPUT}
    assert data['PD'] == {'value': GpioValue.LOW, 'direction': GpioDir.INPUT}


def test_gpio_read_returns_single_pin(ft260, dev):
    set_gpio_report(dev, ex_values=0b0000_1000, ex_dirs=0b0000_1000)
    assert ft260.gpio_read(GpioEx.PD) == {'value': GpioValue.HIGH, 'direction': GpioDir.OUTPUT}


def test_gpio_init_sets_ex_direction_bit_only(ft260, dev):
    set_gpio_report(dev, values=0x0F, dirs=0x01, ex_values=0xAA, ex_dirs=0b0000_0001)
    ft260.gpio_init(GpioEx.PD, GpioDir.OUTPUT)
    assert dev.feature_writes == [bytes([0xB0, 0x0F, 0x01, 0xAA, 0b0000_1001])]


def test_gpio_init_clears_ex_direction_bit(ft260, dev):
    set_gpio_report(dev, ex_dirs=0xFF)
    ft260.gpio_init(GpioEx.PC, GpioDir.INPUT)
    assert dev.feature_writes == [bytes([0xB0, 0x00, 0x00, 0x00, 0b1111_1011])]


def test_gpio_init_sets_gpio_direction_bit_only(ft260, dev):
    set_gpio_report(dev, values=0x05, dirs=0b0001, ex_values=0x10, ex_dirs=0x20)
    ft260.gpio_init(Gpio.P2, GpioDir.OUTPUT)
    assert dev.feature_writes == [bytes([0xB0, 0x05, 0b0101, 0x10, 0x20])]


def test_gpio_write_sets_ex_value_bit_only(ft260, dev):
    set_gpio_report(dev, values=0x03, dirs=0x0F, ex_values=0b0000_0001, ex_dirs=0xFF)
    ft260.gpio_write(GpioEx.PD, GpioValue.HIGH)
    assert dev.feature_writes == [bytes([0xB0, 0x03, 0x0F, 0b0000_1001, 0xFF])]


def test_gpio_write_clears_ex_value_bit(ft260, dev):
    set_gpio_report(dev, ex_values=0xFF)
    ft260.gpio_write(GpioEx.PA, GpioValue.LOW)
    assert dev.feature_writes == [bytes([0xB0, 0x00, 0x00, 0b1111_1110, 0x00])]


def test_gpio_write_sets_gpio_value_bit(ft260, dev):
    set_gpio_report(dev, values=0b0001, dirs=0b1111)
    ft260.gpio_write(Gpio.P3, GpioValue.HIGH)
    assert dev.feature_writes == [bytes([0xB0, 0b1001, 0b1111, 0x00, 0x00])]


@pytest.mark.parametrize('call', ['gpio_init', 'gpio_write'])
def test_invalid_port_raises_and_writes_nothing(ft260, dev, call):
    set_gpio_report(dev)
    with pytest.raises(ValueError):
        getattr(ft260, call)(99, GpioDir.OUTPUT if call == 'gpio_init' else GpioValue.HIGH)
    assert dev.feature_writes == []


@pytest.mark.parametrize('function', [0, 2, 5, 6])
def test_select_gpioG_function(ft260, dev, function):
    ft260.select_gpioG_function(function)
    assert dev.feature_writes == [bytes([0xA1, 0x09, function])]


@pytest.mark.parametrize('function', [1, 3, 7])
def test_select_gpioG_function_rejects_invalid(ft260, dev, function):
    with pytest.raises(ValueError):
        ft260.select_gpioG_function(function)
    assert dev.feature_writes == []
