import serial
from pyubx2 import UBXReader

ser = serial.Serial('COM3', 9600, 8, 'N', 1)

#test