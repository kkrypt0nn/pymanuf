from pymanuf import lookup

try:
    manuf = lookup("C4:A8:1D:73:D7:8C")
    print(f"Manufacturer: {manuf}")
except Exception as e:
    print(f"Error: {e}")
