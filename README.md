<div align="center">

# pymanuf

[![Discord Server Badge](https://img.shields.io/discord/1358456011316396295?logo=discord)](https://discord.gg/xj6y5ZaTMr)
[![PyPi Badge](https://img.shields.io/pypi/v/pymanuf.svg)](https://pypi.org/p/pymanuf)
[![PyPi Supported Versions Badge](https://img.shields.io/pypi/pyversions/pymanuf.svg)](https://pypi.org/p/pymanuf)
[![CI Badge](https://github.com/kkrypt0nn/pymanuf/actions/workflows/ci.yml/badge.svg)](https://github.com/kkrypt0nn/pymanuf/actions)

[![Last Commit Badge](https://img.shields.io/github/last-commit/kkrypt0nn/pymanuf)](https://github.com/kkrypt0nn/pymanuf/commits/main)
[![Conventional Commits Badge](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org/en/v1.0.0/)

</div>

---

A very simple Python library to get the manufacturer of a specific MAC address

## Getting Started

### Installation

If you want to use this library for one of your projects, you can install it like any other Python library

```bash
python -m pip install pymanuf
```

### Versioning

The versioning of the library is the following: `YYYY.MM.DD` where the leading `0` is **removed**.

Versions are automatically released every month on the first day of that month.

### Example Usage

#### Offline Lookup (preferred)

```python
from pymanuf import lookup

try:
    manuf = lookup("C4:A8:1D:73:D7:8C")
    print(f"Manufacturer: {manuf}")
except Exception as e:
    print(f"Error: {e}")
```

#### Online Lookup

```python
from pymanuf.online import lookup

try:
    manuf = lookup("C4:A8:1D:73:D7:8C")
    print(f"Manufacturer: {manuf}")
except Exception as e:
    print(f"Error: {e}")
```

## Troubleshooting

If you have problems using the library, you can open up an [issue](https://github.com/kkrypt0nn/pymanuf/issues) or join my [Discord server](https://discord.gg/xj6y5ZaTMr).

## Contributing

People may contribute by following the [Contributing Guidelines](./CONTRIBUTING.md) and
the [Code of Conduct](./CODE_OF_CONDUCT.md)

## License

This library was made with 💜 by Krypton and is under the [MIT License](./LICENSE.md).
