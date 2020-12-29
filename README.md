[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# Vasya Name Service

Temporary test realization of name service.

List of dependencies:

* ecdsa
* argparse
* sys

# Build

* Install [Python3](https://www.python.org/downloads/)
* Run `pip install ecdsa` or `pip3 install ecdsa` to install ECDSA
* Navigate the terminal to the directory where the script is located using the `$ cd` command.
* Type `python name_service.py --request_type` or `python3 name_service.py --request_type` with required request type in the terminal to execute the script.

# Argument types

| --request_type | Parameters | Sesult |
| --- | --- | --- |
|  ‎ record-set | --uid, --ipfs_link, --sig  | Status of operation |
|  ‎ record-get | --uid | Link | 
|  ‎ record-test | — | Test results | 