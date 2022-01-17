# MIT License

# Copyright (c) 2022 BlackMirage

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

#!/usr/bin/python3

# Stdlib
from socket import inet_aton, error as socket_error

# Remote
from nmap3 import NmapScanTechniques

# Local
import config


def convert_to_es(scan_results) -> dict:
    data = {}
    keys = list(scan_results.keys())
    if config.IP not in keys:
        return data
    if 'ports' not in scan_results[config.IP]:
        return data
    data = scan_results
    data['scan_results'] = scan_results[config.IP]
    data['host'] = {}
    data['host']['ip'] = config.IP
    data.pop(config.IP)
    return data


def scan() -> tuple[dict, dict]:
    scanner = NmapScanTechniques()
    tcp_ports = ','.join([str(port) for port in config.TCP_PORTS])
    tcp_results = {}
    if not config.IP:
        return tcp_results
    if config.TCP_PORTS:
        tcp_results.update(scanner.nmap_tcp_scan(config.IP, args='-p {}'.format(tcp_ports)))
    return tcp_results


def validate_config() -> None:
    # Validate on Host field
    try:
        inet_aton(config.IP) # IP is valid
    except socket_error:
        print("Error: Config's host IP address is incorrect.")
        exit(1)
    # Validate ports
    for port in config.TCP_PORTS:
        if isinstance(port, int):
            if port > 0 and port < 65536:
                continue
            else:
                print("Error: one of more TCP ports is <1 or >65535")
                exit(1)
        else:
            print("Error: one or more TCP ports not an integer.")
            exit(1)


def main():
    # Validation on config fields
    validate_config()

    # Scan using config
    tcp_results = scan()

    # Convert to a format that works better with ElasticSearch
    tcp_results = convert_to_es(tcp_results)
    print(tcp_results)


if __name__ == '__main__':
    main()
