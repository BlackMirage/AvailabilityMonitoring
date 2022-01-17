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

from nmap3 import NmapScanTechniques

import config


def scan() -> dict:
    scanner = NmapScanTechniques()
    tcp_ports = ','.join([str(port) for port in config.TCP_PORTS])
    udp_ports = ','.join([str(port) for port in config.UDP_PORTS])
    tcp_results = {}
    udp_results = {}
    if not config.HOST:
        return tcp_results, udp_results
    if config.TCP_PORTS:
        tcp_results.update(scanner.nmap_tcp_scan(config.HOST, args='-p {}'.format(tcp_ports)))
    if config.UDP_PORTS:
        udp_results.update(scanner.nmap_udp_scan(config.HOST, args='-p {}'.format(udp_ports)))
    return tcp_results, udp_results


def main():
    # Scan using config
    scan_results = scan()
    print(scan_results)


if __name__ == '__main__':
    main()
