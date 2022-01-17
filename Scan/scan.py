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
from ipaddress import IPv4Network, AddressValueError
import logging
from queue import Queue
from socket import inet_aton, error as socket_error
from threading import Thread

# Remote
from nmap3 import NmapScanTechniques

# Local
import config

def convert_to_es(scan_results: list[tuple[dict]]) -> list[dict]:
    logging.info("Converting the scan output to one that elasticsearch parses better.")
    list_of_scans = []
    for scan in scan_results:
        data = {}
        scan_dict = scan[0]
        keys = list(scan_dict.keys())
        ip = scan[1]
        if ip in keys and 'ports' in scan_dict[ip]:
            data = scan_dict
            data['scan_results'] = scan_dict[ip]
            data['host'] = {}
            data['host']['ip'] = ip
            data.pop(ip)
        list_of_scans.append(data)
    return list_of_scans

def scan_run(ip_queue: Queue, result_queue: Queue) -> None:
    scanner = NmapScanTechniques()
    tcp_ports = ','.join([str(port) for port in config.TCP_PORTS])
    while not ip_queue.empty():
        tcp_results = {}
        ip = ip_queue.get()
        if ip and config.TCP_PORTS:
            logging.info("Performing scan on ({}) on ports ({})".format(ip, tcp_ports))
            tcp_results.update(scanner.nmap_tcp_scan(ip, args='-p {}'.format(tcp_ports)))
        result_queue.put((tcp_results, ip))

def scan(ips: list[str]) -> list[dict]:
    tcp_ports = ','.join([str(port) for port in config.TCP_PORTS])
    logging.debug("Performing scans on the following ips: {}".format(ips))
    logging.debug("Performing scans on the following ports: {}".format(tcp_ports))
    ip_queue = Queue(config.MAX_IPS)
    result_queue = Queue(config.MAX_IPS)
    for ip in ips:
        if not ip_queue.full():
            ip_queue.put(ip)
    threads = []
    for i in range(config.THREADS):
        thread = Thread(target=scan_run, name='thread-{}'.format(i), kwargs={'ip_queue': ip_queue, 'result_queue': result_queue})
        threads.append(thread)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return list(result_queue.queue)


def validate_config(ips: list[str]) -> None:
    logging.info("Validating the configurations specified in config.py")
    # Validate all ips to scan
    for ip in ips:
        try:
            inet_aton(ip) # IP is valid
        except socket_error:
            logging.error("Error: Config's host IP address is incorrect.")
            exit(1)
    # Validate ports
    for port in config.TCP_PORTS:
        if isinstance(port, int):
            if port > 0 and port < 65536:
                continue
            else:
                logging.error("Error: one of more TCP ports is <1 or >65535.")
                exit(1)
        else:
            logging.error("Error: one or more TCP ports not an integer.")
            exit(1)


def expand_ips() -> list[str]:
    logging.info("Expanding IP ranges.")
    ips = []
    for address in config.IPS:
        try:
            ips += [str(ip) for ip in IPv4Network(address)]
        except AddressValueError:
            logging.error("Error parsing list of IPs.")
            exit(1)
    logging.debug("Expanded IPs to scan: {}".format(ips))
    return ips

def main():
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

    # Expand CIDR IP ranges to an actual list of IPs
    ips = expand_ips()
    # Validation on config fields
    validate_config(ips)

    # Scan using config
    tcp_results = scan(ips)

    # Convert to a format that works better with ElasticSearch
    tcp_results = convert_to_es(tcp_results)
    print(tcp_results)


if __name__ == '__main__':
    main()
