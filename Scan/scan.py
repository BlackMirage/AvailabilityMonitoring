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
from queue import Queue, Empty
from socket import inet_aton, error as socket_error
from threading import Thread

# Remote
from elasticsearch import Elasticsearch
from nmap3 import NmapScanTechniques

# Local
import config

def upload_to_es(nmap_result: dict, es_instance: Elasticsearch) -> bool:
    """
    Uploads the nmap result to elasticsearch.
    Input:
        - nmap_result: a dictionary result of the nmap scan.
        - es_instance: an Elasticsearch object used to index the nmap result.
    """
    _doc = nmap_result
    if not nmap_result:
        return False
    res = es_instance.index(index=config.ELASTICSEARCH_INDEX, document=_doc)
    if 'result' in res and res['result'] == 'success':
        return True
    else:
        return False

def convert_to_es(scan_result: tuple[dict, str]) -> dict:
    """
    Converts a dictionary with an IP as a key to a dictionary with the IP as a value, which helps elasticsearch queries.
    Input:
        - scan_result: a tuple with the scanned dictionary as the first element and the IP address of the host as the second.
    Output: a dictionary with the IP as a value.
    """
    logging.info("Converting the scan output to one that elasticsearch parses better.")
    data = {}
    scan_dict = scan_result[0]
    keys = list(scan_dict.keys())
    ip = scan_result[1]
    if ip in keys and 'ports' in scan_dict[ip]:
        data = scan_dict
        data['scan_results'] = scan_dict[ip]
        data['host'] = {}
        data['host']['ip'] = ip
        data.pop(ip)
    return data


def run_nmap(ip_queue: Queue, scanned_queue: Queue) -> None:
    """
    Worker that continually tries to pull IP addresses from an IP address queue and scan them with nmap.
    It then outputs the nmap results to another queue passed in.
    Input:
        - ip_queue: the queue in which the IP addresses should be added.
        - scanned_queue: the queue storing the scanned nmap hosts.
    """
    scanner = NmapScanTechniques()
    tcp_ports = ','.join([str(port) for port in config.TCP_PORTS])
    while not ip_queue.empty():
        tcp_results = {}
        ip = ip_queue.get()
        if ip and config.TCP_PORTS:
            logging.info("Performing scan on ({}) on ports ({})".format(ip, tcp_ports))
            tcp_results.update(scanner.nmap_tcp_scan(ip, args='-p {}'.format(tcp_ports)))
        scanned_queue.put((tcp_results, ip))


def run_fill_ip_queue(ips: list[str], ip_queue: Queue):
    """
    Worker that fills in the IP queue with the IPs parameterized in the function.
    Input:
        - ips: a list of IP addresses to be entered into the queue.
        - ip_queue: the queue in which the IP addresses should be added.
    """
    for ip in ips:
        ip_queue.put(ip)


def run_clean_and_upload(scanned_queue: Queue) -> None:
    """
    Worker that continually tries to upload to elasticsearch whatever it finds in its queue.
    Additionally attempts to make the nmap output more conducive to elasticsearch queries before uploading.
    Input:
        - scanned_queue: a queue storing the scanned nmap hosts.
    """
    es = Elasticsearch([config.ELASTICSEARCH_URL])
    while True:
        # To do: fix hack to prevent race condition when no elements are in queues and are instead in running nmap scans
        try:
            nmap_result = scanned_queue.get(timeout=20)
        except Empty:
            break
        if nmap_result and isinstance(nmap_result, tuple) and nmap_result[0]: # Checks if it's not an empty dict
            modified_nmap_result = convert_to_es(nmap_result)
            upload_to_es(modified_nmap_result, es)


def scan(ips: list[str]) -> None:
    """
    Scans a list of IP addresses with nmap and sends the output to elasticsearch.
    Input:
        - ips: a list of IP addresses to be scanned.
    """
    tcp_ports = ','.join([str(port) for port in config.TCP_PORTS])
    logging.debug("Performing scans on the following ips: {}".format(ips))
    logging.debug("Performing scans on the following ports: {}".format(tcp_ports))
    ip_queue = Queue(config.MAX_QUEUE_SIZE)
    scanned_queue = Queue(config.MAX_QUEUE_SIZE)

    # Fill up the IP queue for nmap to take
    ip_fill_thread = Thread(target=run_fill_ip_queue, name='thread-fill-ip-queue', kwargs={'ips': ips, 'ip_queue': ip_queue})
    ip_fill_thread.start()

    # Create and start nmap threads to scan each IP in IP queue
    nmap_threads = []
    for i in range(config.NMAP_THREADS):
        thread = Thread(target=run_nmap, name='thread-nmap-{}'.format(i), kwargs={'ip_queue': ip_queue, 'scanned_queue': scanned_queue})
        nmap_threads.append(thread)
    for thread in nmap_threads:
        thread.start()

    # Create and start elasticsearch clean and upload thread
    upload_threads = []
    for i in range(config.UPLOAD_THREADS):
        thread = Thread(target=run_clean_and_upload, name='thread-es-{}'.format(i), kwargs={'scanned_queue': scanned_queue})
        upload_threads.append(thread)
    for thread in upload_threads:
        thread.start()

    # Join elasticsearch threads
    for thread in nmap_threads:
        thread.join()

    # Join nmap threads
    for thread in nmap_threads:
        thread.join()

    # Join fill IP queue thread
    ip_fill_thread.join()


def validate_config(ips: list[str]) -> None:
    """
    Checks done on a list of IPs to check they are valid and a check on the ports in the config.
    Exits if errors found.
    Input:
        - ips: list of IP addresses to validate.
    """
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
    """
    Given the list of IP addresses in the config, expands IP addresses with subnets into all the addresses that exist in the subnet.
    Output: list of expanded IP addresses from their CIDR notation in a list.
    """
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
    scan(ips)


if __name__ == '__main__':
    main()
