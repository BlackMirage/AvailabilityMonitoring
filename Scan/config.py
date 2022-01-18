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

# Hosts to be scanned
# e.g., ['192.168.1.1', '192.168.1.0/24']
IPS = []
# The number of threads to be used for scanning
NMAP_THREADS = 8
# The number of threads to be used for uploading to elasticsearch
UPLOAD_THREADS = 4

# Elasticsearch
# URL
# e.g., 'https://USERNAME:PASSWORD@elasticinstances.com:9200'
ELASTICSEARCH_URL = ''
ELASTICSEARCH_INDEX = ''

# Nmap
# Ports to be scanned
# e.g., [80, 443]
TCP_PORTS = [80, 443]


# MISC
# Queue size
# The maximum size of the queue for communication between threads
# The larger this is, the more memory you will use
MAX_QUEUE_SIZE = 10000