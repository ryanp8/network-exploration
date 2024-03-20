# network-exploration

Tool to gather information about websites developed in Python, using asyncio and various command-line tools.

## Sample output
```json
[
  "amazon.com": {
        "geo_locations": [
            "Ashburn, Virginia, United States"
        ],
        "hsts": true,
        "http_server": "Server",
        "insecure_http": true,
        "ipv4": [
            "52.94.236.248",
            "205.251.242.103",
            "54.239.28.85"
        ],
        "ipv6": [],
        "rdns_names": [
            "s3-console-us-standard.console.aws.amazon.com"
        ],
        "redirect_to_https": true,
        "root_ca": "DigiCert Inc",
        "rtt_range": [
            22.0,
            27.0
        ],
        "scan_time": 1709958995.72,
        "tls_versions": [
            "TLSv1.0",
            "TLSv1.1",
            "TLSv1.2"
        ]
    }
]
```
