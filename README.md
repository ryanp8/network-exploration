# network-exploration

Tool to gather information about websites developed in Python, using asyncio and various command-line tools.

## Usage
Make sure you are using Python >=3.5 since async/await syntax is used.
1. Install the dependencies listed in `requirements.txt`
2. Run `python3 scan.py [.txt file with one website per line] out.json` to create a json file with the results.
3. Run `python3 report.py out.json report.txt` to create a report summarizing the json file with tables.

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
