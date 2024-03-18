import json
import sys
import time
import math
import asyncio

import scanners

async def create_entry(hostname):
    entry = {}
    scan_time = math.floor(time.time() * 100) / 100
    entry['scan_time'] = scan_time
    ipv4 = await scanners.ipv4_address(hostname)
    if ipv4 == -1:
        return None
    entry['ipv4'] = ipv4
    entry['ipv6'] = await scanners.ipv6_address(hostname)
    entry['insecure_http'] = await scanners.insecure_http(hostname)
    entry['http_server'] = await scanners.http_server(hostname, entry['insecure_http'])
    entry['redirect_to_https'] = await scanners.redirect_to_https(hostname, entry['insecure_http'])
    entry['hsts'] = await scanners.hsts(hostname)

    tls_versions = await scanners.tls_versions(hostname)
    entry['tls_versions'] = tls_versions
    entry['root_ca'] = None if not tls_versions else await scanners.root_ca(hostname)
    entry['rdns_names'] = await scanners.rdns_names(ipv4)
    entry['rtt_range'] = await scanners.rtt_range(ipv4)
    entry['geo_locations'] = scanners.geolocations(ipv4)
    if -1 in entry.values():
        return None
    return entry

async def main(input_file, output_file):
    results = {}
    with open(input_file, 'r') as f:
        hostnames = [hostname.replace('\n', '') for hostname in f.readlines()]
        for hostname in hostnames:
            print(f'creating entry for {hostname}')
            entry = await create_entry(hostname)
            if entry:
                results[hostname] = entry

    with open(output_file, 'w') as f:
        json.dump(results, f, sort_keys=True, indent=4)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python3 scan.py [input_file.txt] [output_file.json]')
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    asyncio.run(main(input_file, output_file))




