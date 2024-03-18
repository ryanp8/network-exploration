from texttable import Texttable
import json
import sys
import heapq


TLS_VERSIONS = ['SSLv2',
                'SSLv3',
                'TLSv1.0',
                'TLSv1.1',
                'TLSv1.2',
                'TLSv1.3']

input_file = sys.argv[1]
output_file = sys.argv[2]
with open(input_file, 'r') as f:
    contents = json.load(f)

    # Each element is a populated table for each hostname
    total_data = []
    # table = Texttable(max_width=0)
    # rows = [['Host',
    #         'scan_time',
    #         'ipv4',
    #         'ipv6',
    #         'http_server',
    #         'insecure_http',
    #         'redirect_to_https',
    #         'hsts',
    #         'tls_versions',
    #         'root_ca',
    #         'rdns_names',
    #         'rtt_range',
    #         'geolocations']]

    # Need intermediate storage for each table
    rtts_heap = []
    root_ca_freq = {}
    server_freq = {}

    # Store count of each property (to be used to calculate means later)
    summary_stats = {
        'SSLv2': 0,
        'SSLv3': 0,
        'TLSv1.0': 0,
        'TLSv1.1': 0,
        'TLSv1.2': 0,
        'TLSv1.3': 0,
        'plain http': 0,
        'https redirect': 0,
        'hsts': 0,
        'ipv6': 0
    }
    for hostname, data in contents.items():

        for version in TLS_VERSIONS:
            if version in data['tls_versions']:
                summary_stats[version] += 1
        if data['insecure_http']:
            summary_stats['plain http'] += 1
        if data['redirect_to_https']:
            summary_stats['https redirect'] += 1
        if data['hsts']:
            summary_stats['hsts'] += 1
        if data['ipv6']:
            summary_stats['ipv6'] += 1

        all_data_table = Texttable(max_width=0)
        rows = [['hostname', hostname]]
        for k, v in data.items():
            if k in ['ipv4', 'ipv6', 'tls_versions', 'rdns_names', 'geo_locations']:
                rows.append([k, '\n'.join(v)])
            else:
                rows.append([k, v])
        all_data_table.add_rows(rows)
        total_data.append(all_data_table)

        # Want to eventually sort by rtt, so push to the heap
        rtt = data['rtt_range']
        heapq.heappush(rtts_heap, (rtt[0], rtt[1], hostname))

        # Increment the frequency of the current root ca
        if data['root_ca']:
            root_ca_freq[data['root_ca']] = root_ca_freq.get(data['root_ca'], 0) + 1

        # Increment the frequency of the current server
        if data['http_server']:
            server_freq[data['http_server']] = server_freq.get(data['http_server'], 0) + 1

        # Collect data points for general table in one row
    #     row = [hostname,
    #            data['scan_time'],
    #            '\n'.join(data['ipv4']),
    #            '\n'.join(data['ipv6']),
    #            data['http_server'],
    #            data['insecure_http'],
    #            data['redirect_to_https'],
    #            data['hsts'],
    #            '\n'.join(data['tls_versions']),
    #            data['root_ca'],
    #            '\n'.join(data['rdns_names']),
    #            data['rtt_range'],
    #            '\n'.join(data['geo_locations'])]
    #     rows.append(row)

    
    # table.add_rows(rows)

    # Create rtt table
    rtt_table = Texttable(max_width=0)
    rtt_rows = [['hostname', 'min rtt (ms)', 'max rtt (ms)']]
    while rtts_heap:
        min_time, max_time, hostname = heapq.heappop(rtts_heap)
        rtt_rows.append([hostname, min_time, max_time])
    rtt_table.add_rows(rtt_rows)

    # Create root ca table
    root_ca_table = Texttable(max_width=0)
    root_ca_rows = [['root_ca', 'occurences']]
    root_ca_heap = []
    for rca, count in root_ca_freq.items():
        # Store as negative count since we want most popular ones to be popped first
        heapq.heappush(root_ca_heap, (-count, rca))

    while root_ca_heap:
        count, rca = heapq.heappop(root_ca_heap)
        root_ca_rows.append([rca, -count])
    root_ca_table.add_rows(root_ca_rows)

    # Create web server table
    server_table = Texttable(max_width=0)
    server_rows = [['http server', 'occurences']]
    server_heap = []
    for server, count in server_freq.items():
        # Store as negative count since we want most popular ones to be popped first
        heapq.heappush(server_heap, (-count, server))

    while server_heap:
        count, server = heapq.heappop(server_heap)
        server_rows.append([server, -count])
    server_table.add_rows(server_rows)

    # Create summary table
    summary_table = Texttable(max_width=0)
    summary_percentages = [i / len(contents) for i in summary_stats.values()]
    summary_rows = [['SSLv2',
                     'SSLv3',
                     'TLSv1.0',
                     'TLSv1.1',
                     'TLSv1.2',
                     'TLSv1.3',
                     'plain http',
                     'https redirect',
                     'hsts',
                     'ipv6'
                     ],
                     summary_percentages]
    summary_table.add_rows(summary_rows)


    with open(output_file, 'w') as f:
        # f.write(table.draw())
        for table in total_data:
            f.write(table.draw())
            f.write('\n\n')
        f.write(rtt_table.draw())
        f.write('\n\n')
        f.write(root_ca_table.draw())
        f.write('\n\n')
        f.write(server_table.draw())
        f.write('\n\n')
        f.write(summary_table.draw())

