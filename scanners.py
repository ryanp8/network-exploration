import asyncio
import aiohttp
import re
import subprocess
import maxminddb
import sys

public_dns_resolvers = [
    '208.67.222.222',
    '1.1.1.1',
    '8.8.8.8',
    '8.26.56.26',
    '9.9.9.9',
    '64.6.65.6',
    '91.239.100.100',
    '185.228.168.168',
    '77.88.8.7',
    '156.154.70.1',
    '198.101.242.72',
    '176.103.130.130'
]

async def run_subprocess(cmd):
    output = await asyncio.create_subprocess_shell(cmd,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(output.communicate(), timeout=2)
        stdout_utf8, stderr_utf8 = stdout.decode('utf-8'), stderr.decode('utf-8')
        if 'command not found' in stderr_utf8.lower():
            print(f'command not found: {cmd}', file=sys.stderr)
            return -1
        return stdout.decode('utf-8'), stderr.decode('utf-8')
    except asyncio.TimeoutError:
        print(f'[Timeout] {cmd}')
        return (None, None)
    except:
        print(f'Unable to run {cmd}')
        return (None, None)


async def nslookup(hostname, resolver, lookup_type):
    result = await run_subprocess(f'nslookup -type={lookup_type} {hostname} {resolver}')
    if result == -1:
        return -1
    nslookup_output, _ = result
    if nslookup_output:
        return nslookup_output.split('\n')[3:]


async def tls_lookup(hostname, version):
    result = await run_subprocess(f'echo | openssl s_client {version + " "}-connect {hostname}:443')
    if result == -1:
        return -1
    openssl_stdout, openssl_stderr = result
    if openssl_stderr or openssl_stdout:
        return openssl_stdout, openssl_stderr
    return ':error:', ':error:'


async def ipv4_address(hostname):
    ret = set()
    results = await asyncio.gather(*(nslookup(hostname, resolver, 'A') for resolver in public_dns_resolvers for _ in range(10)))
    if -1 in results:
        return -1
    for result in results:
        if result:
            for line in result:
                if 'Address' in line:
                    ret.add(line.split(' ')[1])
    return list(ret)


async def ipv6_address(hostname):
    ret = set()
    results = await asyncio.gather(*(nslookup(hostname, resolver, 'AAAA') for resolver in public_dns_resolvers for _ in range(10)))
    if -1 in results:
        return -1
    for result in results:
        if result:
            for line in result:
                if 'Address:' in line:
                    ret.add(line.split(' ')[1])
    return list(ret)


async def http_server(hostname, insecure_http):
    async with aiohttp.ClientSession() as session:
        try:
            found = False
            if insecure_http:
                async with session.get(f'http://{hostname}:80', allow_redirects=False, timeout=2) as response:
                    if 'Server' in response.headers:
                        return response.headers['Server']

            async with session.get(f'https://{hostname}:443', allow_redirects=False, timeout=2) as response:
                if 'Server' in response.headers:
                    return response.headers['Server']
        except:
            return False


async def insecure_http(hostname):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f'http://{hostname}:80', timeout=2, allow_redirects=False) as _:
                return True
        except:
            return False


async def redirect_to_https(location, insecure_http, ttl=10):
    if not insecure_http or ttl == 0:
        return False

    async with aiohttp.ClientSession() as session:
        try:
            if ttl == 10:
                location = f'http://{location}'
            async with session.get(location, allow_redirects=False, timeout=2) as response:
                status = response.status
                if status >= 300 and status < 310:
                    location = response.headers['Location']
                    if 'https' in location:
                        return True
                    await redirect_to_https(location, insecure_http, ttl-1)
        except:
            return False
    return False


async def hsts(location, ttl=10):
    if ttl == 0:
        return False

    async with aiohttp.ClientSession() as session:
        try:
            if ttl == 10:
                location = f'http://{location}'
            async with session.get(location, allow_redirects=False, timeout=2) as response:
                status = response.status
                if status == 301 or status == 302:
                    location = response.headers['Location']
                    if 'https' in location:
                        return True
                    await redirect_to_https(location, ttl-1)
                else:
                    return 'Strict-Transport-Security' in response.headers
        except:
            return False
    return False


async def tls_versions(hostname):
    versions = [('TLSv1.0', '-tls1'), ('TLSv1.1', '-tls1_1'), ('TLSv1.2', '-tls1_2'), ('TLSv1.3', '-tls1_3')]
    outputs = await asyncio.gather(*(tls_lookup(hostname, version_flag) for _, version_flag in versions))
    if -1 in outputs:
        return -1
    # results = [':error:' not in stderr for _, stderr in outputs if stderr]
    results = []
    for _, stderr in outputs:
        if not stderr:
            results.append(False)
        elif ':error:' not in stderr:
            results.append(True)
        else:
            results.append(False)
    # print(results, [stderr for _, stderr in outputs])
    return [version for i, (version, _) in enumerate(versions) if results[i]]


async def root_ca(hostname):
    result = await tls_lookup(hostname, '')
    if result == -1:
        return -1
    _, openssl_stderr = result
    if openssl_stderr:
        line = openssl_stderr.split('\n')[0]
        target = line[line.find('O =') + len('O = '):]
        start = 0
        if target[0] == '"':
            start = 1
            end = target[1:].find('"')
        else:
            next_comma = target.find(',')
            endline = target.find('\n')
            end = min(next_comma, endline) if endline != -1 else next_comma
        root_ca = target[start:end]
        return root_ca


async def rdns_names(addresses):
    res = set()
    rdns_outputs = await asyncio.gather(*(nslookup(address, '', 'PTR') for address in addresses))
    if -1 in rdns_outputs:
        return -1
    for output in rdns_outputs:
        if output:
            for line in output:
                idx = line.find('name = ')
                if idx != -1:
                    res.add(line[idx+len('name = '):-1])
    return list(res)


async def rtt_range(addresses):
    telnet_outputs = await asyncio.gather(*(run_subprocess(f'''sh -c "time echo -e '\x1dclose\x0d' | telnet {address} 443"''') for address in addresses))
    if -1 in telnet_outputs:
        return -1
    time_data = [output[1] for output in telnet_outputs]
    rtts = []
    for time in time_data:
        if time:
            start, end = time.find('\t')+1, time.find('s')
            timestamp = time[start:end]
            m, s = timestamp.split('m')
            rtts.append(60 * 1000 * float(m) + 1000 * float(s))
    return [min(rtts), max(rtts)]


def geolocations(addresses):
    ret = set()
    for address in addresses:
        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            result = reader.get(address)
            if result and 'city' in result and 'subdivisions' in result and 'country' in result:
                ret.add(f"{result['city']['names']['en']}, {result['subdivisions'][0]['names']['en']}, {result['country']['names']['en']}")
    return list(ret)