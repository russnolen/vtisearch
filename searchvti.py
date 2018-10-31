import re
import json
import ipaddress
import validators
from urllib.parse import urlparse

from virus_total_apis import PublicApi as VirusTotalPublicApi


class searchVTI:
    def __init__(self):
        self.config = {}
        self.vti_key = ''
        self.vti = ''

    def parse_file(self, logfile):
        results = {}
        with open(logfile, 'r') as infile:
            for key in self.config['ioc_types'].keys():
                results[key] = set()
            for line in infile:
                for key, value in self.config['ioc_types'].items():
                    found_items = re.findall(value, line)
                    results[key].update(found_items)
        return results

    def parse_cli(self, cli_data):
        results = {}
        for ioc_type in self.config['ioc_types'].keys():
            results[ioc_type] = set()
        for key, value in self.config['ioc_types'].items():
            found_items = re.findall(value, cli_data)
            results[key].update(found_items)
        return results

    def load_config(self, config_file):
        with open(config_file, 'r') as configs:
            self.config = json.load(configs)
        self.vti = VirusTotalPublicApi(self.config['api_keys']['vti'])

    def _handle_domain(self, domains):
        domain_data = {}
        for domain in domains:
            if validators.domain(domain):
                domain_data[domain] = self.vti.get_domain_report(domain)
            else:
                print("Domain is not valid and VTI was not queried for:", domain)
        return domain_data

    def _handle_ipaddr(self, ips):
        ip_data = {}
        for ip in ips:
            try:
                valid_ip = ipaddress.IPv4Network(ip)
                ip_data[ip] = self.vti.get_ip_report(valid_ip)
            except ValueError:
                print('IP address is invalid for IPv4:', valid_ip)
        return ip_data

    def _handle_md5(self, md5s):
        md5_data = {}
        for md5 in md5s:
            md5_data[md5] = self.vti.get_file_report(md5)
        return md5_data

    def _url_validator(self, url):
        url_result = urlparse(url)
        if all([url_result.scheme,url_result.netloc]):
            return True
        else:
            return False

    def _handle_urls(self, urls):
        url_data = {}
        for url in urls:
            print(url)
            if self._url_validator(url):
                url_data[url] = self.vti.get_url_report(url)
        return url_data

    def get_vti_data(self, ioc_dict):
        vti_data = {}
        for ioc_type,iocs in ioc_dict.items():
            if ioc_type == 'domain':
                vti_data['domains'] =  self._handle_domain(iocs)
            if ioc_type == 'ipaddr':
                vti_data['ips'] = self._handle_ipaddr(iocs)
            if ioc_type == 'md5':
                vti_data['md5s'] = self._handle_md5(iocs)
            if ioc_type == 'url':
                vti_data['urls'] = self._handle_urls(iocs)

        return vti_data