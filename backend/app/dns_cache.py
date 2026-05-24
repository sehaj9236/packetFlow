DNS_CACHE = {}

def add_dns_mapping(ip, domain):
    DNS_CACHE[ip] = domain

def get_domain_from_ip(ip):
    return DNS_CACHE.get(ip, "Unknown")