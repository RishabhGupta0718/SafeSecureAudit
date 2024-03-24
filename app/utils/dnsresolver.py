import dns.resolver
def dns_record_lookup(domain_name, record_type):
    try:
        answers = dns.resolver.resolve(domain_name, record_type)
        result = [r.to_text() for r in answers]
        return result
    except dns.resolver.NoAnswer:
        return ["No {} record found for {}".format(record_type, domain_name)]
    except dns.resolver.NXDOMAIN:
        return ["Domain {} does not exist".format(domain_name)]
    except dns.resolver.Timeout:
        return ["Timeout occurred while performing DNS lookup"]
    except dns.exception.DNSException as e:
        return ["DNS lookup error: {}".format(str(e))]