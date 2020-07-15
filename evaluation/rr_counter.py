import dns.resolver
import collections
import functools
import operator
import math


def get_records(domain):
    """
    Get all the resource records of a domain.
    :param domain:
    :return:
    """
    rr = []
    rr_counter = {}
    ids = [
        'NONE',
        'A',
        'NS',
        'MD',
        'MF',
        'CNAME',
        'SOA',
        'MB',
        'MG',
        'MR',
        'NULL',
        'WKS',
        'PTR',
        'HINFO',
        'MINFO',
        'MX',
        'TXT',
        'RP',
        'AFSDB',
        'X25',
        'ISDN',
        'RT',
        'NSAP',
        'NSAP-PTR',
        'SIG',
        'KEY',
        'PX',
        'GPOS',
        'AAAA',
        'LOC',
        'NXT',
        'SRV',
        'NAPTR',
        'KX',
        'CERT',
        'A6',
        'DNAME',
        'OPT',
        'APL',
        'DS',
        'SSHFP',
        'IPSECKEY',
        'RRSIG',
        'NSEC',
        'DNSKEY',
        'DHCID',
        'NSEC3',
        'NSEC3PARAM',
        'TLSA',
        'HIP',
        'CDS',
        'CDNSKEY',
        'CSYNC',
        'SPF',
        'UNSPEC',
        'EUI48',
        'EUI64',
        'TKEY',
        'TSIG',
        'IXFR',
        'AXFR',
        'MAILB',
        'MAILA',
        'ANY',
        'URI',
        'CAA',
        'TA',
        'DLV',
    ]

    for a in ids:
        answers = dns.resolver.query(domain, a, raise_on_no_answer=False)
        for rdata in answers:
            rr.append(a)

    for i in rr:
        rr_counter[i] = rr_counter.get(i, 0) + 1

    return dict(collections.Counter(rr))


def query_domain_records(domain_list):
    """
    Creates a list of dictionary with the number of each resource record for each domain.
    :param domain_list: file with domains on each line.
    :return: The created list of dictionary with each rr of each domain.
    """
    domains = []

    f = open(domain_list, "r")
    for domain in f:
        domains.append(get_records(domain.rstrip()))


    return domains


def sum_rr_domain(input_dict):
    """
    Sums the number of each resource record.

    source: https://www.geeksforgeeks.org/python-sum-list-of-dictionaries-with-same-key/
    :param input_dict:
    :return: dictionary with sum values of the same keys
    """
    result = dict(functools.reduce(operator.add, map(collections.Counter, input_dict)))

    return result


def avg_rr_domain(input_dict, divider):
    """
    Calculates the average and std of resource record.
    :param input_dict: Summed up dictionary for each resource record.
    :param divider: Length of the dictionary before it was summed.
    :return: dictionary of the averages
    """
    # print("Input_dict: %s" % str(input_dict))
    # print("Divider: %i" % divider)
    avg_dict = {}
    std_dict = {}
    for key in input_dict:
        avg_dict[key] = input_dict[key] / divider
        std_dict[key] = math.sqrt(math.pow(input_dict[key] - avg_dict[key], 2))

    # print(str(avg_dict))

    return avg_dict, std_dict


if __name__ == '__main__':
    benign_records = list(filter(None, query_domain_records("ben_domains.txt")))
    # print("Benign records stats: %s" % benign_records)
    # print(len(benign_records))
    # result_benign = sum_rr_domain(benign_records)
    # print("resultant dictionary : ", str(result_benign))
    # avg_ben, std_ben = avg_rr_domain(result_benign, len(benign_records))
    # print("avg_ben: ", str(avg_ben))
    # print("std_ben: ", str(std_ben))

    mal_records = list(filter(None, query_domain_records("mal_domains.txt")))
    print("mal records stats: %s" % mal_records)
    print(len(mal_records))
    result_malicious = sum_rr_domain(mal_records)
    print("resultant dictionary : ", str(result_malicious))
    # avg_mal, std_mal = avg_rr_domain(result_malicious, len(mal_records))
    # print("avg_mal: ", str(avg_mal))

