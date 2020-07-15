from scipy.stats import entropy
import collections
import whois
import tldextract



def get_whois_entropy(domain):
    """
    This function is used to get the all the whois features for check_domain_rep

    :param domain: Domain name (i.e., google.com, google.co.jp)
    :return:
    """
    domain_entropy = None
    shan_domain_entropy = None
    domain_data = whois.query(domain, slow_down=10)

    if domain_data is None:
        return domain_entropy, shan_domain_entropy, None

    domain_entropy = calculate_entropy(domain_data.name)
    shan_domain_entropy = calculate_shanon(domain_data.name)

    return domain_entropy, shan_domain_entropy, domain_data.name

def calculate_entropy(domain_name):
    """
    This function will calculate the entropy of a given domain.

    :param domain_name: Domain name in string format. i.e., google.com
    :return: relative entropy of the domain name.
    """
    DOMAIN_CHARACTER_FREQUENCIES = {
        'g': 0.025249941725372402,
        'o': 0.0663235171629015,
        'l': 0.04657376149687994,
        'e': 0.09371878412461322,
        'f': 0.016704094923625783,
        'a': 0.087659720916966,
        'c': 0.04058990102201812,
        'b': 0.022289470798469258,
        'k': 0.01704924850198753,
        'y': 0.017866791092401087,
        'u': 0.030667634481561547,
        't': 0.05886056973909945,
        'w': 0.01675243240392876,
        'i': 0.06955823338094509,
        'r': 0.06182213924510039,
        'n': 0.06168471698704895,
        's': 0.0630636334964357,
        'm': 0.031000603819020478,
        'd': 0.03118146988684835,
        'p': 0.026072078373831287,
        'v': 0.012782167544497946,
        'h': 0.028330257644762265,
        'z': 0.007483321072524796,
        'q': 0.0030804157902169335,
        '3': 0.003709002775809768,
        'x': 0.006860426724075081,
        'j': 0.007537550931625036,
        '-': 0.010594097594171698,
        '1': 0.004531439036749868,
        '6': 0.0034792000027164863,
        '4': 0.0038123690818295617,
        '8': 0.004382631504412193,
        '2': 0.0040967013265043,
        '0': 0.004334493765763362,
        '5': 0.0035300342536962693,
        '7': 0.0032469004589463987,
        '9': 0.0035202469126431875
    }

    domain_probability_pk = []
    domain_probability_qk = []

    sanitized_domain_name = sanitize_domain(domain_name)

    res = collections.Counter(sanitized_domain_name)
    sum_res = sum(res.values())

    for key in res:
        domain_probability_pk.append(res[key] / sum_res)
        domain_probability_qk.append(DOMAIN_CHARACTER_FREQUENCIES[key])

    relative_entropy = entropy(domain_probability_pk, domain_probability_qk, base=37)

    return relative_entropy


def calculate_shanon(domain_name):
    """
    This function will calculate the entropy of a given domain.

    :param domain_name: Domain name in string format. i.e., google.com
    :return: shannon entropy of the domain name.
    """

    domain_probability_pk = []

    sanitized_domain_name = sanitize_domain(domain_name)

    res = collections.Counter(sanitized_domain_name)
    sum_res = sum(res.values())

    for key in res:
        domain_probability_pk.append(res[key] / sum_res)

    shan_entropy = entropy(domain_probability_pk, base=37)
    return shan_entropy

def sanitize_domain(domain_name):
    """
    Sanitizes a domain
    :param domain_name:
    :return:
    """
    ext = tldextract.extract("http://www." + domain_name.rstrip())
    return ext.domain

def get_all_entropy(text_file, num_domains):
    entropy_list = []
    shannon_list = []
    domain_name_list = []
    counter = 0

    f = open(text_file, "r")
    for domain in f:
        if counter < num_domains:
            entropy_score, shannon_score, used_domain_name = get_whois_entropy(domain)

            if entropy_score is None or shannon_score is None or used_domain_name in domain_name_list:
                continue

            entropy_list.append(entropy_score)
            shannon_list.append(shannon_score)
            domain_name_list.append(used_domain_name)
            counter += 1
        else:
            break

    return entropy_list, shannon_list, domain_name_list


def get_all_entropy_list(domain_list):
    entropy_list = []
    shannon_list = []
    counter = 0

    for domain in domain_list:
        entropy_score = calculate_entropy(domain)
        shannon_score = calculate_shanon(domain)

        entropy_list.append(entropy_score)
        shannon_list.append(shannon_score)
        if entropy_score > 0.12:
            counter += 1

    print(counter)

    return entropy_list, shannon_list


if __name__ == "__main__":
    mal_domains = []
    ben_domains = []

    with open('mal_domains.txt', 'r') as file:
        for domain in file:
            mal_domains.append(domain.rstrip())

    with open('ben_domains.txt', 'r') as file:
        for domain in file:
            ben_domains.append(domain.rstrip())

    mal_entropies, mal_shan_entropy = get_all_entropy_list(mal_domains)
    print(mal_entropies)
    print(mal_shan_entropy)

    ben_entropies, ben_shan_entropy,  = get_all_entropy_list(ben_domains)
    print(ben_entropies)
    print(ben_shan_entropy)