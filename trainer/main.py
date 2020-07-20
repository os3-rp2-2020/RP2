import collections
import whois
import datetime
import dns.resolver

from scipy.stats import entropy
from trainer import DNSReputationTrainer


def main():
    malicious = read_domain_file("./train_data/malicious.txt")
    benign = read_domain_file("./train_data/benign.txt")

    trainer = DNSReputationTrainer()
    trainer.train(malicious, benign)
    trainer.save("./output.model")


def read_domain_file(input):
    with open(input, 'r') as file:
        domain_info = []
        for domain_name in file:
            domain_name = domain_name.rstrip()
            num_ns, num_mx, num_txt = get_dns_records(domain_name)
            registration_period, domain_entropy = get_whois_features(domain_name)
            domain_info.append([num_ns, num_mx, num_txt, domain_entropy, registration_period])

    return domain_info

def get_dns_records(domain):
    """
    Get all the records associated to domain parameter.
    source: https://gist.github.com/akshaybabloo/2a1df455e7643926739e934e910cbf2e
    :param domain:
    :return:
    """
    rr = []
    ids = [
        'NS',
        'MX',
        'TXT'
    ]

    for a in ids:
        answers = dns.resolver.query(domain, a, lifetime=5, raise_on_no_answer=False)
        for rdata in answers:
            rr.append(a)

    rr_counter = dict(collections.Counter(rr))

    return rr_counter.get("NS") or 0, rr_counter.get("MX") or 0, rr_counter.get("TXT") or 0

def sanitize_domain(domain_name):
    """
    :param domain_name:
    :return:
    """
    domain_name = domain_name.lower().strip()
    domain_name = domain_name.split(".")

    if domain_name[0] == 'www':
        domain_name = domain_name[1:]
    if len(domain_name) == 1:
        return None

    return "".join(domain_name[:-1])


def calculate_entropy(domain_name):
    """
    This function will calculate the entropy of a given domain.

    Domain character Frequencies found: https://redcanary.com/blog/threat-hunting-entropy/
    :param domain_name: Domain name in string format. i.e., google.com
    :return: relative entropy of the domain name.
    """
    DOMAIN_CHARACTER_FREQUENCIES = {
        "-": 0.013342298553905901,
        "_": 9.04562613824129e-06,
        "0": 0.0024875471880163543,
        "1": 0.004884638114650296,
        "2": 0.004373560237839663,
        "3": 0.0021136613076357144,
        "4": 0.001625197496170685,
        "5": 0.0013070929769758662,
        "6": 0.0014880054997406921,
        "7": 0.001471421851820583,
        "8": 0.0012663876593537805,
        "9": 0.0010327089841158806,
        "a": 0.07333590631143488,
        "b": 0.04293204925644953,
        "c": 0.027385633133525503,
        "d": 0.02769469202658208,
        "e": 0.07086192756262588,
        "f": 0.01249653250998034,
        "g": 0.038516276096631406,
        "h": 0.024017645001386995,
        "i": 0.060447396668797414,
        "j": 0.007082725266242929,
        "k": 0.01659570875496002,
        "l": 0.05815885325582237,
        "m": 0.033884915513851865,
        "n": 0.04753175014774523,
        "o": 0.09413783122067709,
        "p": 0.042555148167356144,
        "q": 0.0017231917793349655,
        "r": 0.06460084667060655,
        "s": 0.07214640647425614,
        "t": 0.06447722311338391,
        "u": 0.034792493336388744,
        "v": 0.011637198026847418,
        "w": 0.013318176884203925,
        "x": 0.003170491961453572,
        "y": 0.016381628936354975,
        "z": 0.004715786426736459
    }

    domain_probability_pk = []
    domain_probability_qk = []

    sanitized_domain_name = sanitize_domain(domain_name)

    res = collections.Counter(sanitized_domain_name)
    sum_res = sum(res.values())

    for key in res:
        domain_probability_pk.append(res[key] / sum_res)
        domain_probability_qk.append(DOMAIN_CHARACTER_FREQUENCIES[key])

    relative_entropy = entropy(domain_probability_pk, domain_probability_qk, base=2)

    return relative_entropy

def get_whois_features(domain_name):
    registration_period = get_whois_reg(domain_name)
    entropy_domain = calculate_entropy(domain_name)

    return registration_period.days, entropy_domain


def get_whois_reg(domain_name):
    domain_data = whois.query(domain_name, slow_down=5)

    if domain_data is None:
        return None, None

    if domain_data.creation_date is None and domain_data.last_updated is None and domain_data.expiration_date is None:
        return None, None

    # Remove any timezones (Inaccuracy of max 24 hours) + calculate registration period
    if domain_data.expiration_date is None and domain_data.last_updated is None:
        domain_data.creation_date = domain_data.creation_date.replace(tzinfo=None)
        registration_period = datetime.datetime.today() - domain_data.creation_date
        registration_period_2 = datetime.datetime.today() - domain_data.creation_date
    elif domain_data.expiration_date is None and domain_data.creation_date is None:
        domain_data.last_updated = domain_data.last_updated.replace(tzinfo=None)
        registration_period = datetime.datetime.today() - domain_data.last_updated
        registration_period_2 = datetime.datetime.today() - domain_data.last_updated
    elif domain_data.creation_date is None and domain_data.last_updated is None:
        domain_data.expiration_date = domain_data.expiration_date.replace(tzinfo=None)
        registration_period = domain_data.expiration_date - datetime.datetime.today()
        registration_period_2 = domain_data.expiration_date - datetime.datetime.today()
    elif domain_data.last_updated is None:
        domain_data.expiration_date = domain_data.expiration_date.replace(tzinfo=None)
        domain_data.creation_date = domain_data.creation_date.replace(tzinfo=None)
        registration_period = domain_data.expiration_date - domain_data.creation_date
        registration_period_2 = domain_data.expiration_date - domain_data.creation_date
    elif domain_data.expiration_date is None:
        domain_data.last_updated = domain_data.last_updated.replace(tzinfo=None)
        domain_data.creation_date = domain_data.creation_date.replace(tzinfo=None)
        registration_period = datetime.datetime.today() - domain_data.last_updated
        registration_period_2 = datetime.datetime.today() - domain_data.creation_date
    elif domain_data.creation_date is None:
        domain_data.expiration_date = domain_data.expiration_date.replace(tzinfo=None)
        domain_data.last_updated = domain_data.last_updated.replace(tzinfo=None)
        registration_period = domain_data.expiration_date - domain_data.last_updated
        registration_period_2 = domain_data.expiration_date - domain_data.last_updated
    else:
        domain_data.expiration_date = domain_data.expiration_date.replace(tzinfo=None)
        domain_data.last_updated = domain_data.last_updated.replace(tzinfo=None)
        domain_data.creation_date = domain_data.creation_date.replace(tzinfo=None)
        registration_period = domain_data.expiration_date - domain_data.last_updated
        registration_period_2 = domain_data.expiration_date - domain_data.creation_date

    return registration_period_2

if __name__ == "__main__":
    main()

