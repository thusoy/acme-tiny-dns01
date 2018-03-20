#!/usr/bin/env python
import argparse
import base64
import binascii
import copy
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import sys
import textwrap
import time

import dns.message
import dns.query
import dns.resolver
import dns.update
import dns.tsigkeyring

try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2
    input = raw_input

#DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.DEBUG)

def get_crt(account_key, csr, skip_check=False, log=LOGGER, CA=DEFAULT_CA, contact_mail=False,
            dns_zone_update_server=None, dns_zone_keyring=None, dns_zone=None, dns_update_algo=None):
    # helper function base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # parse account key to get public key
    log.debug("Parsing account key...")
    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # helper function make signed requests
    def _send_signed_request(url, payload):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    # find domains
    log.debug("Parsing CSR...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(csr, err))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    # register the account (or, if already registered, simply update the contact infos)
    log.debug("Registering account...")
    payload = {
        "resource": "new-reg",
        "agreement": json.loads(urlopen(CA + "/directory").read().decode('utf8'))['meta']['terms-of-service'],
    }
    if contact_mail:
        payload["contact"] = [ "mailto:" + contact_mail ]

    code, result = _send_signed_request(CA + "/acme/new-reg", payload)
    if code == 201:
        log.debug("Registered!")
    elif code == 409:
        log.debug("Already registered!")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

    pending = {}

    # get the challenge for each domain
    for domain in domains:
        log.debug("Getting challenge for {0}...".format(domain))

        # get new challenge
        code, result = _send_signed_request(CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))
        # make the challenge file
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        record = _b64(hashlib.sha256(keyauthorization.encode()).digest())
        log.info('_acme-challenge.%s. 1 IN TXT %s' % (domain, record))
        zone = '_acme-challenge.'+domain
        if dns_zone:
          zone = dns_zone
          if isinstance(dns_zone,int):
            zone = '.'.join(('_acme-challenge.'+domain).split('.')[dns_zone:])
        pending[domain] = (challenge, token, keyauthorization, record, zone)

    if not dns_zone_update_server:
      log.info('Press enter to continue after updating DNS server')
      input()
    else:
      log.debug('Performing DNS Zone Updates...')
      for domain in pending.keys():
        record = pending[domain][3]
        zone = pending[domain][4]
        log.debug('Updating TXT record {0} in DNS zone {1}'.format('_acme-challenge.'+domain,zone))
        update = dns.update.Update(zone, keyring=dns_zone_keyring, keyalgorithm=dns_update_algo)
        update.replace('_acme-challenge.'+domain+'.', 0, 'TXT', str(record))
        response = dns.query.tcp(update, dns_zone_update_server, timeout=10)
        if response.rcode() != 0:
          raise Exception("DNS zone update failed, aborting, query was: {0}".format(response))

    # verify locally that all challenges are in place
    if not skip_check:
        for domain in pending.keys():
            challenge, token, keyauthorization, record, zone = pending[domain]
            log.debug("Local checks on {0}...".format(domain))
            # get the IP address of all the primary servers for the current domain
            addr = set()
            for x in dns.resolver.query(dns.resolver.zone_for_name(domain), 'NS'):
                addr = addr.union(map(str, dns.resolver.query(str(x), 'A', raise_on_no_answer=False)))
                addr = addr.union(map(str, dns.resolver.query(str(x), 'AAAA', raise_on_no_answer=False)))

            # check directly on each name server of the current domain, if the challenge is in place
            while len(addr):
                x = addr.pop()
                log.debug("Locally checking challenge on {0}...".format(x))
                req = dns.message.make_query('_acme-challenge.%s' % domain, 'TXT')
                try:
                    resp = dns.query.udp(req, x, timeout=30)
                except dns.exception.Timeout:
                    log.warning("Name server {0} not responding. We assume it's just bad luck and we ignore...".format(x))
                    continue
                txt = set()
                for y in resp.answer:
                    txt = txt.union(map(lambda x: str(x)[1:-1], y))
                if len(txt) != 1 or record not in txt:
                    # the challenge has not been found (or an old one is still there)
                    # we wait a little and check again.
                    log.warning("_acme-challenge.{0} does not contain (only ?) {1} on nameserver {2}. We sleep for 1mn before checking again...".format(domain, record, x))
                    addr.add(x)
                    time.sleep(60)

    # ask Let's Encrypt to verify each challenge
    for domain in pending.keys():
        challenge, token, keyauthorization, record, zone = pending[domain]
        log.debug("Asking authority to verify challenge {0}...".format(domain))
        code, result = _send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                raise ValueError("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))))
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                log.debug("{0} verified!".format(domain))
                break
            else:
                raise ValueError("{0} challenge did not pass: {1}".format(
                    domain, challenge_status))

    # get the new certificate
    log.debug("Signing certificate...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result = _send_signed_request(CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": _b64(csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

    # return signed certificate!
    log.debug("Certificate signed!")
    if not dns_zone_update_server:
      log.debug("You can now remove the _acme-challenge records from your DNS zone.")
    else:
      log.debug('Removing DNS records added for ACME challange...')
      for domain in pending.keys():
        record = pending[domain][3]
        zone = pending[domain][4]
        log.debug('Removing TXT record {0} in DNS zone {1}'.format('_acme-challenge.'+domain,zone))
        update = dns.update.Update(zone, keyring=dns_zone_keyring, keyalgorithm=dns_update_algo)
        update.delete('_acme-challenge.'+domain+'.', 'TXT')
        response = dns.query.tcp(update, dns_zone_update_server, timeout=10)

    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script assists you in the process of getting a signed TLS certificate from
            Let's Encrypt using the DNS challenge of the ACME protocol.
            It will need to have access to your private account key, so PLEASE READ THROUGH IT!
            It's only ~200 lines, so it won't take long.

            ===Example Usage===
            python acme_tiny_dns01.py --account-key ./account.key --csr ./domain.csr > signed.crt
            ===================
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--quiet", action="store_const", const=logging.INFO, help="suppress output except for errors")
    parser.add_argument("--skip-check", action="store_true", help="skip checking for DNS records")
    parser.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")
    parser.add_argument("--contact-mail", help="an optional email address to receive expiration alerts from Let's Encrypt (no guarantee)")
    parser.add_argument("--dns-zone-update", metavar='DNS_SERVER', help="optionally automatically provision TXT record for challange on the DNS Server specified by this option using DNS zone updates")
    parser.add_argument("--dns-zone-key", nargs=3, metavar=('KEY_NAME','SECRET','ALGORITHM'), help="optional. if --dns-zone-update is used, the key name, secret and algorithm for the TSIG key which may be used to authenticate the DNS zone updates")
    parser.add_argument("--dns-zone", help="optional. if --dns-zone-update is used, specifies in which dns zone the dns zone update should be made. Per default, the challange domain (_acme-challenge.your.domain) is assumed have it's own zone. A number can be specified if a parent domain of the challange domain is the dns zone to change. Alternatively, the name of the dns zone may be explicitly specified.")

    args = parser.parse_args(argv)

    if not args.dns_zone_update and ( args.dns_zone_key or args.dns_zone ):
      ArgumentParser.error("--dns-zone and --dns-zone-key can only be used together with --dns-zone-update")

    dns_update_algo = None
    dns_zone_keyring = None
    if args.dns_zone_key:
      dns_zone_keyring = dns.tsigkeyring.from_text({args.dns_zone_key[0]:args.dns_zone_key[1]})
      dns_update_algo = args.dns_zone_key[2]

    if args.dns_zone and args.dns_zone.isdigit():
      args.dns_zone = int(args.dns_zone)

    LOGGER.setLevel(args.quiet or LOGGER.level)
    signed_crt = get_crt(args.account_key, args.csr, args.skip_check, log=LOGGER, CA=args.ca, contact_mail=args.contact_mail,
                         dns_zone_update_server=args.dns_zone_update, dns_zone_keyring=dns_zone_keyring, dns_zone=args.dns_zone,
                         dns_update_algo=dns_update_algo)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
