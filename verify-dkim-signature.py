#!/usr/bin/env python3
from typing import Dict
import re
import sys
import email.header
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence, DerNull, DerOctetString, DerObjectId
import Crypto.Util
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pathlib import Path
import dns.resolver
from base64 import b64encode, b64decode


# RFC info about SMTP here : https://datatracker.ietf.org/doc/html/rfc5321
# RFC info about DKIM here : https://datatracker.ietf.org/doc/html/rfc6376


def hash_body(body: bytes) -> str:
    # https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.3
    # https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.4

    # canonical type of - headers/body : simple or relaxed
    type_algo = dkim_parameter['c'].split('/')
    if len(type_algo) == 1:
        type_algo.append("simple")

    start_body_position = start_body + 4

    # body length for hash is parameter 'l' in DKIM-Signature header
    if 'l' in dkim_parameter.keys():
        canonical_body = re.sub(b"[\\r\\n]+$", b"\r\n",
                                mail_bin[start_body_position: start_body_position + int(dkim_parameter['l'])])
    else:
        canonical_body = re.sub(b"[\\r\\n]+$", b"\r\n", mail_bin[start_body_position:])

    # the last line of body finish always with only one CRLF
    if body != b"":
        canonical_body = re.sub(b"[\\r\\n]+$", b"\r\n", body)

    if type_algo[1] == "relaxed":
        canonical_body = re.sub(b"[ \t]+\r\n", b"\r\n", canonical_body)
        canonical_body = re.sub(b"[ \t]+", b" ", canonical_body)

    # if body is empty, add one null line
    if canonical_body == "":
        canonical_body += b"\r\n"

    # for debug
    # f = open("body.txt", "wb")
    # f.write(canonical_body)
    # f.close()

    bh = ""
    if dkim_parameter['a'] == "rsa-sha1":
        bh = b64encode(SHA1.new(canonical_body).digest())
    elif dkim_parameter['a'] == "rsa-sha256":
        bh = b64encode(SHA256.new(canonical_body).digest())

    return bh.decode()


def get_public_key(domain: str, selector: str):

    dkim_pub = ""

    if domain == "gmail.com" and selector == "20161025":
        # The 20161025._domainkey.gmail.com public DKIM key has been revoked by Google. This is a copy.
        # 20161025._domainkey.gmail.com
        dkim_pub = "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviPGBk4ZB64UfSqWyAicdR7lodhytae+EYRQVtKDhM+1mXjEqRtP/pDT3sBhazkmA48n2k5NJUyMEoO8nc2r6sUA+/Dom5jRBZp6qDKJOwjJ5R/OpHamlRG+YRJQqRtqEgSiJWG7h7efGYWmh4URhFM9k9+rmG/CwCgwx7Et+c8OMlngaLl04/bPmfpjdEyLWyNimk761CX6KymzYiRDNz1MOJOJ7OzFaS4PFbVLn0m5mf0HVNtBpPwWuCNvaFVflUYxEyblbB6h/oWOPGbzoSgtRA47SHV53SwZjIsVpbq4LxUW9IxAEwYzGcSgZ4n5Q8X8TndowsDUzoccPFGhdwIDAQAB"
    elif domain == "gmail.com" and selector == "20120113":
        # The 20120113._domainkey.gmail.com public DKIM key has been revoked by Google. This is a copy.
        # 20120113._domainkey.gmail.com
        dkim_pub = "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Kd87/UeJjenpabgbFwh+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQs8g3FgD2Ap3ZB5DekAo5wMmk4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbbhzY8i+RQ9DpSVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5OctMEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZK9vlfuac0598HY+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21MycBX5jYchHjPY/wIDAQAB"
    else:
        # Public DKIM key extraction from DNS records
        dns.resolver.Resolver().nameservers = ['8.8.8.8', '4.4.4.4', '1.1.1.1', '208.67.222.222', '208.67.220.220']
        dns_answer = dns.resolver.resolve("{}._domainkey.{}.".format(selector, domain), "TXT").response.answer
        for key in dns_answer:
            if re.match(".*TXT.*p=.*", key.to_text()):
                dkim_pub = key.to_text()
                break

    dkim_pub = re.sub(r'[\s"]+', '', dkim_pub)
    p = re.search(r'p=([\w/+]*)', dkim_pub).group(1)

    if dkim_pub == "":
        return None

    pub_key = RSA.importKey(b64decode(p))
    return pub_key


def parse_dkim_header() -> Dict[str, str]:
    parameters = {}
    parts = dkim_header.split(";")
    for part in parts:
        if part == '':
            continue
        key, value = part.split("=", 1)
        parameters[key.strip()] = re.sub(r'(\t|\r|\n|\s)', "", value)
    return parameters


def hash_headers(header_to_hash: str):
    type_algo = dkim_parameter['c'].split('/')
    headers_passed = {}  # we can have to hash more than one same type header, this is for avoid double hash

    header_to_hash_list = header_to_hash.split(":")
    # DKIM header is always the last
    header_to_hash_list.append("DKIM-Signature")

    headers = b""
    header_to_hash_number = 0  # we need to know this, in case for one or more DKIM-Signature to hash
    # https://datatracker.ietf.org/doc/html/rfc6376#section-5.4
    for header_to_hash in header_to_hash_list:
        header_to_hash_number = header_to_hash_number + 1
        if header_to_hash not in headers_passed.keys():
            headers_passed[header_to_hash] = 1
        else:
            headers_passed[header_to_hash] = headers_passed[header_to_hash] + 1
        iteration = 1
        for header in mail_headers:
            if re.match(b"^" + header_to_hash.encode() + b"\\s*:.*", header, re.IGNORECASE):
                if iteration != headers_passed[header_to_hash]:
                    iteration = iteration + 1
                    continue
            else:
                continue

            if type_algo[0] == "relaxed":
                # https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.2
                value = header[header.find(b':') + 1:].strip()
                is_dkim = False
                if re.match(b"DKIM-Signature", header, re.IGNORECASE):
                    value = dkim_header.encode()
                    is_dkim = True
                value = re.sub(b'\r\n', b"", value)
                value = re.sub(b'\\s+', b" ", value) + b"\r\n"
                if is_dkim and header_to_hash_number == len(header_to_hash_list):
                    value = re.sub(b'b=[\\w\\s/+=]{25,}', b"b=", value.rstrip())
                headers += header_to_hash.lower().encode() + b":" + value
                break
            else:
                # https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.1
                value = header
                if (re.match(b"DKIM-Signature", header, re.IGNORECASE)
                        and header_to_hash_number == len(header_to_hash_list)):
                    value = re.sub(b'b=[\\w\\s/+=]{25,}', b"b=", header.rstrip())
                headers += value
                break

    # for debug
    # f = open("headers.txt", "wb")
    # f.write(headers)
    # f.close()

    if dkim_parameter['a'].lower() == "rsa-sha1":
        return SHA1.new(headers)
    elif dkim_parameter['a'].lower() == "rsa-sha256":
        return SHA256.new(headers)
    else:
        return None


def pkcs1_v1_5_encode(msg_hash, em_len: int) -> bytes:
    # code from EMSA_PKCS1_V1_5_ENCODE
    # https://github.com/dlitz/pycrypto/blob/v2.7a1/lib/Crypto/Signature/PKCS1_v1_5.py#L173

    digest_algo = DerSequence([DerObjectId(msg_hash.oid)])
    digest_algo = digest_algo.append(DerNull())

    digest = DerOctetString(msg_hash.digest())
    digest_info = DerSequence([digest_algo, digest.encode()]).encode()

    # We need at least 11 bytes for the remaining data: 3 fixed bytes and
    # at least 8 bytes of padding.
    if em_len < len(digest_info) + 11:
        raise TypeError("Selected hash algorith has a too long digest (%d bytes)." % len(digest.payload))
    ps = b'\xFF' * (em_len - len(digest_info) - 3)
    return b'\x00\x01' + ps + b'\x00' + digest_info


def verify_signature() -> bool:
    em_len = Crypto.Util.number.size(public_key.n) // 8

    signature_long = bytes_to_long(signature)
    expected_message_int = pow(signature_long, public_key.e, public_key.n)
    expected_message = long_to_bytes(expected_message_int, em_len)

    padded_hash = pkcs1_v1_5_encode(hashed_header, em_len)

    return padded_hash == expected_message


if __name__ == '__main__':
    # EML file to check
    if len(sys.argv) > 1:
        mail_file = sys.argv[1]
    else:
        print("Missing argument. Correct syntax is : verify-dkim-signature.py \"email.eml\"")
        exit(1)

    print(f"EML : {mail_file}")

    mail_file_check = Path(mail_file)
    if not mail_file_check.exists():
        print(f"Error! The file {mail_file} is missing.")
        exit(1)

    mail_bin = open(mail_file, "rb").read()

    mail = email.message_from_bytes(open(mail_file, "rb").read())

    # get all headers
    # https://datatracker.ietf.org/doc/html/rfc6376#section-5.4.2
    dkim_header_number = 0
    mail_headers = []
    mail_header_body = b""
    start_body = mail_bin.find(b"\r\n\r\n")
    if start_body < 0:
        print("Please, use CRLF separator for new line in your EML file!")
        exit(1)
    get_mail_headers = mail_bin[0: start_body + 2]
    get_mail_headers = get_mail_headers.splitlines(True)
    get_mail_headers = reversed(get_mail_headers)
    for line in get_mail_headers:
        if re.match(b"^\\w[\\w\\s-]+:.*", line):
            # header field start
            mail_headers.append(line + mail_header_body)
            mail_header_body = b""
            if re.match(b"^DKIM-Signature\\s*:+", line, re.IGNORECASE):
                dkim_header_number = dkim_header_number + 1
        else:
            # header value
            mail_header_body = line + mail_header_body

    if len(mail_headers) == 0 or dkim_header_number == 0:
        print("No headers found or DKIM signature is missing. Exit!")
        exit(1)

    dkim_header = ""
    dkim_parameter = []
    dkim_header_number_actually = 0

    while True:
        # search for the first non-tested DKIM signature
        dkim_header_number = 0
        for headers in mail_headers:
            if re.match(b"^DKIM-Signature\\s*:+", headers, re.IGNORECASE):
                if dkim_header_number != dkim_header_number_actually:
                    dkim_header_number = dkim_header_number + 1
                    continue
                if dkim_header_number_actually > 0:
                    print("We will verify with another DKIM signature.")
                dkim_header = headers[headers.find(b':') + 1:].decode().strip()
                dkim_parameter = parse_dkim_header()
                dkim_header_number_actually = dkim_header_number_actually + 1  # next DKIM if we need
                break

        # no more DKIM signatures
        if dkim_header == "":
            print("No more DKIM signatures to verify. Signature is NOT valid.")
            break

        body_hash = hash_body(b"")

        if body_hash == dkim_parameter['bh']:
            print("Body hash matches.")
        else:
            print(f"Body hash mismatch.\nGot \"{body_hash}\" but expected \"{dkim_parameter['bh']}\".")
            break

        public_key = get_public_key(dkim_parameter['d'], dkim_parameter['s'])
        if public_key is None:
            print("Public DKIM key is missing.")
            dkim_header = ""
            continue

        hashed_header = hash_headers(dkim_parameter['h'])

        signature = b64decode(dkim_parameter['b'])

        if verify_signature():
            print("Signature is VALID.")
            break
        else:
            print("Signature is NOT valid.")
            dkim_header = ""
