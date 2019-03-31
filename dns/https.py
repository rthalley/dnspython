"""This code was originally written by Jacob Davis and modified by Kimball Leavitt"""

import requests
import base64
import dns.message
import dns.rdatatype


def _create_query(url, record_type="A", b64=False):
    """
    Creates a DNS query in wire format. Can be encoded in base64 for use in GET method
    :param url: the url to create a query for e.g. example.com
    :param record_type: the desired record type in string format e.g. AAAA
    :param b64: If true will base64url encode the query
    :return: the dns message in wire format or a b64 string
    """
    message = dns.message.make_query(url, dns.rdatatype.from_text(record_type)).to_wire()
    if not b64:
        return message
    else:
        return base64.urlsafe_b64encode(message).decode('utf-8').strip("=")


def _decode_b64_answer(data):
    """
    Decodes a base64 response into wire format
    :param data: the base64 response
    :return: a dns wire message
    """
    message = dns.message.from_wire(data)
    return message


def _get_wire(resolver_url, query_name):
    """
    Official RFC method. Send a get request to resolver/dns-query with param
        dns={base64 encoded dns wire query}

    :param resolver_url: The resolver to query e.g. 1.1.1.1
    :param query_name: The query url e.g. example.com
    :return: a dns.message object received from the resolver
    """
    headers = {"accept": "application/dns-message"}
    payload = {"dns": _create_query(query_name, b64=True)}
    url = "https://{}/dns-query".format(resolver_url)
    try:
        res = requests.get(url, params=payload, headers=headers, stream=True, timeout=10)
        return _decode_b64_answer(res.content)
    except Exception as e:
        return None


def _post_wire(resolver_url, query_name):
    """
    Official RFC method. Send a post request with the body being a raw dns query in wire format
    :param resolver_url: The resolver to query e.g. 1.1.1.1
    :param query_name: The query url e.g. example.com
    :return: a dns.message object received from the resolver
    """
    query = _create_query(query_name)
    headers = {"accept": "application/dns-message", "content-type": "application/dns-message",
               "content-length": str(len(query))}
    url = "https://{}/dns-query".format(resolver_url)
    res = requests.post(url, data=query, headers=headers, stream=True, timeout=10)
    return _decode_b64_answer(res.content)


def _get_json(resolver_url, query_name):
    """
    Not in RFC, but appears to be a common method. Send get with a param name={url}.
        Response in json

    :param resolver_url: The resolver to query e.g. 1.1.1.1
    :param query_name: The query url e.g. example.com
    :return: a json response from the resolver
    """
    headers = {"accept": "application/dns-json"}
    payload = {"name": query_name}
    if resolver_url in ["8.8.8.8", "8.8.4.4", "dns.google.com"]:  # dns.google.com/resolve 4 google
        url = "https://dns.google.com/resolve"
    else:
        url = "https://{}/dns-query".format(resolver_url)
    res = requests.get(url, params=payload, headers=headers, stream=True, timeout=10)
    return res.json()


def get(q, where, json_query=False):
    if json_query:
        r = _get_json(where, q)
    else:
        r = _get_wire(where, q)
    return r


def post(q, where):
    r = _post_wire(where, q)
    return r
