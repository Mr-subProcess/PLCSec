import random

from plcsec.parsers.bacnet import parse_bacnet_datagram
from plcsec.parsers.dnp3 import parse_dnp3_stream
from plcsec.parsers.ethernet_ip import parse_enip_stream
from plcsec.parsers.iec104 import parse_iec104_stream
from plcsec.parsers.modbus import parse_mbap_stream
from plcsec.parsers.opcua import parse_opcua_stream
from plcsec.parsers.s7 import parse_s7_stream
from plcsec.parsers.tls import parse_dtls_datagram, parse_tls_stream


def test_protocol_parsers_do_not_raise_on_deterministic_random_buffers():
    parsers = (
        parse_mbap_stream,
        parse_s7_stream,
        parse_enip_stream,
        parse_opcua_stream,
        parse_tls_stream,
        parse_iec104_stream,
        parse_dnp3_stream,
        parse_bacnet_datagram,
        parse_dtls_datagram,
    )
    rng = random.Random(0x504C4353)
    for _ in range(1_000):
        payload = rng.randbytes(rng.randrange(0, 512))
        for parser in parsers:
            parser(payload)
