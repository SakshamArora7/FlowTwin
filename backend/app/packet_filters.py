"""A deliberately bounded display-filter subset compiled to SQL expressions, never eval."""
import ipaddress
import math
import re

from sqlalchemy import and_, or_, not_, true


class FilterError(ValueError):
    pass


TOKEN = re.compile(r'''\s*(&&|\|\||==|!=|>=|<=|[()!<>]|"[^"\n]*"|'[^'\n]*'|[A-Za-z0-9_.:/+\-]+)''')
COMPARISONS = {"==", "!=", ">", ">=", "<", "<="}


def compile_filter(expression, columns, relative_time=None):
    expression = expression.strip()
    if len(expression) > 1024:
        raise FilterError("Filter exceeds 1,024 characters")
    tokens, position = [], 0
    while position < len(expression):
        match = TOKEN.match(expression, position)
        if not match:
            raise FilterError(f"Unexpected character at position {position + 1}")
        tokens.append(match[1])
        position = match.end()
    if len(tokens) > 128:
        raise FilterError("Filter exceeds 128 tokens")
    if not tokens:
        return true()
    c, cursor = columns, 0
    relative_time = c.timestamp if relative_time is None else relative_time

    def peek():
        return tokens[cursor].lower() if cursor < len(tokens) else ""

    def take():
        nonlocal cursor
        if cursor >= len(tokens):
            raise FilterError("Expected a field, protocol, or value at end of filter")
        token = tokens[cursor]
        cursor += 1
        return token

    def compare(column, operator, value):
        if operator == "==": return column == value
        if operator == "!=": return column != value
        if operator == ">": return column > value
        if operator == ">=": return column >= value
        if operator == "<": return column < value
        return column <= value

    def atom(depth):
        if depth > 12:
            raise FilterError("Filter nesting exceeds 12 levels")
        if peek() in {"!", "not"}:
            take()
            return not_(atom(depth + 1))
        if peek() == "(":
            take()
            result = parse_or(depth + 1)
            if take() != ")":
                raise FilterError("Expected closing parenthesis")
            return result
        field = take().lower()
        protocol_scope = {
            "ip": c.ip_version == 4, "ipv6": c.ip_version == 6,
            "tcp": c.transport == "TCP", "udp": c.transport == "UDP", "icmp": c.transport == "ICMP",
            **{name: c.protocol == name.upper() for name in ("arp", "dns", "http", "tls")},
        }
        if field in protocol_scope:
            return protocol_scope[field]
        flags = {"tcp.flags.fin": 1, "tcp.flags.syn": 2, "tcp.flags.rst": 4, "tcp.flags.ack": 16}
        if field in flags:
            flag = c.tcp_flags.op("&")(flags[field]) != 0
            if peek() not in COMPARISONS:
                return and_(c.transport == "TCP", flag)
            op, raw = take(), take().lower()
            if op not in {"==", "!="} or raw not in {"true", "false", "0", "1"}:
                raise FilterError("TCP flag comparisons require == or != and true/false/0/1")
            wanted = raw in {"true", "1"}
            return and_(c.transport == "TCP", flag if wanted == (op == "==") else not_(flag))
        if peek() not in COMPARISONS:
            raise FilterError(f"Expected a comparison after {field}")
        op, raw = take(), take().strip("\"'")
        if field in {f"{family}.{suffix}" for family in ("ip", "ipv6") for suffix in ("src", "dst", "addr")}:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise FilterError("Expected an exact IPv4/IPv6 address (CIDR is not supported)") from exc
            version = 4 if field.startswith("ip.") else 6
            if address.version != version or op not in {"==", "!="}:
                raise FilterError("IP address family or comparison does not match the field")
            selected = [c.source, c.destination] if field.endswith("addr") else [c.source if field.endswith("src") else c.destination]
            match = or_(*(column == str(address) for column in selected))
            return and_(c.ip_version == version, match if op == "==" else not_(match))
        ports = {f"{proto}.{suffix}": (proto.upper(), suffix) for proto in ("tcp", "udp") for suffix in ("port", "srcport", "dstport")}
        numeric = {"frame.len": c.length, "frame.number": c.number, "frame.time_epoch": c.timestamp,
                   "frame.time_relative": relative_time, "tcp.stream": c.stream_id}
        if field not in numeric and field not in ports:
            raise FilterError(f"Unsupported field: {field}")
        try:
            value = float(raw) if field.startswith("frame.time_") else int(raw)
            if not math.isfinite(value) or value < 0 or value > (65535 if field in ports else 1e15):
                raise ValueError()
        except ValueError as exc:
            raise FilterError(f"Invalid numeric value for {field}") from exc
        if field in ports:
            protocol, suffix = ports[field]
            selected = [c.source_port, c.destination_port] if suffix == "port" else [c.source_port if suffix == "srcport" else c.destination_port]
            match = or_(*(compare(column, "==" if op == "!=" else op, value) for column in selected))
            return and_(c.transport == protocol, not_(match) if op == "!=" else match)
        return compare(numeric[field], op, value)

    def parse_and(depth):
        result = atom(depth)
        while peek() in {"&&", "and"}:
            take()
            result = and_(result, atom(depth))
        return result

    def parse_or(depth):
        result = parse_and(depth)
        while peek() in {"||", "or"}:
            take()
            result = or_(result, parse_and(depth))
        return result

    result = parse_or(0)
    if cursor != len(tokens):
        raise FilterError(f"Unexpected token: {tokens[cursor]}")
    return result
