"""Raw TCP BGP session - Simpson redirect-ip builder and send_via_tcp."""

import socket
import struct
import time
from typing import Optional, Tuple

# BGP Constants
BGP_MARKER = b"\xff" * 16
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4

AFI_IPV4 = 1
SAFI_FLOWSPEC_VPN = 134

FS_DEST_PREFIX = 1
FS_SRC_PREFIX = 2

PA_ORIGIN = 1
PA_AS_PATH = 2
PA_MP_REACH_NLRI = 14
PA_EXT_COMMUNITY = 16

EXTCOMM_RT_2BYTE = (0x00, 0x02)
EXTCOMM_RT_IP = (0x01, 0x02)
EXTCOMM_RT_4BYTE = (0x02, 0x02)
EXTCOMM_REDIRECT = (0x08, 0x00)


def _build_bgp_header(msg_type: int, payload: bytes) -> bytes:
    length = 19 + len(payload)
    return BGP_MARKER + struct.pack("!HB", length, msg_type) + payload


def _encode_prefix(prefix_str: str) -> Tuple[bytes, int]:
    ip_str, plen_str = prefix_str.split("/")
    plen = int(plen_str)
    ip_bytes = socket.inet_aton(ip_str)
    num_octets = (plen + 7) // 8
    return ip_bytes[:num_octets], plen


def _encode_rd(rd_str: str) -> bytes:
    parts = rd_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid RD format: {rd_str}")
    try:
        socket.inet_aton(parts[0])
        ip_bytes = socket.inet_aton(parts[0])
        nn = int(parts[1])
        return struct.pack("!H", 1) + ip_bytes + struct.pack("!H", nn)
    except socket.error:
        pass
    asn = int(parts[0])
    nn = int(parts[1])
    if asn <= 65535:
        return struct.pack("!HHI", 0, asn, nn)
    return struct.pack("!HIH", 2, asn, nn)


def _encode_rt_extcomm(rt_str: str) -> bytes:
    parts = rt_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid RT: {rt_str}")
    if "." in parts[0]:
        ip_bytes = socket.inet_aton(parts[0])
        nn = int(parts[1])
        return bytes(EXTCOMM_RT_IP) + ip_bytes + struct.pack("!H", nn)
    asn = int(parts[0])
    nn = int(parts[1])
    if asn <= 65535:
        return bytes(EXTCOMM_RT_2BYTE) + struct.pack("!HI", asn, nn)
    return bytes(EXTCOMM_RT_4BYTE) + struct.pack("!IH", asn, nn)


def _encode_flowspec_nlri(dest_prefix: Optional[str] = None, src_prefix: Optional[str] = None) -> bytes:
    nlri = b""
    if dest_prefix:
        prefix_bytes, plen = _encode_prefix(dest_prefix)
        nlri += struct.pack("!BB", FS_DEST_PREFIX, plen) + prefix_bytes
    if src_prefix:
        prefix_bytes, plen = _encode_prefix(src_prefix)
        nlri += struct.pack("!BB", FS_SRC_PREFIX, plen) + prefix_bytes
    return nlri


class SimpsonRedirectBuilder:
    """Builds BGP UPDATE for Simpson redirect-ip (FlowSpec-VPN)."""

    def build_update(
        self,
        rd: str,
        redirect_ip: str,
        rt: str,
        dest_prefix: Optional[str] = None,
        src_prefix: Optional[str] = None,
        local_pref: int = 100,
        origin: int = 0,
    ) -> bytes:
        attrs = b""
        attrs += self._build_attr(0x40, PA_ORIGIN, struct.pack("!B", origin))
        attrs += self._build_attr(0x40, PA_AS_PATH, b"")
        attrs += self._build_attr(0x40, 5, struct.pack("!I", local_pref))

        simpson_extcomm = bytes(EXTCOMM_REDIRECT) + b"\x00\x00\x00\x00\x00\x01"
        ext_comms = simpson_extcomm + _encode_rt_extcomm(rt)
        attrs += self._build_attr(0xC0, PA_EXT_COMMUNITY, ext_comms)

        nh_rd = b"\x00" * 8
        nh_ip = socket.inet_aton(redirect_ip)
        next_hop = nh_rd + nh_ip

        fs_nlri = _encode_flowspec_nlri(dest_prefix, src_prefix)
        rd_bytes = _encode_rd(rd)
        nlri_with_rd = rd_bytes + fs_nlri
        nlri_len = len(nlri_with_rd)
        if nlri_len < 240:
            nlri_block = struct.pack("!B", nlri_len) + nlri_with_rd
        else:
            nlri_block = struct.pack("!BH", 0xF0 | (nlri_len >> 8), nlri_len & 0xFF) + nlri_with_rd

        mp_reach = struct.pack("!HBB", AFI_IPV4, SAFI_FLOWSPEC_VPN, len(next_hop))
        mp_reach += next_hop + b"\x00" + nlri_block
        attrs += self._build_attr(0x80, PA_MP_REACH_NLRI, mp_reach)

        update_payload = struct.pack("!HH", 0, len(attrs)) + attrs
        return _build_bgp_header(BGP_UPDATE, update_payload)

    @staticmethod
    def _build_attr(flags: int, type_code: int, value: bytes) -> bytes:
        if len(value) > 255:
            flags |= 0x10
            return struct.pack("!BBH", flags, type_code, len(value)) + value
        return struct.pack("!BBB", flags, type_code, len(value)) + value

    def send_via_tcp(
        self,
        target_ip: str,
        target_port: int,
        update_bytes: bytes,
        local_as: int = 65200,
        peer_as: int = 1234567,
        hold_time: int = 600,
        router_id: str = "100.64.6.134",
        local_address: str = "100.64.6.134",
    ) -> dict:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.bind((local_address, 0))
            sock.connect((target_ip, target_port))

            open_msg = self._build_open(local_as, hold_time, router_id)
            sock.sendall(open_msg)
            data = sock.recv(4096)
            if len(data) < 19:
                return {"success": False, "error": "No OPEN received"}

            keepalive = _build_bgp_header(BGP_KEEPALIVE, b"")
            sock.sendall(keepalive)
            time.sleep(1)
            sock.recv(4096)

            sock.sendall(update_bytes)
            time.sleep(3)
            sock.sendall(keepalive)
            time.sleep(2)

            notification = _build_bgp_header(BGP_NOTIFICATION, struct.pack("!BB", 6, 0))
            sock.sendall(notification)
            sock.close()

            return {"success": True, "bytes_sent": len(update_bytes)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _build_open(local_as: int, hold_time: int, router_id: str) -> bytes:
        version = 4
        rid_bytes = socket.inet_aton(router_id)
        cap_4byte_as = struct.pack("!BBI", 65, 4, local_as)
        cap_mp = struct.pack("!BBHBB", 1, 4, AFI_IPV4, 0, SAFI_FLOWSPEC_VPN)
        caps = cap_4byte_as + cap_mp
        opt_params = struct.pack("!BB", 2, len(caps)) + caps
        my_as = local_as if local_as <= 65535 else 23456
        payload = struct.pack("!BHH", version, my_as, hold_time)
        payload += rid_bytes + struct.pack("!B", len(opt_params)) + opt_params
        return _build_bgp_header(BGP_OPEN, payload)

    @staticmethod
    def hexdump(data: bytes) -> str:
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_str:<48s}  {ascii_str}")
        return "\n".join(lines)


def _encode_redirect_rt_extcomm(rt_str: str) -> bytes:
    """Encode redirect-to-rt extended community (RFC 5575 / RFC 7674).
    2-byte ASN: type (0x80, 0x08), 4-byte ASN: type (0x82, 0x08)."""
    parts = rt_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid redirect RT: {rt_str}")
    asn = int(parts[0])
    nn = int(parts[1])
    if asn <= 65535:
        return struct.pack("!BBHI", 0x80, 0x08, asn, nn)
    return struct.pack("!BBIH", 0x82, 0x08, asn, nn)


class CombinedRedirectBuilder(SimpsonRedirectBuilder):
    """Builds BGP UPDATE with BOTH Simpson redirect-ip AND redirect-to-rt."""

    def build_combined_update(
        self,
        rd: str,
        redirect_ip: str,
        redirect_rt: str,
        rt: str,
        dest_prefix: Optional[str] = None,
        src_prefix: Optional[str] = None,
        local_pref: int = 100,
        origin: int = 0,
        local_as: int = 65200,
    ) -> bytes:
        attrs = b""
        attrs += self._build_attr(0x40, PA_ORIGIN, struct.pack("!B", origin))
        as_path_seg = struct.pack("!BBI", 2, 1, local_as)
        attrs += self._build_attr(0x40, PA_AS_PATH, as_path_seg)
        attrs += self._build_attr(0x40, 5, struct.pack("!I", local_pref))

        simpson_extcomm = bytes(EXTCOMM_REDIRECT) + b"\x00\x00\x00\x00\x00\x00"
        redirect_rt_extcomm = _encode_redirect_rt_extcomm(redirect_rt)
        rt_extcomm = _encode_rt_extcomm(rt)
        ext_comms = simpson_extcomm + redirect_rt_extcomm + rt_extcomm
        attrs += self._build_attr(0xC0, PA_EXT_COMMUNITY, ext_comms)

        nh_rd = b"\x00" * 8
        nh_ip = socket.inet_aton(redirect_ip)
        next_hop = nh_rd + nh_ip

        fs_nlri = _encode_flowspec_nlri(dest_prefix, src_prefix)
        rd_bytes = _encode_rd(rd)
        nlri_with_rd = rd_bytes + fs_nlri
        nlri_len = len(nlri_with_rd)
        if nlri_len < 240:
            nlri_block = struct.pack("!B", nlri_len) + nlri_with_rd
        else:
            nlri_block = struct.pack("!BH", 0xF0 | (nlri_len >> 8), nlri_len & 0xFF) + nlri_with_rd

        mp_reach = struct.pack("!HBB", AFI_IPV4, SAFI_FLOWSPEC_VPN, len(next_hop))
        mp_reach += next_hop + b"\x00" + nlri_block
        attrs += self._build_attr(0x80, PA_MP_REACH_NLRI, mp_reach)

        update_payload = struct.pack("!HH", 0, len(attrs)) + attrs
        return _build_bgp_header(BGP_UPDATE, update_payload)

    def send_and_hold(
        self,
        target_ip: str,
        target_port: int,
        update_bytes: bytes,
        hold_seconds: int = 120,
        local_as: int = 65200,
        peer_as: int = 1234567,
        hold_time: int = 600,
        router_id: str = "100.64.6.134",
        local_address: str = "100.64.6.134",
    ) -> dict:
        """Send UPDATE and keep session alive for hold_seconds (for verification)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.bind((local_address, 0))
            sock.connect((target_ip, target_port))

            open_msg = self._build_open(local_as, hold_time, router_id)
            sock.sendall(open_msg)
            data = sock.recv(4096)
            if len(data) < 19:
                return {"success": False, "error": "No OPEN received"}

            keepalive = _build_bgp_header(BGP_KEEPALIVE, b"")
            sock.sendall(keepalive)
            time.sleep(1)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass

            sock.sendall(update_bytes)
            time.sleep(2)

            start = time.time()
            while time.time() - start < hold_seconds:
                sock.sendall(keepalive)
                time.sleep(min(30, hold_seconds - (time.time() - start)))
                try:
                    sock.settimeout(5)
                    sock.recv(4096)
                except socket.timeout:
                    pass

            notification = _build_bgp_header(BGP_NOTIFICATION, struct.pack("!BB", 6, 0))
            sock.sendall(notification)
            sock.close()

            return {"success": True, "bytes_sent": len(update_bytes), "held_seconds": hold_seconds}
        except Exception as e:
            return {"success": False, "error": str(e)}


def send_simpson_redirect(
    target_ip: str,
    rd: str,
    redirect_ip: str,
    rt: str,
    dest_prefix: Optional[str] = None,
    src_prefix: Optional[str] = None,
    target_port: int = 179,
    local_as: int = 65200,
    peer_as: int = 1234567,
) -> dict:
    """Build and send Simpson redirect-ip in one call."""
    builder = SimpsonRedirectBuilder()
    update = builder.build_update(
        rd=rd, redirect_ip=redirect_ip, rt=rt,
        dest_prefix=dest_prefix, src_prefix=src_prefix,
    )
    return builder.send_via_tcp(
        target_ip=target_ip, target_port=target_port,
        update_bytes=update, local_as=local_as, peer_as=peer_as,
    )
