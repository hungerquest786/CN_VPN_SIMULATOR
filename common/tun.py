"""Open a Linux tun device (a virtual network card that gives us raw IP packets)."""
import fcntl
import os
import struct
import subprocess

TUNSETIFF = 0x400454CA   # ioctl number: "set up this interface"
IFF_TUN = 0x0001         # tun = IP packets (tap would be Ethernet frames)
IFF_NO_PI = 0x1000       # no extra 4-byte header in front of each packet
MTU = 1400


def open_tun(name, address_cidr):
    """Create tun device `name`, give it an IP like '10.8.0.1/24', return (fd, name)."""
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    # Use the normal `ip` command for address, MTU and bringing it up.
    subprocess.run(["ip", "addr", "add", address_cidr, "dev", name], check=True)
    subprocess.run(["ip", "link", "set", name, "mtu", str(MTU), "up"], check=True)
    return fd, name
