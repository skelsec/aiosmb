"""Shared command-line help for aiosmb console entry points."""

import argparse
import sys
import textwrap

from aiosmb._version import __version__


class AIOSMBHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Preserve examples and show only defaults that carry useful information."""

    def _get_help_string(self, action):
        help_text = action.help
        if (
            help_text
            and "%(default)" not in help_text
            and action.default not in (argparse.SUPPRESS, None, False, "", 0)
        ):
            help_text += " (default: %(default)s)"
        return help_text


SMB_URL_HELP = textwrap.dedent(
    r"""
    SMB CONNECTION URL

      <dialect>[-<transport>]+<auth>://[<domain>\]<user>[:<secret>]@<host>[:<port>][/<path>][?<query>]

    Dialects:
      smb, smb2, smb3, smb202, smb210, smb300, smb302, smb311

    Transports:
      tcp (default) or quic. For example: smb3-quic+ntlm-password://...

    Common authentication forms:
      ntlm-password       plaintext password in the URL
      ntlm-pwprompt       prompt for the password instead of storing it in the URL
      ntlm-pwhex          hex-encoded password
      ntlm-pwb64          base64-encoded password
      ntlm-nt             NT hash
      ntlm-none           anonymous/null-session authentication
      kerberos-password   Kerberos with a password
      kerberos-rc4        Kerberos with an RC4/NT key
      kerberos-aes        Kerberos with an AES-128 or AES-256 key
      kerberos-ccache     path to a Kerberos ccache
      kerberos-keytab     path to a Kerberos keytab
      kerberos-kirbi      path to a KIRBI ticket
      kerberos-pfx        path to a PFX certificate; use keydata for its password
      sspi-ntlm           current Windows credentials through SSPI
      sspi-kerberos       current Windows credentials through SSPI

      File-backed Kerberos secrets also accept hex and base64 forms such as
      kerberos-ccachehex, kerberos-ccacheb64, kerberos-keytabhex,
      kerberos-keytabb64, kerberos-kirbihex, and kerberos-kirbib64.

    Remote authentication subprotocols:
      wsnet-ntlm, wsnet-kerberos
      wsnetdirect-ntlm, wsnetdirect-kerberos
      sspiproxy-ntlm, sspiproxy-kerberos

    Target and SMB query parameters:
      timeout=<seconds>             connection timeout
      serverip=<address>            connect to this address while retaining the URL hostname
      dc=<address>                  Kerberos domain-controller address
      dns=<address>                 DNS server address
      privport=0|1                  request a privileged source port
      fragment=<level>              SMB request fragmentation level (1-5)
      compress=0|1                  advertise and use SMB compression
      compress_min=<bytes>          minimum payload size to compress
      compress_algorithms=<names>   comma-separated lznt1,lz77,lz77_huffman,lz4

    NTLM query parameters:
      ntlmnosig=0|1, ntlmdisableess=0|1, ntlmworkstation=<name>,
      ntlmdomain=<name>, ntlmflags=<integer>, ntlmversionmajor=<integer>,
      ntlmversionminor=<integer>, ntlmversionbuild=<integer>

    Kerberos query parameters:
      altname=<principal>, altdomain=<realm>, etype=<integer>, dcc=<address>,
      dnsc=<address>, realmc=<realm>, certdata=<value>, keydata=<value>

    TLS/QUIC query parameters:
      sslca=<path>, sslcert=<path>, sslkey=<path>, sslpassword=<value>,
      sslverify=<boolean>

    Proxy query parameters:
      proxytype=<socks4|socks5|http|...>, proxyhost/proxyserver=<address>,
      proxyport=<port>, proxybind=<boolean>, proxyuser=<name>,
      proxypass=<secret>, proxytimeout=<seconds>, proxyetimeout=<seconds>,
      proxybsize=<bytes>, proxyuserid=<id>, proxyagentid=<id>

      Add proxy1type/proxy1host/proxy1port, then proxy2..., for a proxy chain.

    Remote-authentication query parameters:
      wsip=<address>, wsport=<port>, wsproto=<ws|wss>
      authhost=<address>, authport=<port>, authproto=<ws|wss>,
      authagentid=<id>

    Examples:
      Anonymous:
        'smb2+ntlm-none://files.example'

      NTLM password:
        'smb3+ntlm-password://LAB%5Calice:PASSWORD@files.example'

      Prompt for the NTLM password:
        'smb3+ntlm-pwprompt://LAB%5Calice@files.example'

      Kerberos with an explicit domain controller:
        'smb3+kerberos-password://LAB.EXAMPLE%5Calice:PASSWORD@files.example?dc=10.0.0.10'

      Through a SOCKS5 proxy:
        'smb3+ntlm-password://LAB%5Calice:PASSWORD@files.example?proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080'

    Quote URLs in the shell. Percent-encode reserved characters in usernames,
    passwords, paths, and query values; %5C is a domain/user backslash.
    Boolean query values use 0 or 1.
    """
).strip()


CONNECTION_EPILOG = textwrap.dedent(
    r"""
    Connection URL:
      <dialect>+<auth>://[<domain>\]<user>[:<secret>]@<host>[:<port>][/<path>]

      Example: 'smb3+ntlm-pwprompt://LAB%5Calice@files.example'
      Use --help-url for authentication types, transport settings, SMB tuning,
      Kerberos/NTLM parameters, proxy chaining, and more examples.
    """
).strip()


class SMBURLHelpAction(argparse.Action):
    """Print connection URL documentation without requiring other arguments."""

    def __init__(
        self,
        option_strings,
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        help=None,
    ):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        parser._print_message(SMB_URL_HELP + "\n", sys.stdout)
        parser.exit()


def make_parser(description, prog=None, epilog=None):
    parser = argparse.ArgumentParser(
        prog=prog,
        description=description,
        epilog=epilog,
        formatter_class=AIOSMBHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {}".format(__version__),
    )
    return parser


def add_url_help(parser):
    parser.add_argument(
        "--help-url",
        action=SMBURLHelpAction,
        help=(
            "show SMB URL authentication, transport, tuning, and proxy "
            "parameters"
        ),
    )


def add_verbosity(group):
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase logging detail; repeat for protocol-level diagnostics",
    )
