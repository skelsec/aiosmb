"""Command-line entry point for the SMB 2.0.2 local-filesystem server."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict

from asysocks.unicomm.common.target import UniProto, UniTarget

from aiosmb import logger as aiosmb_logger
from aiosmb.examples._cli import add_verbosity, make_parser
from aiosmb.server.filesystem import ShareConfig
from aiosmb.server.server import SMBServer, SMBServerSettings, TRACE_LEVEL


def _port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def parse_share_spec(value, read_only=False):
    """Parse a ``NAME=PATH`` command-line share definition."""

    name, separator, root = value.partition("=")
    name = name.strip()
    root = root.strip()
    if not separator or not name or not root:
        raise ValueError(
            "share definitions must use NAME=PATH with non-empty values"
        )
    return ShareConfig(
        name=name,
        root=Path(root),
        read_only=read_only,
    )


def collect_shares(writable, read_only):
    shares = {}  # type: Dict[str, ShareConfig]
    folded_names = {}
    for value, is_read_only in [
        (item, False) for item in (writable or ())
    ] + [
        (item, True) for item in (read_only or ())
    ]:
        share = parse_share_spec(value, read_only=is_read_only)
        folded = share.name.casefold()
        if folded in folded_names:
            raise ValueError(
                "share {!r} is configured more than once".format(share.name)
            )
        folded_names[folded] = share.name
        shares[share.name] = share
    if not shares:
        raise ValueError("configure at least one --share or --read-only-share")
    return shares


def build_parser(prog="aiosmb-server"):
    parser = make_parser(
        "Serve local directories over SMB 2.0.2",
        prog=prog,
        epilog=(
            "Examples:\n"
            "  Anonymous read-only share:\n"
            "    aiosmb-server --read-only-share Public=/srv/public\n\n"
            "  Authenticated writable share with signing:\n"
            "    aiosmb-server --share Data=/srv/data --username alice "
            "--password PASSWORD --domain LAB --require-signing\n\n"
            "Repeat --share and --read-only-share to expose multiple roots."
        ),
    )
    listener = parser.add_argument_group("listener")
    listener.add_argument(
        "--host",
        default="0.0.0.0",
        help="address on which to accept SMB connections",
    )
    listener.add_argument(
        "--port",
        type=_port,
        default=445,
        help="TCP port on which to accept SMB connections",
    )

    authentication = parser.add_argument_group("authentication")
    authentication.add_argument(
        "-u",
        "--username",
        help="NTLM account name; omit all credentials for anonymous access",
    )
    authentication.add_argument(
        "-d",
        "--domain",
        default="",
        help="NTLM domain; empty means a local account",
    )
    credential = authentication.add_mutually_exclusive_group()
    credential.add_argument(
        "-p",
        "--password",
        help="NTLM account password",
    )
    credential.add_argument(
        "--nt-hash",
        help="32-character hexadecimal NT hash",
    )
    authentication.add_argument(
        "--require-signing",
        action="store_true",
        help="reject unsigned authenticated SMB requests",
    )
    authentication.add_argument(
        "--disable-ess",
        "--downgrade-ess",
        dest="disable_ess",
        action="store_true",
        help=(
            "clear NTLM extended-session-security in the challenge; "
            "does not select NTLMv1 versus NTLMv2"
        ),
    )

    shares = parser.add_argument_group("shares")
    shares.add_argument(
        "-s",
        "--share",
        action="append",
        metavar="NAME=PATH",
        help="writable disk share; repeat for multiple shares",
    )
    shares.add_argument(
        "--read-only-share",
        action="append",
        metavar="NAME=PATH",
        help="read-only disk share; repeat for multiple shares",
    )

    identity = parser.add_argument_group("server identity")
    identity.add_argument(
        "--server-name",
        default="AIOSMB",
        help="server name returned by the srvsvc RPC service",
    )
    identity.add_argument(
        "--server-comment",
        default="aiosmb SMB server",
        help="server comment returned by the srvsvc RPC service",
    )

    diagnostics = parser.add_argument_group("diagnostics")
    add_verbosity(diagnostics)
    return parser


def settings_from_args(args):
    has_secret = args.password is not None or args.nt_hash is not None
    if args.username is None and has_secret:
        raise ValueError("--password/--nt-hash requires --username")
    if args.username is not None and not has_secret:
        raise ValueError(
            "--username requires --password or --nt-hash; "
            "omit all credentials for anonymous access"
        )
    shares = collect_shares(args.share, args.read_only_share)

    if args.username is None:
        if args.require_signing:
            raise ValueError(
                "anonymous access cannot be combined with --require-signing"
            )
        settings = SMBServerSettings.from_anonymous(
            disable_ess=args.disable_ess,
        )
    elif args.nt_hash is not None:
        try:
            decoded = bytes.fromhex(args.nt_hash)
        except ValueError:
            raise ValueError("--nt-hash must be hexadecimal")
        if len(decoded) != 16:
            raise ValueError("--nt-hash must contain exactly 32 hex characters")
        settings = SMBServerSettings.from_nt_hash(
            args.username,
            args.nt_hash,
            args.domain,
            disable_ess=args.disable_ess,
        )
    else:
        settings = SMBServerSettings.from_password(
            args.username,
            args.password,
            args.domain,
            disable_ess=args.disable_ess,
        )

    settings.shares = shares
    settings.RequireSigning = args.require_signing
    settings.ServerName = args.server_name
    settings.ServerComment = args.server_comment
    settings.log_level = (
        TRACE_LEVEL
        if args.verbose > 1
        else logging.DEBUG if args.verbose else logging.INFO
    )
    return settings


async def amain(args):
    settings = settings_from_args(args)
    # Resolve and validate share roots before opening the listening socket.
    settings.create_filesystem_backend()
    target = UniTarget(args.host, args.port, UniProto.SERVER_TCP)
    server = SMBServer(target, settings)
    server_task, error = await server.run()
    if error is not None:
        raise error
    print(
        "Serving {} share(s) on {}:{} {}{}{}".format(
            len(settings.shares),
            args.host,
            args.port,
            (
                "anonymously"
                if args.username is None
                else "as {}".format(args.username)
            ),
            " (signing required)" if settings.RequireSigning else "",
            " (ESS disabled)" if settings.DisableESS else "",
        )
    )
    await server_task


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    log_level = (
        TRACE_LEVEL
        if args.verbose > 1
        else logging.DEBUG if args.verbose else logging.INFO
    )
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    aiosmb_logger.setLevel(log_level)
    aiosmb_logger.propagate = False
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        return 130
    except ValueError as error:
        parser.error(str(error))
    except Exception as error:
        print("aiosmb-server: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    main()
