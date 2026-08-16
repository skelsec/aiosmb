"""Command-line entry point for the SMB 2.0.2 local-filesystem server."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict

from asysocks.unicomm.common.target import UniProto, UniTarget

from aiosmb import logger as aiosmb_logger
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


def build_parser():
    parser = argparse.ArgumentParser(
        prog="aiosmb-server",
        description="Serve local directories over SMB 2.0.2",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="address to listen on (default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=445,
        help="TCP port to listen on (default: %(default)s)",
    )
    parser.add_argument(
        "-u",
        "--username",
        help="NTLM account name; omit all credentials for anonymous access",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="",
        help="NTLM domain (default: empty)",
    )
    credential = parser.add_mutually_exclusive_group()
    credential.add_argument(
        "-p",
        "--password",
        help="NTLM account password",
    )
    credential.add_argument(
        "--nt-hash",
        help="32-character hexadecimal NT hash",
    )
    parser.add_argument(
        "-s",
        "--share",
        action="append",
        metavar="NAME=PATH",
        help="writable disk share; repeat for multiple shares",
    )
    parser.add_argument(
        "--read-only-share",
        action="append",
        metavar="NAME=PATH",
        help="read-only disk share; repeat for multiple shares",
    )
    parser.add_argument(
        "--require-signing",
        action="store_true",
        help="reject unsigned authenticated SMB requests",
    )
    parser.add_argument(
        "--disable-ess",
        "--downgrade-ess",
        dest="disable_ess",
        action="store_true",
        help=(
            "clear NTLM extended-session-security in the challenge; "
            "does not select NTLMv1 versus NTLMv2"
        ),
    )
    parser.add_argument(
        "--server-name",
        default="AIOSMB",
        help="name returned by srvsvc (default: %(default)s)",
    )
    parser.add_argument(
        "--server-comment",
        default="aiosmb SMB server",
        help="comment returned by srvsvc",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase diagnostic logging; use twice for raw packet dumps",
    )
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

    settings.shares = collect_shares(args.share, args.read_only_share)
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
