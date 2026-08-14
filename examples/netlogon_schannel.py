"""
Netlogon secure channel (schannel / RPC_C_AUTHN_NETLOGON) example.

Establishes a Netlogon secure channel against a domain controller using a
computer account's NT hash as the shared secret, then makes a signed+sealed
(RPC_C_AUTHN_NETLOGON) call over it.

The secure channel is carried over ncacn_ip_tcp; the named-pipe transport over a
user SMB session is rejected by the DC for schannel.

Usage:
    python netlogon_schannel.py \
        'smb2+ntlm-password://user:pass@dc.example.com' \
        --dc-name DC01 --computer WS01 --domain CONTOSO \
        --nt-hash 8c0f0d9df27154282e1651e0db4ceb32
"""
import argparse
import asyncio
import logging

from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.dcerpc.v5 import nrpc
from aiosmb.dcerpc.v5.interfaces.netlogonmgr import SMBNetlogon


async def run(url, dc_name, computer, domain, nt_hash, aes):
    connection = SMBConnectionFactory.from_url(url).get_connection()
    _, err = await connection.login()
    if err is not None:
        print('[-] SMB login failed:', err)
        return
    print('[+] SMB logged in')

    nl, err = await SMBNetlogon.from_smbconnection(
        connection,
        dc_name=dc_name,
        computer_name=computer,
        domain_name=domain,
        nt_hash=bytes.fromhex(nt_hash),
        aes=aes,
    )
    if err is not None:
        print('[-] Secure channel establishment failed:', err)
        await connection.terminate()
        return

    print('[+] Secure channel established')
    print('    negotiated flags : 0x%08x' % nl.negotiate_flags)
    print('    session key      : %s' % nl.session_key.hex())

    # Signed + sealed RPC call over the secure channel.
    resp, err = await nrpc.hNetrLogonGetCapabilities(
        nl.dce, nl.dc_handle, computer + '\x00', nl.update_authenticator(), 0, 1)
    if err is not None:
        print('[-] NetrLogonGetCapabilities failed:', err)
    else:
        print('[+] NetrLogonGetCapabilities OK')
        print('    ServerCapabilities : 0x%08x' % resp['ServerCapabilities']['ServerCapabilities'])
        print('    ErrorCode          : %d' % resp['ErrorCode'])

    await nl.close()
    await connection.terminate()


def main():
    parser = argparse.ArgumentParser(description='Netlogon secure channel (schannel) example')
    parser.add_argument('url', help='SMB connection URL (used to reach/locate the DC)')
    parser.add_argument('--dc-name', required=True, help='NetBIOS name of the DC (no trailing $)')
    parser.add_argument('--computer', required=True, help='Client computer account name (no trailing $)')
    parser.add_argument('--domain', required=True, help='NetBIOS domain of the computer account')
    parser.add_argument('--nt-hash', required=True, help='NT hash of the computer account password (hex)')
    parser.add_argument('--rc4', action='store_true', help='Use RC4/strong-key instead of AES (most modern DCs refuse this)')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    logging.getLogger('aiosmb').setLevel(logging.DEBUG if args.verbose else logging.CRITICAL)
    asyncio.run(run(args.url, args.dc_name, args.computer, args.domain, args.nt_hash, aes=not args.rc4))


if __name__ == '__main__':
    main()
