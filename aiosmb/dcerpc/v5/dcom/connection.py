# Async DCOM Connection Manager for aiosmb
#
# Implements a singleton pattern for managing DCOM connections and
# object lifetime via async ping mechanism.
#

import asyncio
import copy
from typing import Dict, Set, Optional, List

from aiosmb import logger
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_WINNT

from aiosmb.dcerpc.v5.dcom.dcomrt import IID_IObjectExporter


class DCOMConnectionManager:
    """
    Singleton manager for DCOM connections.
    
    Manages:
    - Connection pooling per target
    - Object ID (OID) tracking for keep-alive pings
    - Background ping task to prevent server-side garbage collection
    
    Usage:
        manager = DCOMConnectionManager.get_instance()
        # ... or use DCOMConnection which handles this automatically
    """
    _instance = None
    _lock = asyncio.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    @classmethod
    def get_instance(cls) -> 'DCOMConnectionManager':
        """Get or create the singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        
        # Per-target state tracking
        # target -> DCERPC5Connection (portmap connection)
        self._portmaps: Dict[str, DCERPC5Connection] = {}
        
        # target -> set of OIDs to add in next ping
        self._oid_add: Dict[str, Set[int]] = {}
        
        # target -> set of OIDs to delete in next ping
        self._oid_del: Dict[str, Set[int]] = {}
        
        # target -> {'oids': set(), 'setid': int}
        self._oid_set: Dict[str, dict] = {}
        
        # target -> oxid -> DCE/RPC connection for that OXID
        self._oxid_connections: Dict[str, Dict[int, dict]] = {}
        
        # Credentials storage per target for connection reuse
        self._credentials: Dict[str, DCERPCAuth] = {}
        
        # Ping task management
        self._ping_task: Optional[asyncio.Task] = None
        self._ping_interval: int = 120  # seconds
        self._ping_running: bool = False
        
        # Lock for thread-safe operations
        self._state_lock = asyncio.Lock()
    
    async def add_oid(self, target: str, oid: int):
        """Register an OID for keep-alive pinging"""
        async with self._state_lock:
            if target not in self._oid_add:
                self._oid_add[target] = set()
            self._oid_add[target].add(oid)
            
            if target not in self._oid_set:
                self._oid_set[target] = {'oids': set(), 'setid': 0}
    
    async def del_oid(self, target: str, oid: int):
        """Mark an OID for removal from keep-alive set"""
        async with self._state_lock:
            if target not in self._oid_del:
                self._oid_del[target] = set()
            self._oid_del[target].add(oid)
            
            if target not in self._oid_set:
                self._oid_set[target] = {'oids': set(), 'setid': 0}
    
    def register_portmap(self, target: str, portmap: DCERPC5Connection):
        """Register a portmap connection for a target"""
        self._portmaps[target] = portmap
    
    def get_portmap(self, target: str) -> Optional[DCERPC5Connection]:
        """Get the portmap connection for a target"""
        return self._portmaps.get(target)
    
    def register_credentials(self, target: str, auth: DCERPCAuth):
        """Store credentials for a target for later connection reuse"""
        self._credentials[target] = auth
    
    def get_credentials(self, target: str) -> Optional[DCERPCAuth]:
        """Get a fresh copy of stored credentials for a target.
        
        Each connection needs its own fresh authentication context because
        NTLM/Kerberos contexts have internal state that gets consumed during
        authentication.
        """
        auth = self._credentials.get(target)
        if auth is not None:
            return auth.get_copy()
        return None
    
    def register_oxid_connection(self, target: str, oxid: int, dce: DCERPC5Connection, current_binding):
        """Register a DCE/RPC connection for a specific OXID"""
        if target not in self._oxid_connections:
            self._oxid_connections[target] = {}
        self._oxid_connections[target][oxid] = {
            'dce': dce,
            'currentBinding': current_binding
        }
    
    def get_oxid_connection(self, target: str, oxid: int) -> Optional[dict]:
        """Get DCE/RPC connection info for a specific OXID"""
        if target in self._oxid_connections:
            return self._oxid_connections[target].get(oxid)
        return None
    
    def update_oxid_binding(self, target: str, oxid: int, dce: DCERPC5Connection, binding):
        """Update the binding for an OXID connection"""
        if target in self._oxid_connections and oxid in self._oxid_connections[target]:
            self._oxid_connections[target][oxid]['dce'] = dce
            self._oxid_connections[target][oxid]['currentBinding'] = binding
    
    def start_ping_task(self):
        """Start the background ping task if not already running"""
        if self._ping_task is None or self._ping_task.done():
            self._ping_running = True
            self._ping_task = asyncio.create_task(self._ping_loop())
    
    async def stop_ping_task(self):
        """Stop the background ping task"""
        self._ping_running = False
        if self._ping_task is not None:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass
            self._ping_task = None
    
    async def _ping_loop(self):
        """Background task that periodically pings all registered objects"""
        while self._ping_running:
            try:
                await asyncio.sleep(self._ping_interval)
                await self._do_ping()
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue pinging
                logger.debug(f'DCOM ping error: {e}')
    
    async def _do_ping(self):
        """Execute ping operations for all targets"""
        # Import here to avoid circular imports
        from aiosmb.dcerpc.v5.dcom.objectexporter import IObjectExporter
        
        async with self._state_lock:
            targets = list(self._oid_set.keys())
        
        for target in targets:
            try:
                async with self._state_lock:
                    added_oids = set()
                    deleted_oids = set()
                    
                    if target in self._oid_add:
                        added_oids = self._oid_add[target]
                        del self._oid_add[target]
                    
                    if target in self._oid_del:
                        deleted_oids = self._oid_del[target]
                        del self._oid_del[target]
                    
                    portmap = self._portmaps.get(target)
                    if portmap is None:
                        continue
                    
                    oid_info = self._oid_set.get(target, {'oids': set(), 'setid': 0})
                
                obj_exporter = IObjectExporter(portmap)
                
                if len(added_oids) > 0 or len(deleted_oids) > 0:
                    set_id = oid_info.get('setid', 0)
                    resp, err = await obj_exporter.ComplexPing(set_id, 0, added_oids, deleted_oids)
                    if err is None:
                        async with self._state_lock:
                            self._oid_set[target]['oids'] -= deleted_oids
                            self._oid_set[target]['oids'] |= added_oids
                            self._oid_set[target]['setid'] = resp['pSetId']
                else:
                    set_id = oid_info.get('setid', 0)
                    if set_id != 0:
                        _, err = await obj_exporter.SimplePing(set_id)
                        if err is not None:
                            logger.debug(f'DCOM SimplePing failed for {target}: {err}')
                            
            except Exception as e:
                logger.debug(f'DCOM ping error for {target}: {e}')
    
    async def cleanup_target(self, target: str):
        """Clean up all resources for a target"""
        async with self._state_lock:
            if target in self._portmaps:
                del self._portmaps[target]
            if target in self._oid_set:
                del self._oid_set[target]
            if target in self._oid_add:
                del self._oid_add[target]
            if target in self._oid_del:
                del self._oid_del[target]
            if target in self._oxid_connections:
                # Disconnect all OXID connections
                for oxid_info in self._oxid_connections[target].values():
                    try:
                        await oxid_info['dce'].disconnect()
                    except:
                        pass
                del self._oxid_connections[target]
            if target in self._credentials:
                del self._credentials[target]
        
        # Stop ping task if no more targets
        if len(self._portmaps) == 0:
            await self.stop_ping_task()


class DCOMConnection:
    """
    Main DCOM connection class.
    
    Establishes a DCE/RPC connection to the target's portmapper (port 135)
    and provides methods to create COM objects remotely.
    
    Usage:
        async with DCOMConnection(target, auth) as dcom:
            interface = await dcom.CoCreateInstanceEx(clsid, iid)
            # use interface...
    
    Or without context manager:
        dcom = DCOMConnection(target, auth)
        _, err = await dcom.connect()
        if err is None:
            interface = await dcom.CoCreateInstanceEx(clsid, iid)
        await dcom.disconnect()
    """
    
    def __init__(self, target: str, auth: DCERPCAuth = None, 
                 auth_level: int = RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                 oxidResolver: bool = True,
                 proxies: List = None,
                 dc_ip: str = None,
                 domain: str = None):
        """
        Initialize DCOM connection.
        
        Args:
            target: Target hostname or IP address
            auth: DCERPCAuth credentials (can be None for anonymous)
            auth_level: RPC authentication level
            oxidResolver: If True, enable object lifetime pinging
            proxies: List of proxy targets
            dc_ip: Domain controller IP for Kerberos
            domain: Domain name
        """
        self._target = target
        self._auth = auth
        self._auth_level = auth_level
        self._oxid_resolver = oxidResolver
        self._proxies = proxies
        self._dc_ip = dc_ip
        self._domain = domain
        
        self._portmap: Optional[DCERPC5Connection] = None
        self._manager = DCOMConnectionManager.get_instance()
        self._connected = False
    
    async def __aenter__(self):
        _, err = await self.connect()
        if err is not None:
            raise err
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    @staticmethod
    def from_smbconnection(smb_connection, auth_level: int = RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                           oxidResolver: bool = True) -> 'DCOMConnection':
        """
        Create DCOMConnection from an existing SMB connection.
        Copies credentials from the SMB connection.
        """
        auth = DCERPCAuth.from_smb_gssapi(smb_connection.gssapi)
        target = smb_connection.target.get_hostname_or_ip()
        
        return DCOMConnection(
            target=target,
            auth=auth,
            auth_level=auth_level,
            oxidResolver=oxidResolver,
            proxies=smb_connection.target.proxies,
            dc_ip=smb_connection.target.dc_ip,
            domain=smb_connection.target.domain
        )
    
    @staticmethod
    async def from_epm(target: str, auth: DCERPCAuth = None,
                       auth_level: int = RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                       oxidResolver: bool = True,
                       proxies: List = None) -> 'DCOMConnection':
        """
        Create DCOMConnection using EPM to resolve endpoint.
        Similar pattern to other DCERPC interface managers.
        """
        return DCOMConnection(
            target=target,
            auth=auth,
            auth_level=auth_level,
            oxidResolver=oxidResolver,
            proxies=proxies
        )
    
    async def connect(self):
        """
        Establish connection to the DCOM portmapper.
        
        Returns:
            (True, None) on success
            (None, Exception) on failure
        """
        try:
            # Build connection string for TCP port 135
            connection_string = f'ncacn_ip_tcp:{self._target}[135]'
            target = DCERPCTarget.from_connection_string(
                connection_string,
                proxies=self._proxies,
                dc_ip=self._dc_ip,
                domain=self._domain,
                hostname=self._target
            )
            
            self._portmap = DCERPC5Connection(self._auth, target)
            self._portmap.set_auth_level(self._auth_level)
            
            if self._auth is not None:
                if self._auth.kerberos is not None:
                    self._portmap.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
                elif self._auth.ntlm is not None:
                    self._portmap.set_auth_type(RPC_C_AUTHN_WINNT)
            
            _, err = await self._portmap.connect()
            if err is not None:
                raise err
            
            # Register with manager
            self._manager.register_portmap(self._target, self._portmap)
            if self._auth is not None:
                self._manager.register_credentials(self._target, self._auth)
            
            # Start ping task if using OXID resolver
            if self._oxid_resolver:
                self._manager.start_ping_task()
            
            self._connected = True
            return True, None
            
        except Exception as e:
            return None, e
    
    async def disconnect(self):
        """
        Disconnect and clean up resources.
        
        Returns:
            (True, None) on success
            (None, Exception) on failure
        """
        try:
            await self._manager.cleanup_target(self._target)
            
            if self._portmap is not None:
                await self._portmap.disconnect()
                self._portmap = None
            
            self._connected = False
            return True, None
            
        except Exception as e:
            return None, e
    
    def get_dce_rpc(self) -> Optional[DCERPC5Connection]:
        """Get the underlying DCE/RPC connection"""
        return self._portmap
    
    def get_target(self) -> str:
        """Get the target hostname/IP"""
        return self._target
    
    def get_auth(self) -> Optional[DCERPCAuth]:
        """Get the authentication credentials"""
        return self._auth
    
    def get_auth_level(self) -> int:
        """Get the RPC authentication level"""
        return self._auth_level
    
    async def CoCreateInstanceEx(self, clsid: bytes, iid: bytes):
        """
        Create a COM object instance on the remote server.
        
        Args:
            clsid: Class ID (CLSID) of the object to create
            iid: Interface ID (IID) to query
        
        Returns:
            (IRemUnknown2 interface, None) on success
            (None, Exception) on failure
        """
        try:
            # Import here to avoid circular imports
            from aiosmb.dcerpc.v5.dcom.activation import IRemoteSCMActivator
            
            scm = IRemoteSCMActivator(self._portmap, self._target)
            interface, err = await scm.RemoteCreateInstance(clsid, iid)
            if err is not None:
                raise err
            
            return interface, None
            
        except Exception as e:
            return None, e
    
    async def GetClassObject(self, clsid: bytes, iid: bytes):
        """
        Get a class factory object for the specified CLSID.
        
        Args:
            clsid: Class ID (CLSID) of the class factory
            iid: Interface ID (IID), typically IID_IClassFactory
        
        Returns:
            (IRemUnknown2 interface, None) on success
            (None, Exception) on failure
        """
        try:
            from aiosmb.dcerpc.v5.dcom.activation import IRemoteSCMActivator
            
            scm = IRemoteSCMActivator(self._portmap, self._target)
            interface, err = await scm.RemoteGetClassObject(clsid, iid)
            if err is not None:
                raise err
            
            return interface, None
            
        except Exception as e:
            return None, e
