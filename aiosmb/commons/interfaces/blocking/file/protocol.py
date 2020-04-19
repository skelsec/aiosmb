import enum

class SMBFILECMD(enum.Enum):
    OPEN  = 'OPEN'
    CLOSE = 'CLOSE'
    READ  = 'READ'
    WRITE = 'WRITE'
    ERROR = 'ERROR'
    TERMINATE = 'TERMINATE'

class SMBFileCommand:
    def __init__(self, cmd_id = None, cmd_type = None):
        self.cmd_id = cmd_id
        self.cmd_type = cmd_type


class SMBFileOpenCommand(SMBFileCommand):
    def __init__(self, cmd_id = None, path = None, mode = 'r'):
        super().__init__(cmd_id, SMBFILECMD.OPEN)
        self.path = path
        self.mode = mode

class SMBFileOpenReply(SMBFileCommand):
    def __init__(self, cmd_id = None, handle = None, filesize = None):
        super().__init__(cmd_id, SMBFILECMD.OPEN)
        self.handle = handle
        self.filesize = filesize

class SMBFileReadCommand(SMBFileCommand):
    def __init__(self, cmd_id = None, handle = None, position = None, count = None):
        super().__init__(cmd_id, SMBFILECMD.READ)
        self.handle = handle
        self.position = position
        self.count = count

class SMBFileReadReply(SMBFileCommand):
    def __init__(self, cmd_id = None, handle = None, data = None):
        super().__init__(cmd_id, SMBFILECMD.READ)
        self.handle = handle
        self.data = data

class SMBFileWriteCommand(SMBFileCommand):
    def __init__(self, cmd_id = None, handle = None, position = None, data = None):
        super().__init__(cmd_id, SMBFILECMD.WRITE)
        self.handle = handle
        self.position = position
        self.data = data

class SMBFileWriteReply(SMBFileCommand):
    def __init__(self, cmd_id = None, handle = None, count = None):
        super().__init__(cmd_id, SMBFILECMD.WRITE)
        self.handle = handle
        self.count = count

class SMBFileError(SMBFileCommand):
    def __init__(self, cmd_id = None, error = None):
        super().__init__(cmd_id, SMBFILECMD.ERROR)
        self.error = error

class SMBFileCloseCommand(SMBFileCommand):
    def __init__(self, cmd_id = None, handle = None):
        super().__init__(cmd_id, SMBFILECMD.CLOSE)
        self.handle = handle

class SMBFileCloseReply(SMBFileCommand):
    def __init__(self, cmd_id = None, handle = None):
        super().__init__(cmd_id, SMBFILECMD.CLOSE)
        self.handle = handle

class SMBFileTerminateCommand(SMBFileCommand):
    def __init__(self, cmd_id = None):
        super().__init__(cmd_id, SMBFILECMD.TERMINATE)