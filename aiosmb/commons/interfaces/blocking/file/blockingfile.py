from aiosmb.commons.interfaces.blocking.file.protocol import *
import traceback

class Section:
    def __init__(self, start, data):
        self.start = start
        self.end = self.start + len(data)
        self.data = data

    def inbuffer(self, pos, size):
        if self.start <= pos <= self.end:
            if self.start <= (pos+size) <= self.end:
                return True
        return False

    def read(self, pos, size):
        st = pos - self.start
        return self.data[st : st+size]

class SMBBlockingFile:
    def __init__(self, in_q, out_q, buffer_size = 65535):
        self.in_q = in_q
        self.out_q = out_q
        self.handle = None
        self.position = 0
        self.next_id = 0
        self.buffer_size = buffer_size
        self.buffers = []
        self.filesize = None
    
    def sr(self, cmd):
        self.in_q.put(cmd)
        reply = self.out_q.get()
        if reply.cmd_type == cmd.cmd_type:
            return reply
        elif reply.cmd_type == SMBFILECMD.ERROR:
            raise Exception(reply.error)

    def open(self, unc_path, mode):
        cmd_id = self.next_id
        self.next_id += 1
        cmd = SMBFileOpenCommand(cmd_id, unc_path, mode)
        reply = self.sr(cmd)
        self.handle = reply.handle
        self.filesize = reply.filesize

    def read(self, count):
        #for line in traceback.format_stack():
        #    print(line.strip())
        if count == 0:
            return b''
        if self.buffer_size is not None:
            for section in self.buffers:
                if section.inbuffer(self.position, count):
                    data = section.read(self.position, count)
                    self.position += len(data)
                    return data
            #else:
            #    print('NOT %s, %s' % (self.position, count))

        cmd_id = self.next_id
        self.next_id += 1
        tc = count
        if self.buffer_size is not None and count < self.buffer_size and self.filesize > self.buffer_size + self.position:
            tc = self.buffer_size
        cmd = SMBFileReadCommand(cmd_id, self.handle, self.position, tc)
        reply = self.sr(cmd)
        self.buffers.append(Section(self.position, reply.data))
        data = reply.data[:count]
        self.position += len(data)
        return data

    def write(self, data):
        cmd_id = self.next_id
        self.next_id += 1
        cmd = SMBFileWriteCommand(cmd_id, self.handle, self.position, data)
        reply = self.sr(cmd)
        self.handle = reply.handle

    def tell(self):
        return self.position

    def seek(self, pos, whence = 0):
        if whence == 0:
            self.position = pos
        elif whence == 1:
            self.position += pos
        elif whence == 2:
            raise Exception('Whence 2 is not implemented')

    def close(self):
        cmd_id = self.next_id
        self.next_id += 1
        cmd = SMBFileCloseCommand(cmd_id, self.handle)
        reply = self.sr(cmd)
        self.handle = reply.handle

    def terminate(self):
        cmd_id = self.next_id
        self.next_id += 1
        cmd = SMBFileTerminateCommand(cmd_id)