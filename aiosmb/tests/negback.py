
		
	async def negotiate(self):
		"""
		Initiates protocol negotiation.
		First we send an SMB_COM_NEGOTIATE_REQ with our supported dialects
		"""
		
		#let's construct an SMBv1 SMB_COM_NEGOTIATE_REQ packet
		header = SMBHeader()
		header.Command  = SMBCommand.SMB_COM_NEGOTIATE
		header.Status   = NTStatus.SUCCESS
		header.Flags    = 0
		header.Flags2   = SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE
			
		command = SMB_COM_NEGOTIATE_REQ()				
		command.Dialects = ['SMB 2.???']
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		#recieveing reply, should be version2, because currently we dont support v1 :(
		rply = await self.recvSMB(message_id) #negotiate MessageId should be 1
		if rply.header.Status == NTStatus.SUCCESS:
			if isinstance(rply, SMB2Message):
				if rply.command.DialectRevision == NegotiateDialects.WILDCARD:
					command = NEGOTIATE_REQ()
					command.SecurityMode    = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED #NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED | NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
					command.Capabilities    = 0
					command.ClientGuid      = self.ClientGUID
					command.Dialects        = self.dialects

					if NegotiateDialects.SMB311 in self.dialects:
						#SMB311 mandates the contextlist to be populated
						command.Capabilities    = NegotiateCapabilities.ENCRYPTION
						
						command.NegotiateContextList.append(
								SMB2PreauthIntegrityCapabilities.construct(
									[self.PreauthIntegrityHashId]
								)
							)

						
						if self.smb2_supported_encryptions is not None:
							command.NegotiateContextList.append(
								SMB2EncryptionCapabilities.from_enc_list(
									self.smb2_supported_encryptions
								)
							)

						#if self.CompressionIds is not None:
						#	command.NegotiateContextList.append(
						#		SMB2CompressionCapabilities.from_comp_list(
						#			self.CompressionIds,
						#			self.SupportsChainedCompression
						#		)
						#	)
					#print('aaaaa')
					#input(command.NegotiateContextList)
					#print('aaaaa')
					header = SMB2Header_SYNC()
					header.Command  = SMB2Command.NEGOTIATE
					header.CreditReq = 0
					
					msg = SMB2Message(header, command)
					message_id = await self.sendSMB(msg)
					rply = await self.recvSMB(message_id) #negotiate MessageId should be 1
					if rply.header.Status != NTStatus.SUCCESS:
						print('session got reply!')
						print(rply)
						raise Exception('session_setup_1 (authentication probably failed) reply: %s' % rply.header.Status)
					
				if rply.command.DialectRevision not in self.supported_dialects:
					raise SMBUnsupportedDialectSelected()
				
				self.selected_dialect = rply.command.DialectRevision
				self.ServerSecurityMode = rply.command.SecurityMode
				self.signing_required = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED in rply.command.SecurityMode
				logger.log(1, 'Server selected dialect: %s' % self.selected_dialect)
				
				self.MaxTransactSize = min(0x100000, rply.command.MaxTransactSize)
				self.MaxReadSize = min(0x100000, rply.command.MaxReadSize)
				self.MaxWriteSize = min(0x100000, rply.command.MaxWriteSize)
				self.ServerGuid = rply.command.ServerGuid
				self.SupportsMultiChannel = NegotiateCapabilities.MULTI_CHANNEL in rply.command.Capabilities
				
			else:
				logger.error('Server choose SMB v1 which is not supported currently')
				raise SMBUnsupportedSMBVersion()
			
		else:
			print('session got reply!')
			print(rply)
			raise Exception('session_setup_1 (authentication probably failed) reply: %s' % rply.header.Status)
			
			
			
		self.status = SMBConnectionStatus.SESSIONSETUP
