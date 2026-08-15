# Fake-peer tests

This area will contain deterministic async tests that inject scripted
transports through the existing `network_connection` seam. Helpers belong in
`tests/support/`; they should record writes and replay bounded responses
without becoming a second SMB implementation.

Mark these tests `fake_peer`. Keep all waits bounded, let strict asyncio expose
leaked tasks, and isolate hangs or crashes instead of weakening the global
timeout.
