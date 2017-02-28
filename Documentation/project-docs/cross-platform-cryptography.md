Cross-Platform Cryptography
===========================

Cryptographic operations in .NET are performed by existing system libraries.
As with most technological decisions, there are various pros and cons.
Since the system already has a vested interested in making the cryptography libraries safe from security vulnerabilities,
and already has an update mechanism that system administrators should be using, .NET gets to benefit from this reliability.
Users who have requirements to use FIPS-validated algorithm implementations also get that benefit for free (when the system
libraries are FIPS-validated, of course).
The biggest con is that not all system libraries offer the same capabilities.
While the core capabilities are present across the various platforms, there are some rough edges.
