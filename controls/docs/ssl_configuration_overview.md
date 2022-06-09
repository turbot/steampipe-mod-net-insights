## Overview

SSL is the backbone of a secure internet, and it protects sensitive information by establishing authenticated and encrypted links between networked computers. So it is necessary to provide extra effort to configure your SSL server to provide necessary security against complex SSL-related attacks.

This benchmark performs various standard checks on your server configuration, for example:

- Do my certificates have a complete chain of trusted certificates?
- Are my servers using insecure cipher suites or protocols?
- Are perfect forward secrecy and TLS fallback SCSV enabled on my servers?
- Do my certificates use RSA keys or ECDSA keys that are too large?
