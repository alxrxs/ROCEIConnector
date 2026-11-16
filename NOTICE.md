# RO CEI Connector

Copyright (C) 2026 Andrei-Alexandru Bleorțu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

## Third-Party Code

None. All source files were written for this project. The files derived from Apple's PIVToken
sample code in earlier versions (`Token.m`, `TokenSession.m`, `TokenDriver.m`, `NSData_Zip.m`)
have been removed.

## Interoperability

The card protocol (application identifiers, file layout, PIN references, command formats) was
established by observing the card itself and, for interoperability with the Romanian electronic
identity card, by analysing the vendor's PKCS#11 module as permitted by Article 6 of Directive
2009/24/EC. No vendor code or binaries are included, copied, or loaded.

Apple, the Apple logo, and macOS are trademarks of Apple Inc., registered
in the U.S. and other countries. IDEMIA is a trademark of its owner. This project is not
affiliated with, endorsed by, or sponsored by Apple Inc., IDEMIA or the Romanian Ministry of
Internal Affairs.
