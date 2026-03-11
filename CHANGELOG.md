# PowerSCAP Changelog

## [2.6.2] - March 2026

### Fixed

- **`SqlHelpers.ps1` — `Extract-SqlQueries` complete overhaul**
  - Validated against the full MS SQL Server 2022 Instance (80 rules) and Database (22 rules) STIG corpus; result is zero prose leaks and 105 valid queries extracted across 71 of 102 rules
  - **`^EXECUTE\b` matched English prose** ("Execute the following SQL script:"): tightened to require a SQL token immediately after the keyword (`AS`, `sp_`, `xp_`, `schema.proc`, or `identifier(`) so prose instructions are never collected as queries
  - **`^IF\b.*BEGIN` missed multi-line `IF` blocks**: the pattern required `BEGIN` on the same line as `IF`; real STIG checks almost always put `BEGIN` on the next line. Changed to `^IF\s*(?:\(|@@|EXISTS\s*\(|NOT\s+EXISTS\s*\(|OBJECT_ID\s*\()` so only SQL-style conditions trigger collection
  - **`^USE` lookahead evaluated the wrong string**: the negative lookahead `[a-zA-Z_#@](?!the\b)` consumed the first letter before testing, so it saw `he` instead of `the`. Fixed by moving the lookahead before the character class
  - **Missing `DECLARE` and `INSERT INTO` starters**: multi-statement blocks beginning with `DECLARE @table ... INSERT INTO @table EXEC sp_...` were never collected
  - **`"Use the "` missing from prose terminators**: lines like "Use the following query to discover..." were not recognized as terminators and could bleed into an active accumulator
  - **Mid-statement `GO` batch separators not split**: checks written as `USE master; GO ↵ SELECT ...` were sent to SQL Server as a single invalid batch. Added a post-extraction pass that splits on standalone `GO` and filters each batch through the SQL validity check
  - **Added SQL_EMBED fallback**: prose lines containing inline SQL ("If Mirroring is in use, run the following to check: `SELECT name FROM sys.database_mirroring_endpoints`...") are now detected and the SQL suffix extracted
  - **Added SQL_VALIDITY post-filter**: every extracted query must contain at least one SQL hallmark (`FROM`, `WHERE`, `JOIN`, `sys.`, brackets, string literals, variables, proc calls, etc.) before being returned, catching any residual prose that slips through a starter match

- **`SqlHelpers.ps1` — `Build-SqlConnection`**
  - `System.Data.SqlClient` is not included in .NET 5+ (PowerShell 7). Connection attempts previously threw a cryptic type-not-found error with no guidance. Now probes for the type at startup and throws a clear message: `"Install-Module -Name SqlServer -Force"`

- **`SqlHelpers.ps1` — `Evaluate-SqlRule`**
  - Removed dead variable `$anyQueryReturned` — it was assigned in the query loop but never read anywhere in the pass/fail logic

- **`Scan-SQLDatabase.ps1` — master connection ignored `-ConnectionString`**
  - When a `-ConnectionString` was provided, the secondary `master` connection (used to route instance-level queries like `sys.databases`, `sys.server_principals`, `sys.server_audits`, etc.) was built by discarding the user's connection string entirely and connecting to `localhost` with integrated auth — wrong server, wrong credentials, wrong TLS settings. It failed silently and fell back to `$connMaster = $null`, meaning all instance-level queries ran in the wrong database context. Fixed by mutating the `Database=` clause of the provided connection string to `master` rather than rebuilding from scratch

---

## [2.6.1] - March 2026

### Fixed

- **`Scan-Computer.ps1` — Missing severity on sub-definitions**
  - Definitions that appear as building blocks via `<extend_definition>` (e.g. shared `class=compliance` helpers) had no XCCDF Rule referencing them directly and therefore no entry in `$script:xccdfRules`. Their severity was blank in scan output
  - Built a reverse `$script:ovalParentDefs` map during OVAL collection (child → parents) and added a post-load propagation pass that walks the map and copies severity from the nearest parent with a known XCCDF entry
  - The propagation resolver uses direct key lookup first, then a numeric-suffix fallback to handle namespace mismatches in multi-hop `extend_definition` chains
  - Fixes ~15 definitions across the Windows 11 V2R7 STIG that previously reported blank severity

---

## [2.6.0] - February 2026

### Hotfix (February 4, 2026)
- **Fixed "All" source downloads failing to find XML files**
  - XML file detection now searches recursively when using `-ScanSource All`
  - VulnDir mode now searches subdirectories to support organized vulnerability files
  - Files downloaded to subdirectories (NVD/, MSRC/, OVAL/) are now properly detected
- **Enhanced NVD API error messages**
  - Added helpful guidance for 404, 403, and 429 errors
  - Provides actionable solutions (API key, rate limiting, alternative sources)
  - Clearer error messages help users troubleshoot NVD issues

### Added
- **Full Linux Support**
  - Added comprehensive Linux scanning capabilities
  - New `LinuxHelpers.ps1` module with Linux-specific operations
  - Platform detection throughout the codebase
  - Cross-platform remote module installation
  - Support for Linux package managers (dpkg, rpm)
  - Linux service status checking (systemd, sysvinit)
  - Linux user account enumeration
  - Linux file system operations

- **Parameter Alignment**
  - Standardized parameters across Scan-Computer, Scan-SQLDatabase, and Scan-SQLInstance
  - Added `ScanSourceType` and `ScanSource` parameters to SQL functions
  - Added `Output` parameter (Console, JSON, CSV, TSV, Legacy) to SQL functions
  - Added `InstallPowerSCAP` parameter to SQL functions
  - Unified `Computer` parameter (with ComputerName alias) across all functions

- **New Output Formats**
  - CSV output support for all scan functions
  - TSV output support for all scan functions
  - Consistent output structure across all functions

- **Cross-Platform Remote Scanning**
  - Remote Linux scanning via PowerShell 7.x remoting
  - InstallPowerSCAP works on both Windows and Linux
  - Automatic platform detection for remote systems
  - Cross-platform module paths

### Changed
- **Breaking Changes**
  - Scan-SQLDatabase: `ComputerName` parameter now `Computer` (ComputerName still works as alias)
  - Scan-SQLInstance: `ComputerName` parameter now `Computer` (ComputerName still works as alias)
  - Scan-SQLDatabase: `ScapFile` replaced with `ScanSourceType` and `ScanSource`
  - Scan-SQLInstance: `ScapFile` replaced with `ScanSourceType` and `ScanSource`
  - Scan-SQLDatabase: `OutputJson` replaced with `Output` parameter
  - Scan-SQLInstance: `OutputJson` replaced with `Output` parameter

- **Module Structure**
  - Updated module version to 2.6.0
  - Added Linux to supported platforms in manifest
  - Updated description to highlight cross-platform support
  - Added RemotePowerSCAPManagement.ps1 to module loader
  - Added LinuxHelpers.ps1 to module loader

- **Documentation**
  - Updated all function help with Linux examples
  - Added comprehensive README for v2.6.0
  - Updated SYNOPSIS and DESCRIPTION for all functions
  - Added platform-specific usage notes

### Fixed
- **Critical .Count Bug** (affects all versions prior to 2.6.0)
  - Fixed all instances of `.Count` property access that could fail on null or single objects
  - Implemented consistent use of `Get-SafeCount` helper throughout codebase
  - Affected functions:
    - Scan-Computer
    - Scan-SQLDatabase
    - Scan-SQLInstance
    - All TestEvaluators functions
    - All helper functions
  - This fixes intermittent "Cannot index into a null array" errors
  - Improves reliability when processing empty or single-item collections

- **Registry and WMI Operations**
  - Added platform detection to prevent errors on Linux
  - Registry operations now gracefully skip on Linux
  - WMI operations now gracefully skip on Linux
  - Better error messages for unsupported operations

- **Remote Scanning**
  - Fixed module path detection for Windows vs Linux
  - Improved error handling for cross-platform scenarios
  - Better PowerShell remoting compatibility
  - Fixed module installation on Linux paths

- **OS Detection**
  - More reliable OS detection for remote systems
  - Better handling of mixed Windows/Linux environments
  - Improved error messages for detection failures

- **SQL Connection Building**
  - Fixed parameter passing for Computer vs ComputerName
  - Improved error handling for connection failures
  - Better support for cross-platform SQL Server

### Improved
- **Code Quality**
  - Consistent error handling across all functions
  - Improved verbose logging throughout
  - Better parameter validation
  - Enhanced documentation and comments
  - More robust null checking

- **Performance**
  - Optimized remote scanning with InstallPowerSCAP
  - Reduced unnecessary WMI/CIM queries on Linux
  - Better handling of large result sets
  - Improved progress indicators

- **Usability**
  - Clearer parameter names and descriptions
  - More informative error messages
  - Better progress indicators during scans
  - Improved verbose output for troubleshooting
  - **Visual progress bars for all vulnerability downloads**
    - NVD downloads show multi-stage progress (query, process, convert, save)
    - MSRC downloads track progress through each monthly update
    - OVAL downloads show download and parsing progress
    - Multi-source downloads show overall progress through each source
    - Conversion operations show progress every 10 items for large datasets
    - Proper progress completion in all scenarios including errors

## [2.5.0] - January 2026

### Added
- Automatic vulnerability definition downloads from NVD, MSRC, and OVAL
- SQL Server STIG scanning (Instance and Database)
- Enhanced remote scanning capabilities
- InstallPowerSCAP parameter for optimized remote scanning

### Fixed
- Remote scanning reliability improvements
- CIM session handling
- Error handling improvements

## [2.4.0] 

### Changed
- Complete parameter interface redesign for better usability
- Introduced ScanSourceType and ScanSource parameters
- Replaced multiple parameters with unified Output parameter
- Cleaner, more intuitive parameter names

### Added
- Role-based filtering for STIG compliance
- Platform filtering for vulnerability scans
- Force role override capability

## [2.3.0]

### Added
- Download capabilities for vulnerability definitions
- NVD API integration
- MSRC security update integration
- OVAL archive support

## [2.2.0]

### Added
- XCCDF STIG parsing capabilities
- SQL Server STIG support
- Enhanced OVAL evaluation

## [2.1.0]

### Added
- Remote scanning via CIM
- Multiple OVAL file processing
- JSON output support

## [2.0.0] 

### Changed
- Major refactor to modular architecture
- Separated concerns into Private and Public functions
- Improved maintainability and extensibility

## [1.0.0] - Initial Release

### Added
- Basic OVAL definition evaluation
- Registry and WMI test support
- Local Windows scanning
- Console output
