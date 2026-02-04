# PowerSCAP Changelog

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

## [2.4.0] - January 2026

### Changed
- Complete parameter interface redesign for better usability
- Introduced ScanSourceType and ScanSource parameters
- Replaced multiple parameters with unified Output parameter
- Cleaner, more intuitive parameter names

### Added
- Role-based filtering for STIG compliance
- Platform filtering for vulnerability scans
- Force role override capability

## [2.3.0] - December 2025

### Added
- Download capabilities for vulnerability definitions
- NVD API integration
- MSRC security update integration
- OVAL archive support

## [2.2.0] - November 2025

### Added
- XCCDF STIG parsing capabilities
- SQL Server STIG support
- Enhanced OVAL evaluation

## [2.1.0] - October 2025

### Added
- Remote scanning via CIM
- Multiple OVAL file processing
- JSON output support

## [2.0.0] - September 2025

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
