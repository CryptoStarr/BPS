"""BPS — BurikaPathScope.

Client-side network path diagnostics: prove where the bottleneck lives
between a client and a destination, even when the ISP's own speedtest
looks fine.

Version bumping policy: bump ``__version__`` on every shipped change.
- Patch (0.x.Z) for fixes / small UX tweaks.
- Minor (0.Y.0) for new features (live dashboard, history timeline, etc).
- Major (X.0.0) reserved for backwards-incompatible changes.
"""
__version__ = "0.8.2"

APP_NAME = "BPS"
APP_LONG_NAME = "BurikaPathScope"
APP_TAGLINE = "network path diagnostics"
