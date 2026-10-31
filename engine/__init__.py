"""
Scanning, route-mapping, decoy-filtering, auto-verification, and correlation engines.
"""

from engine.route_mapper import RouteMapper
from engine.decoy_filter import DecoyFilter
from engine.sast_scanner import SASTScanner
from engine.correlator import Correlator
from engine.sca_reachability import SCAReachabilityEngine
try:
    from engine.dast_scanner import DASTScanner, run_dast_scan, run_dast_scan_sync
except ImportError:  # pragma: no cover
    DASTScanner = None  # type: ignore
    run_dast_scan = None  # type: ignore
    run_dast_scan_sync = None  # type: ignore

__all__ = [
    "RouteMapper",
    "DecoyFilter",
    "SASTScanner",
    "Correlator",
    "SCAReachabilityEngine",
    "DASTScanner",
    "run_dast_scan",
    "run_dast_scan_sync",
]
