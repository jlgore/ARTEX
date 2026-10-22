#!/usr/bin/env python3
"""Run an ARTEX scan without the web UI and write the reports to disk.

Uses the same pipeline as the web UI (app.run_scan), so results match.

    python cli.py example.com --out /workspace/artex
    python cli.py example.com --intensity light --skip ports,email
"""
import argparse
import os
import sys
import uuid

import app
from utils.helpers import validate_domain, sanitize_domain
from utils.reporting import ReportGenerator

MODULES = ['subdomains', 'ports', 'dns', 'real_ip', 'ssl', 'tech', 'email']


def main():
    parser = argparse.ArgumentParser(description='ARTEX reconnaissance scan')
    parser.add_argument('domain')
    parser.add_argument('--out', default='.', help='directory for the reports (default: .)')
    parser.add_argument('--intensity', choices=['light', 'normal', 'aggressive'], default='normal')
    parser.add_argument('--port-scan', choices=['all_subdomains', 'critical_only'], default='all_subdomains',
                        help='which subdomains to port scan')
    parser.add_argument('--skip', default='', help=f'comma-separated modules to skip: {",".join(MODULES)}')
    parser.add_argument('--no-pdf', action='store_true', help='write only the JSON report')
    args = parser.parse_args()

    if not validate_domain(args.domain):
        parser.error(f'invalid domain: {args.domain}')
    domain = sanitize_domain(args.domain)

    skip = {m.strip() for m in args.skip.split(',') if m.strip()}
    unknown = skip - set(MODULES)
    if unknown:
        parser.error(f'unknown modules in --skip: {",".join(sorted(unknown))}')

    options = {m: m not in skip for m in MODULES}
    options['intensity'] = args.intensity
    options['port_scan_choice'] = args.port_scan

    # run_scan reads and writes the module-level state the web UI uses.
    scan_id = str(uuid.uuid4())
    app.scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'current_task': 'Initializing scan...',
        'start_time': app.datetime.now(),
        'domain': domain,
        'options': options,
    }
    app.scan_results[scan_id] = {
        'domain': domain,
        'subdomains': [],
        'port_scan': [],
        'dns_records': {},
        'ssl_scan': {},
        'tech_detection': {},
        'email_enumeration': {},
        'security_analysis': {},
        'ai_analysis': {},
        'scan_id': scan_id,
        'timestamp': app.datetime.now().isoformat(),
        'options': options,
    }
    app.run_scan(scan_id, domain, options)

    status = app.scan_status[scan_id]
    if status['status'] != 'completed':
        print(f"scan failed: {status.get('error', 'unknown error')}", file=sys.stderr)
        return 1

    results = app.scan_results[scan_id]
    results['duration'] = status.get('duration')
    os.makedirs(args.out, exist_ok=True)
    report = ReportGenerator()
    base = os.path.join(args.out, f'artex_{domain}')
    with open(f'{base}.json', 'w') as f:
        f.write(report.generate_json(results))
    print(f'wrote {base}.json')
    if not args.no_pdf:
        with open(f'{base}.pdf', 'wb') as f:
            f.write(report.generate_pdf(results))
        print(f'wrote {base}.pdf')
    return 0


if __name__ == '__main__':
    sys.exit(main())
