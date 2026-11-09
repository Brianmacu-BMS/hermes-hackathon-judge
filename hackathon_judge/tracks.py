"""Two evidence-aware views over one complete, non-certifying review policy."""
from .review import finding_id

TRACKS = {
    'build_guide': ('Build-guide conformance', {'developer-guide'}),
    'competition': ('Competition and catalog readiness', {'catalog-readme', 'catalog-submission', 'announcement'}),
}


def summarize(report):
    result = {}
    assessment = report['assessment']
    usable = assessment['status'] in {'complete', 'incomplete', 'rejected'}
    decisions = assessment['decisions'] if usable else {}
    dispositions = assessment['finding_dispositions'] if usable else {}
    global_blocker = not report['inventory']['complete'] or any(
        check['id'] in {'sources', 'guide-source-map'} and check['status'] == 'fail' for check in report['checks'])
    for key, (title, sources) in TRACKS.items():
        rows = [row for row in report['requirements'] if row['source'] in sources]
        ids = {row['id'] for row in rows}
        checks = [check for check in report['checks'] if ids.intersection(check['rules'])]
        related = ids | {rule for check in checks for rule in check['rules']}
        pending = sorted(rid for rid in ids if not decisions.get(rid, {}).get('complete') or
                         decisions[rid]['decision'] not in {'pass', 'not_applicable'})
        failed = sorted(rid for rid in ids if decisions.get(rid, {}).get('decision') == 'fail')
        failed_checks = sorted(check['id'] for check in checks if check['status'] == 'fail')
        finding_pending = []
        for finding in report['findings']:
            if finding['rule'] not in related:continue
            identity = finding_id(finding)
            disposition = dispositions.get(identity, {})
            if not disposition.get('complete') or disposition.get('decision') != 'acceptable':
                finding_pending.append(identity)
        blocked = global_blocker or bool(failed or failed_checks)
        status = 'blocked' if blocked else 'needs_review' if pending or finding_pending else 'reviewed'
        result[key] = {'title': title, 'source_ids': sorted(sources),
                       'requirement_ids': [row['id'] for row in rows], 'status': status,
                       'pending_requirements': pending, 'failed_requirements': failed,
                       'failed_checks': failed_checks, 'unresolved_findings': sorted(finding_pending),
                       'certified': False,
                       'notice': 'Reviewed means accountable evidence-backed assessment, not official acceptance. Both tracks and the selected readiness gate matter.'}
    return result
