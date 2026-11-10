"""Source-derived synthetic native JSON; never a receipt of actual validation."""

NATIVE_NAMES = ('manifest', 'manifest fields', 'requires_hermes', 'config schema',
                'requires_env', 'oauth', 'loadable', 'python dependencies',
                'capability probe', 'built-in tool collisions', 'security scan', 'no core override',
                'declared tools', 'declared hooks', 'declared middleware')


def native_report(**overrides):
    report = {'ok': True,
              'checks': [{'name': name, 'ok': True, 'detail': 'Synthetic producer-shaped fixture'} for name in NATIVE_NAMES],
              'warnings': [],
              'isolation': {'verdict': 'host', 'host_ready': True, 'reasons': [], 'notes': [], 'ctx_methods': []}}
    report.update(overrides)
    return report
