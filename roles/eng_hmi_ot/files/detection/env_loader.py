"""
Shared environment file loader for attack/defence scripts.

Loads service addresses from deployment env files (dev.env, prod.env)
so scripts can target distributed clusters without passing many CLI args.

Usage:
    from env_loader import load_env_file, resolve_addresses

    addrs = resolve_addresses(load_env_file('deployment/prod.env'))
    # addrs['plc_hosts']   -> {'mg1': ('192.168.10.30', 502), ...}
    # addrs['gateway_host'] -> '192.168.10.10'
    # addrs['gateway_port'] -> 5020
    # addrs['scada_url']    -> 'http://192.168.10.40:8090/Scada-LTS'
    # addrs['db_host']      -> '192.168.10.40'
    # addrs['db_port']      -> 3306
"""


def load_env_file(path):
    """Load KEY=VALUE pairs from an env file."""
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, val = line.split('=', 1)
                    env[key.strip()] = val.strip()
    except FileNotFoundError:
        print(f"Warning: env file not found: {path}")
    return env


def resolve_addresses(env):
    """Resolve service addresses from env vars.

    Returns dict with:
        plc_hosts:    {'mg1': (host, port), 'mg2': ..., 'mg3': ..., 'mg4': ...}
        gateway_host: str
        gateway_port: int
        scada_url:    str  (full URL with context path)
    """
    addrs = {
        'plc_hosts': {},
        'gateway_host': 'localhost',
        'gateway_port': 5020,
        'scada_url': 'http://localhost:8080/Scada-LTS',
        'db_host': 'localhost',
        'db_port': 3306,
    }

    # PLCs
    plc_defaults = {'mg1': 502, 'mg2': 503, 'mg3': 504, 'mg4': 505}
    for mg, default_port in plc_defaults.items():
        num = mg[2]  # '1', '2', '3', '4'
        host = env.get(f'MG{num}_PLC_HOST', 'localhost')
        port = int(env.get(f'MG{num}_PLC_MODBUS_PORT', str(default_port)))
        addrs['plc_hosts'][mg] = (host, port)

    # SCADA Gateway
    addrs['gateway_host'] = env.get('SCADA_GATEWAY_HOST', 'localhost')
    addrs['gateway_port'] = int(env.get('SCADA_GATEWAY_PORT', '5020'))

    # ScadaLTS
    scada_host = env.get('SCADALTS_HOST', 'localhost')
    scada_port = env.get('SCADALTS_PORT', '8080')
    addrs['scada_url'] = f'http://{scada_host}:{scada_port}/Scada-LTS'

    # Database (MySQL)
    addrs['db_host'] = env.get('DATABASE_HOST', 'localhost')
    addrs['db_port'] = int(env.get('DATABASE_PORT', '3306'))

    return addrs
