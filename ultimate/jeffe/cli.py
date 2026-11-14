"""Command line interface. Only explicitly supplied local recovery assets are executed."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

from . import __version__, engines
from .service import catalog_data, private_json, public_job, run_job
from .storage import Workspace


def default_john() -> str | None:
    local = Path(__file__).resolve().parents[2] / 'run' / 'john'
    return str(local) if local.is_file() else shutil.which('john')


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='jeffe', description='Offline recovery workbench and authenticated team server')
    p.add_argument('--version', action='version', version=__version__)
    p.add_argument('--workspace', type=Path, default=Path('jeffe-workspace'))
    p.add_argument('--john', default=default_john())
    p.add_argument('--hashcat', default=shutil.which('hashcat'))
    commands = p.add_subparsers(dest='command', required=True)
    commands.add_parser('init')
    commands.add_parser('diagnose')
    c = commands.add_parser('ingest'); c.add_argument('path', type=Path); c.add_argument('--kind', choices=['hashes', 'wordlist'], required=True)
    commands.add_parser('assets')
    c = commands.add_parser('create'); c.add_argument('--engine', choices=['john','hashcat'], default='john'); c.add_argument('--format', required=True); c.add_argument('--input-id', required=True); c.add_argument('--wordlist-id', required=True); c.add_argument('--runtime', type=int, default=30)
    c = commands.add_parser('jobs'); c.add_argument('--limit', type=int, default=100)
    for name in ['run','resume']:
        c=commands.add_parser(name); c.add_argument('id')
    c=commands.add_parser('report'); c.add_argument('--output',type=Path,required=True)
    c=commands.add_parser('dashboard'); c.add_argument('--output',type=Path,required=True)
    for name in ['catalog','backlog']:
        c=commands.add_parser(name); c.add_argument('--query',default=''); c.add_argument('--status')
    c=commands.add_parser('auth-add'); c.add_argument('--auth',type=Path,required=True); c.add_argument('--name',required=True); c.add_argument('--role',choices=['viewer','operator','admin'],required=True)
    c=commands.add_parser('serve'); c.add_argument('--auth',type=Path,required=True); c.add_argument('--host',default='127.0.0.1'); c.add_argument('--port',type=int,default=8765); c.add_argument('--workers',type=int,default=1)
    commands.add_parser('demo')
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'diagnose':
            data = {'version':__version__,'python':sys.version.split()[0],'platform':sys.platform,'engines':{}}
            for name,path in [('john',args.john),('hashcat',args.hashcat)]:
                data['engines'][name] = engines.diagnostics(path,name) if path else {'available':False,'reason':'not configured'}
        elif args.command in {'catalog','backlog'}:
            data = catalog_data('integrations' if args.command=='catalog' else 'backlog')
            if args.status:
                data=[r for r in data if r.get('status',r.get('decision'))==args.status]
            if args.query:
                data=[r for r in data if args.query.casefold() in json.dumps(r,ensure_ascii=False).casefold()]
        elif args.command == 'auth-add':
            from .server import load_principals
            if args.auth.is_symlink():
                raise ValueError('Auth configuration cannot be a symlink')
            if args.auth.exists():
                load_principals(args.auth)
            auth=json.loads(args.auth.read_text()) if args.auth.exists() else {'principals':[]}
            if not args.name.strip() or any(p['name']==args.name for p in auth['principals']):
                raise ValueError('Principal name must be nonempty and unique')
            token=secrets.token_urlsafe(32)
            auth['principals'].append({'name':args.name,'role':args.role,'token_sha256':hashlib.sha256(token.encode()).hexdigest()})
            # Validate before replacing a working configuration or revealing a token.
            with tempfile.TemporaryDirectory(prefix='jeffe-auth-check-') as temporary:
                candidate=Path(temporary)/'auth.json'
                private_json(candidate,auth)
                load_principals(candidate)
            private_json(args.auth,auth)
            data={'name':args.name,'role':args.role,'token':token,'notice':'Save this token privately. It is shown once; only its digest is stored.'}
        elif args.command == 'serve':
            from .server import build_server
            configured={name:path for name,path in [('john',args.john),('hashcat',args.hashcat)] if path}
            server=build_server(args.host,args.port,args.workspace,args.auth,configured,catalog_data('integrations'),catalog_data('backlog'),max_workers=args.workers)
            print(json.dumps({'listening':f'http://{args.host}:{server.server_port}','transport':'Use a TLS reverse proxy for remote clients.'}),flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        elif args.command in {'run','resume'}:
            data=run_job(args.workspace,args.id,{'john':args.john,'hashcat':args.hashcat},resume=args.command=='resume')
        else:
            ws=Workspace(args.workspace)
            try:
                if args.command=='init':
                    data=ws.report_summary()
                elif args.command=='ingest':
                    result=ws.ingest(args.path,kind=args.kind)
                    data={k:result[k] for k in ('id','sha256','size','kind')}
                elif args.command=='assets':
                    data=[{k:r[k] for k in ('id','sha256','size','kind')} for r in ws.list_assets()]
                elif args.command=='create':
                    spec={'schema_version':1,'engine':args.engine,'format':args.format,'input_id':args.input_id,'wordlist_id':args.wordlist_id,'runtime_seconds':args.runtime}
                    data=public_job(ws.create_job(spec))
                elif args.command=='jobs':
                    data=[public_job(r) for r in ws.list_jobs(limit=args.limit)]
                elif args.command=='report':
                    data={'schema_version':1,'summary':ws.report_summary(),'jobs':[public_job(j) for j in ws.list_jobs(limit=10000)],'interpretation':'Unrecovered records are not evidence of strong passwords. Engine outcomes require context.'}
                    private_json(args.output,data)
                    data={'written':str(args.output)}
                elif args.command=='dashboard':
                    from .dashboard import write_dashboard
                    write_dashboard(args.output,ws.report_summary(),ws.list_jobs(limit=10000),catalog_data('integrations'),catalog_data('backlog'))
                    data={'written':str(args.output)}
                elif args.command=='demo':
                    # This public synthetic fixture is deliberately tiny and contains no user data.
                    demo=Path(tempfile.mkdtemp(prefix='demo-',dir=args.workspace))
                    password='jeffe-synthetic-example-2026'
                    for name,content in [('hashes.txt',hashlib.sha256(password.encode()).hexdigest()+'\n'),('words.txt','synthetic-wrong\n'+password+'\n')]:
                        dest=demo/name
                        with os.fdopen(os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
                            f.write(content)
                    inp=ws.ingest(demo/'hashes.txt',kind='hashes'); words=ws.ingest(demo/'words.txt',kind='wordlist')
                    job=ws.create_job({'schema_version':1,'engine':'john','format':'raw-sha256','input_id':inp['id'],'wordlist_id':words['id'],'runtime_seconds':10})
                    data=run_job(args.workspace,job['id'],{'john':args.john,'hashcat':args.hashcat})
                else:
                    raise ValueError('Unsupported command')
            finally:
                if hasattr(ws,'close'): ws.close()
        print(json.dumps(data,indent=2,ensure_ascii=False))
        return 0
    except (ValueError,KeyError,OSError,RuntimeError) as exc:
        # Paths and arbitrary engine output are omitted from errors on this public channel.
        print(json.dumps({'error':type(exc).__name__,'message':str(exc) if isinstance(exc,ValueError) else 'Operation failed; check configuration and private diagnostics.'}),file=sys.stderr)
        return 2
