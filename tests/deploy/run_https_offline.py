"""Linux-only standalone integration checks; see tests/deploy/README.md."""
import os, subprocess, tempfile, pathlib, shutil, yaml
from offline_support import prepare_test_tree
src=pathlib.Path(__file__).resolve().parents[2]
real_openssl=shutil.which('openssl')
with tempfile.TemporaryDirectory(prefix='https-deploy-test-') as tmp:
    r=pathlib.Path(tmp); prepare_test_tree(src, r)
    b=r/'bin';b.mkdir();state=r/'runtime/public-https';state.mkdir(parents=True)
    secrets=r/'runtime/secrets';secrets.mkdir(parents=True)
    fixtures=r/'fixtures';fixtures.mkdir()
    def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    run(real_openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','7','-keyout',str(fixtures/'key'),'-out',str(secrets/'server.crt'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1')
    run(real_openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','7','-keyout',str(fixtures/'public.key'),'-out',str(fixtures/'public.crt'),'-subj','/CN=Fixture public cert','-addext','subjectAltName=IP:203.0.113.10')
    config=f'''HTTPS_PUBLIC_IP=203.0.113.10
HTTPS_PUBLIC_PORT=8443
HTTPS_ACME_EMAIL=fixture@example.invalid
HTTPS_ACME_REGISTER_WITHOUT_EMAIL=false
HTTPS_COMPOSE_PROJECT=existing-project
HTTPS_UPSTREAM_TLS_NAME=localhost
HTTPS_CA_BUNDLE={fixtures}/public.crt
'''
    (state/'config.env').write_text(config)
    (b/'docker').write_text('''#!/usr/bin/env bash
printf 'port=%s %s\\n' "$HTTPS_PUBLIC_PORT" "$*" >> "$TEST_ROOT/docker.log"
case "$*" in
  *'config --format json') printf '{"services":{"server":{"command":["uvicorn","--port","%s"],"ports":[{"target":%s,"published":"%s","protocol":"tcp"}]}}}\\n' "${TEST_BACKEND_PORT:-8765}" "${TEST_BACKEND_PORT:-8765}" "${TEST_BACKEND_HOST_PORT:-8765}";;
  *'ps --status running -q server') echo fixture-server;;
  *'public-https nginx -t') [[ ! -f "$TEST_ROOT/fail-nginx" ]];;
  *'public-https nginx -s reload') touch "$TEST_ROOT/reloaded";;
esac
''')
    (b/'curl').write_text('#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "$TEST_ROOT/curl.log"\nprintf \'{"status":"ok"}\\n\'\n')
    (b/'ss').write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$TEST_ROOT/ss.log"
if [[ -f "$TEST_ROOT/occupied" ]]; then
    port=$(cat "$TEST_ROOT/occupied")
    if [[ "$*" == *":$port "* ]]; then
        echo "LISTEN 0 511 0.0.0.0:$port 0.0.0.0:*"
    fi
fi
''')
    (b/'openssl').write_text(f'''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$TEST_ROOT/openssl.log"
case "$*" in
  "s_client -connect 127.0.0.1:${{TEST_BACKEND_HOST_PORT:-8765}} "*) cat "$TEST_ROOT/runtime/secrets/server.crt"; exit 0;;
  "s_client -connect 127.0.0.1:$HTTPS_PUBLIC_PORT "*)
     [[ -f "$TEST_ROOT/reloaded" ]] || exit 1
     cat "$TEST_ROOT/fixtures/public.crt"; exit 0;;
esac
exec {real_openssl} "$@"
''')
    for f in b.iterdir(): f.chmod(0o755)
    env=dict(os.environ, PATH=str(b)+':'+os.environ['PATH'], TEST_ROOT=str(r))
    def check(name,args,success=True,contains=None):
        x=subprocess.run(['bash',str(r/'deploy/https/manage.sh'),*args],env=env,universal_newlines=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        assert (x.returncode==0)==success,(name,x.returncode,x.stdout,x.stderr)
        if contains: assert contains in x.stdout+x.stderr,(name,x.stdout,x.stderr)
        print('PASS:',name)
    check('upstream DNS SAN plus certificate preflight',['preflight'])
    assert (state/'upstream/server.crt').read_bytes()==(secrets/'server.crt').read_bytes()
    env.update(TEST_BACKEND_PORT='9876', TEST_BACKEND_HOST_PORT='19876')
    check('preflight uses configured backend host port',['preflight'])
    assert 's_client -connect 127.0.0.1:19876 ' in (r/'openssl.log').read_text()
    for invalid_port in ['0', '80', '65536', '-1', 'abc', '8443;false']:
        (state/'config.env').write_text(config.replace('HTTPS_PUBLIC_PORT=8443', f'HTTPS_PUBLIC_PORT={invalid_port!r}'))
        check(f'invalid HTTPS port {invalid_port!r} rejected',['preflight'],False,'HTTPS_PUBLIC_PORT')
    (state/'config.env').write_text(config.replace('HTTPS_PUBLIC_PORT=8443\n', ''))
    check('missing port retains default 443',['compose', 'config', '--quiet'])
    assert 'port=443 ' in (r/'docker.log').read_text()
    (state/'config.env').write_text(config.replace('TLS_NAME=localhost','TLS_NAME=wrong-name'))
    check('wrong upstream DNS SAN fails closed',['preflight'],False,'not an exact DNS SAN')
    (state/'config.env').write_text(config)
    (r/'occupied').write_text('80')
    check('occupied TCP80 blocks bootstrap',['bootstrap'],False,'already in use')
    (r/'occupied').write_text('8443')
    check('occupied configured HTTPS port blocks bootstrap',['bootstrap'],False,'already in use')
    (r/'occupied').write_text('443')
    check('bootstrap with no public certificate',['bootstrap'])
    assert ':8443 ' in (r/'ss.log').read_text()
    assert 'port=8443 ' in (r/'docker.log').read_text()
    (r/'occupied').unlink()
    assert 'ssl_certificate' not in (state/'nginx/default.conf').read_text()
    check('bootstrap never overwrites active config',['bootstrap'],False,'will not overwrite')
    check('issuance requires explicit terms option',['issue'],False,'terms')
    check('staging uses isolated directories',['test-issuance','--accept-le-terms'],True,'no staging certificate')
    assert '--config-dir /etc/letsencrypt/staging/config' in (r/'docker.log').read_text()
    no_email=config.replace('HTTPS_ACME_EMAIL=fixture@example.invalid', 'HTTPS_ACME_EMAIL=').replace('HTTPS_ACME_REGISTER_WITHOUT_EMAIL=false', 'HTTPS_ACME_REGISTER_WITHOUT_EMAIL=true')
    (state/'config.env').write_text(no_email)
    (r/'docker.log').write_text('')
    check('explicit no-email registration',['test-issuance','--accept-le-terms'])
    assert '--register-unsafely-without-email' in (r/'docker.log').read_text()
    assert '--email ' not in (r/'docker.log').read_text()
    (state/'config.env').write_text(no_email.replace('HTTPS_ACME_REGISTER_WITHOUT_EMAIL=true', 'HTTPS_ACME_REGISTER_WITHOUT_EMAIL=false'))
    check('empty email requires explicit opt-in',['test-issuance','--accept-le-terms'],False,'contact email')
    (state/'config.env').write_text(config.replace('HTTPS_ACME_REGISTER_WITHOUT_EMAIL=false', 'HTTPS_ACME_REGISTER_WITHOUT_EMAIL=true'))
    check('email and no-email mode cannot conflict',['test-issuance','--accept-le-terms'],False,'Leave HTTPS_ACME_EMAIL empty')
    (state/'config.env').write_text(config)
    check('activation refuses missing public certificate',['activate'],False,'No production certificate')
    live=state/'acme/live/session-notify-public';live.mkdir()
    for n in ['cert.pem','chain.pem','fullchain.pem']: shutil.copy(fixtures/'public.crt',live/n)
    (r/'fail-nginx').touch()
    before=(state/'nginx/default.conf').read_text()
    check('failed nginx test restores previous config',['activate'],False,'previous config restored')
    assert (state/'nginx/default.conf').read_text()==before
    assert not (r/'reloaded').exists()
    (r/'fail-nginx').unlink()
    check('activation verifies loaded certificate and health',['activate'],True,'loaded certificate and /health verified')
    assert 'proxy_ssl_verify on;' in (state/'nginx/default.conf').read_text()
    assert 'set $session_notify_backend server:9876;' in (state/'nginx/default.conf').read_text()
    assert '__UPSTREAM_PORT__' not in (state/'nginx/default.conf').read_text()
    curl_args=(r/'curl.log').read_text()
    assert '--connect-to 203.0.113.10:8443:127.0.0.1:8443' in curl_args
    assert 'https://203.0.113.10:8443/health' in curl_args
    (r/'docker.log').write_text('')
    check('no-op renewal does not reload',['renew'])
    assert 'nginx -s reload' not in (r/'docker.log').read_text()
    check('manual renewal delegates to managed gateway',['renew'])
    assert 'exec -T public-https python /opt/gateway/gateway.py renew' in (r/'docker.log').read_text()
    shutil.copy(secrets/'server.crt',live/'cert.pem')
    check('untrusted or wrong-IP certificate rejected',['activate'],False)
    a=yaml.safe_load((r/'compose.https.yaml').read_text())
    assert 'server' not in a['services']
    assert 'session_notify_data' not in str(a)
    assert 'docker.sock' not in str(a)
    assert '${HTTPS_PUBLIC_PORT:-443}:443' in a['services']['public-https']['ports']
    print('PASS: additive overlay has no original service/database changes or Docker socket')
print('All offline cases passed. Docker, nginx and network handshakes are mocked; real OpenSSL certificate validation is used.')
