import * as path from 'node:path';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { EcosystemId, PackageRef } from '../../../src/core/types';
import {
  checkTyposquat,
  damerauLevenshtein,
  fetchRegistryReputation,
  loadTopPackages,
} from '../../../src/scanners/reputation';

const DATA = path.resolve(__dirname, '../../../data');
const ECOSYSTEMS: EcosystemId[] = ['npm', 'pypi', 'go', 'cargo', 'composer', 'maven', 'vscode'];
const tops = {} as Record<EcosystemId, string[]>;
let npmTop: string[];
let pypiTop: string[];

beforeAll(async () => {
  for (const e of ECOSYSTEMS) tops[e] = await loadTopPackages(e, DATA);
  npmTop = tops.npm;
  pypiTop = tops.pypi;
});

const ref = (ecosystem: EcosystemId, name: string, version = '1.0.0'): PackageRef => ({
  ecosystem,
  name,
  version,
});
const npm = (name: string, version = '1.0.0') => ref('npm', name, version);
const pypi = (name: string, version = '1.0.0') => ref('pypi', name, version);

describe('top package lists', () => {
  it('load bundled lists and tolerate missing ones', async () => {
    expect(npmTop.length).toBeGreaterThan(250);
    expect(pypiTop).toContain('python-dateutil');
    expect(await loadTopPackages('npm', path.join(DATA, 'missing'))).toEqual([]);
  });

  it.each(ECOSYSTEMS)('%s: is a sorted, unique, lower-case list', (e) => {
    const list = tops[e];
    expect(list.length).toBeGreaterThan(150);
    expect(list).toEqual([...new Set(list)].sort());
    expect(list.filter((n) => n !== n.toLowerCase())).toEqual([]);
  });
});

describe('damerauLevenshtein', () => {
  it.each([
    ['lodash', 'lodash', 0],
    ['lodahs', 'lodash', 1],
    ['lodas', 'lodash', 1],
    ['kitten', 'sitting', 3],
    ['', 'abc', 3],
  ])('%s vs %s = %d', (a, b, d) => {
    expect(damerauLevenshtein(a, b)).toBe(d);
  });
});

describe('checkTyposquat', () => {
  it.each([
    ['lodahs', 'lodash', npm],
    ['crossenv', 'cross-env', npm],
    ['electorn', 'electron', npm],
    ['express-js', 'express', npm],
    ['reqeusts', 'requests', pypi],
    ['python-dateutils', 'python-dateutil', pypi],
    ['djang0', 'django', pypi],
    ['Python_Dateutils', 'python-dateutil', pypi],
  ] as const)('flags %s as a squat of %s', (name, target, make) => {
    const f = checkTyposquat(make(name), make === npm ? npmTop : pypiTop);
    expect(f).toMatchObject({
      ruleId: 'reputation/typosquat',
      severity: 'medium',
      category: 'reputation',
    });
    expect(f?.title).toBe(`Possible typosquat of ${target}`);
  });

  it.each(ECOSYSTEMS)('%s: never flags popular packages themselves', (e) => {
    for (const name of tops[e]) expect(checkTyposquat(ref(e, name), tops[e]), name).toBeUndefined();
  });

  it.each([
    ['cargo', 'proc-macro1', 'proc-macro2'],
    ['cargo', 'serde_jsom', 'serde_json'],
    ['cargo', 'serde-jsno', 'serde_json'],
    ['cargo', 'tokio-utl', 'tokio-util'],
    ['cargo', 'rust-serde', 'serde'],
    ['cargo', 'reqwest-rs', 'reqwest'],
    ['go', 'github.com/gorila/mux', 'github.com/gorilla/mux'],
    ['go', 'github.com/gorillla/mux/v2', 'github.com/gorilla/mux'],
    ['go', 'github.com/spf13/cobar', 'github.com/spf13/cobra'],
    ['go', 'github.com/sirupsen/logrsu/hooks', 'github.com/sirupsen/logrus'],
    ['go', 'github.com/strechr/testify/assert', 'github.com/stretchr/testify'],
    ['go', 'githuh.com/stretchr/testify', 'github.com/stretchr/testify'],
    ['go', 'go1ang.org/x/crypto', 'golang.org/x/crypto'],
    ['go', 'github.com/Gorila/Mux', 'github.com/gorilla/mux'],
    ['composer', 'symfony/consle', 'symfony/console'],
    ['composer', 'guzzlehttp/guzle', 'guzzlehttp/guzzle'],
    ['composer', 'symfonny/console', 'symfony/console'],
    ['composer', 'laravel/framwork', 'laravel/framework'],
    ['composer', 'monolog/mono-log', 'monolog/monolog'],
    ['maven', 'org.apache.logging.log4j:log4j-cor', 'org.apache.logging.log4j:log4j-core'],
    [
      'maven',
      'com.fasterxml.jackson.core:jackson-databnd',
      'com.fasterxml.jackson.core:jackson-databind',
    ],
    ['maven', 'org.apache.loging.log4j:log4j-core', 'org.apache.logging.log4j:log4j-core'],
    ['maven', 'org.sprlngframework:spring-core', 'org.springframework:spring-core'],
    ['vscode', 'ms-pythom.python', 'ms-python.python'],
    ['vscode', 'esbenp.prettier-vscod', 'esbenp.prettier-vscode'],
    ['vscode', 'Esbenp.Prettier-VSCod', 'esbenp.prettier-vscode'],
    ['vscode', 'esbnep.prettier-vscode', 'esbenp.prettier-vscode'],
    ['vscode', 'dbaeumer.vscode-eslnt', 'dbaeumer.vscode-eslint'],
    ['vscode', 'gihtub.copilot', 'github.copilot'],
    ['vscode', 'ms-azure-tools.vscode-docker', 'ms-azuretools.vscode-docker'],
    ['vscode', 'eamodio.gitIens', 'eamodio.gitlens'],
    ['vscode', 'rust-lang.rust-analyser', 'rust-lang.rust-analyzer'],
  ] as const)('%s: flags %s as a squat of %s', (e, name, target) => {
    const f = checkTyposquat(ref(e, name), tops[e]);
    expect(f?.title).toBe(`Possible typosquat of ${target}`);
    expect(f).toMatchObject({ ruleId: 'reputation/typosquat', severity: 'medium' });
  });

  it('names the differing part of a path-like name', () => {
    expect(checkTyposquat(ref('go', 'github.com/gorila/mux'), tops.go)?.message).toBe(
      'github.com/gorila/mux looks like an imitation of the popular package github.com/gorilla/mux ' +
        '("gorila" instead of "gorilla" is a one-character typo away). Check that you meant to install it.',
    );
  });

  it.each([
    // Crates: versioned forks, short-named siblings, sub-crates, short names.
    ['cargo', 'serde_json5'],
    ['cargo', 'tracing_subscriber'],
    ['cargo', 'serde-json-lenient'],
    ['cargo', 'aws-sdk-sqs'],
    ['cargo', 'aws-sdk-sns'],
    ['cargo', 'tide'],
    ['cargo', 'rand_pcg'],
    ['cargo', 'tokio-test'],
    ['cargo', 'openssl-src'],
    ['cargo', 'my-internal-crate'],
    // Go: sub-modules and packages under a popular module, major versions, forks.
    ['go', 'github.com/aws/aws-sdk-go-v2/service/sqs'],
    ['go', 'github.com/aws/aws-sdk-go-v2/service/s3'],
    ['go', 'github.com/aws/aws-sdk-go-v2/feature/s3/manager'],
    ['go', 'cloud.google.com/go/firestore'],
    ['go', 'github.com/go-chi/chi/v6'],
    ['go', 'gopkg.in/yaml.v1'],
    ['go', 'github.com/stretchr/testify/require'],
    ['go', 'github.com/myfork/mux'],
    ['go', 'github.com/spf13/cobra-cli'],
    ['go', 'gitlab.com/gorilla/mux'],
    ['go', 'golang.org/x/vuln'],
    ['go', 'golang.org/x/arch'],
    ['go', 'k8s.io/client-gen'],
    ['go', 'github.com/hashicorp/consul/sdk'],
    ['go', 'example.com/internal/thing'],
    // Composer: siblings in a vendor, plugins, other vendors with the same name.
    ['composer', 'symfony/polyfill-php83'],
    ['composer', 'symfony/security-guard'],
    ['composer', 'laravel/vapor-core'],
    ['composer', 'illuminate/testing'],
    ['composer', 'spatie/laravel-query-builder'],
    ['composer', 'acme/console'],
    ['composer', 'guzzlehttp/guzzle-services'],
    // Maven: siblings in a group, version suffixes, relocated groups, Scala builds.
    ['maven', 'org.apache.spark:spark-core_2.13'],
    ['maven', 'com.amazonaws:aws-java-sdk-sns'],
    ['maven', 'software.amazon.awssdk:sns'],
    ['maven', 'org.apache.maven.plugins:maven-pmd-plugin'],
    ['maven', 'org.springframework.boot:spring-boot-starter-batch'],
    ['maven', 'org.apache.logging.log4j:log4j-iostreams'],
    ['maven', 'com.squareup.okhttp3:okhttp-sse'],
    ['maven', 'io.prometheus:simpleclient_httpserver'],
    ['maven', 'org.apache.httpcomponents:httpclient-cache'],
    ['maven', 'org.apache.httpcomponents.client5:httpclient'],
    ['maven', 'org.apache.commons:commons-collections'],
    ['maven', 'org.springframework.ws:spring-ws-core'],
    ['maven', 'com.example:guava'],
    ['maven', 'org.apache.poi:poi-scratchpad'],
    ['maven', 'junit'],
    // Extensions: the same name from another publisher, siblings, forks, short ids.
    ['vscode', 'acme.python'],
    ['vscode', 'someone.prettier-vscode'],
    ['vscode', 'github.copilot-labs'],
    ['vscode', 'esbenp.prettier-vscode-fork'],
    ['vscode', 'ms-ceintl.vscode-language-pack-nl'],
    ['vscode', 'ms-vscode.remote-ssh'],
    ['vscode', 'redhat.vscode-commons'],
    ['vscode', 'vue.volar2'],
    ['vscode', 'my-company.internal-tools'],
    ['vscode', 'nodot'],
  ] as const)('%s: does not flag %s', (e, name) => {
    expect(checkTyposquat(ref(e, name), tops[e])).toBeUndefined();
  });

  it.each([
    'react-dom-utils',
    'lodash.pick',
    'eslint-plugin-foo',
    '@scope/lodahs',
    'abc',
    'my-internal-lib',
  ])('does not flag %s', (name) => {
    expect(checkTyposquat(npm(name), npmTop)).toBeUndefined();
  });
});

function npmDoc(over: Record<string, unknown> = {}) {
  return {
    repository: { url: 'git+https://example.invalid/repo.git' },
    time: {
      created: '2015-01-01T00:00:00Z',
      '0.9.0': '2020-01-01T00:00:00Z',
      '1.0.0': '2021-01-01T00:00:00Z',
    },
    versions: {
      '0.9.0': { _npmUser: { name: 'alice' }, maintainers: [{ name: 'alice' }, { name: 'bob' }] },
      '1.0.0': { _npmUser: { name: 'bob' } },
    },
    ...over,
  };
}

function registry(routes: Record<string, unknown | number>) {
  return vi.fn(async (url: string | URL | Request) => {
    const hit = routes[String(url)];
    if (hit === undefined) return new Response('', { status: 500 });
    if (typeof hit === 'number') return new Response('', { status: hit });
    return Response.json(hit);
  });
}

const NOW = new Date('2026-11-02T00:00:00Z');
const ids = (r: { findings: Array<{ ruleId: string; package: { name: string } }> }) =>
  r.findings.map((f) => `${f.package.name}:${f.ruleId}`).sort();

describe('fetchRegistryReputation', () => {
  it('reports nothing for an established npm package', async () => {
    const fetchImpl = registry({ 'https://registry.npmjs.org/ok': npmDoc() });
    expect(
      await fetchRegistryReputation([npm('ok')], { enabled: true, fetchImpl, now: NOW }),
    ).toEqual({
      findings: [],
      errors: [],
    });
  });

  it('flags new, fresh, deprecated, unlinked and newly maintained npm releases', async () => {
    const fetchImpl = registry({
      'https://registry.npmjs.org/@scope%2Fnew': {
        time: { created: '2026-10-25T00:00:00Z', '1.0.0': '2026-11-01T00:00:00Z' },
        versions: { '1.0.0': { deprecated: 'use something else' } },
      },
      'https://registry.npmjs.org/taken-over': npmDoc({
        versions: {
          '0.9.0': { _npmUser: { name: 'alice' }, maintainers: [{ name: 'alice' }] },
          '1.0.0': { _npmUser: { name: 'mallory' } },
        },
      }),
      'https://registry.npmjs.org/private-name': 404,
    });
    const result = await fetchRegistryReputation(
      [npm('@scope/new'), npm('taken-over'), npm('private-name')],
      { enabled: true, fetchImpl, now: NOW },
    );
    expect(result.errors).toEqual([]);
    expect(ids(result)).toEqual([
      '@scope/new:reputation/deprecated',
      '@scope/new:reputation/fresh-version',
      '@scope/new:reputation/new-package',
      '@scope/new:reputation/no-repository',
      'private-name:reputation/not-in-registry',
      'taken-over:reputation/maintainer-change',
    ]);
    const missing = result.findings.find((f) => f.ruleId === 'reputation/not-in-registry');
    expect(missing).toMatchObject({ severity: 'high', source: 'reputation' });
    expect(missing?.message).toContain('dependency confusion');
  });

  it('checks PyPI releases', async () => {
    const fetchImpl = registry({
      'https://pypi.org/pypi/old/json': {
        info: { project_urls: { Source: 'https://example.invalid' } },
        releases: {
          '1.0.0': [
            { upload_time_iso_8601: '2019-01-01T00:00:00Z', yanked: true, yanked_reason: 'broken' },
          ],
        },
      },
      'https://pypi.org/pypi/fresh/json': {
        info: { home_page: null, project_urls: null },
        releases: { '1.0.0': [{ upload_time_iso_8601: '2026-11-01T00:00:00Z' }] },
      },
      'https://pypi.org/pypi/gone/json': 404,
    });
    const result = await fetchRegistryReputation([pypi('old'), pypi('fresh'), pypi('gone')], {
      enabled: true,
      fetchImpl,
      now: NOW,
    });
    expect(ids(result)).toEqual([
      'fresh:reputation/fresh-version',
      'fresh:reputation/new-package',
      'fresh:reputation/no-repository',
      'gone:reputation/not-in-registry',
      'old:reputation/yanked',
    ]);
    expect(result.findings.find((f) => f.ruleId === 'reputation/yanked')?.message).toContain(
      'broken',
    );
  });

  it('reports registry errors and skips unsupported ecosystems', async () => {
    const fetchImpl = registry({});
    const result = await fetchRegistryReputation(
      [npm('down'), { ecosystem: 'cargo', name: 'serde', version: '1.0.0' }],
      { enabled: true, fetchImpl },
    );
    expect(result).toEqual({ findings: [], errors: ['Registry lookup for down failed: HTTP 500'] });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const pyDown = await fetchRegistryReputation([pypi('down')], { enabled: true, fetchImpl });
    expect(pyDown.errors).toEqual(['Registry lookup for down failed: HTTP 500']);
  });
});
