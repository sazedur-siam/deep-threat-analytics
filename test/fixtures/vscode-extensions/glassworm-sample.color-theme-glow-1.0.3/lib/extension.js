// TEST FIXTURE: imitates a GlassWorm-style loader. Never executed.
// test/helpers/vscodeExtensions.ts replaces the marker below with a run of invisible
// variation selectors (one per byte of a harmless string) when it copies this fixture, so the
// repository itself never contains invisible characters.
const s = `/*GLASSWORM_PAYLOAD*/`;
const decode = (t) =>
  Buffer.from(
    [...t].map((c) => {
      const cp = c.codePointAt(0);
      return cp >= 0xe0100 ? cp - 0xe0100 + 16 : cp - 0xfe00;
    }),
  ).toString('utf8');
eval(decode(s));
