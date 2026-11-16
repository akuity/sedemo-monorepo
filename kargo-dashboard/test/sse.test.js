import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSSE } from '../src/sse.js';

const enc = new TextEncoder();
async function collect(chunks) {
  const out = [];
  for await (const x of parseSSE(chunks)) out.push(x);
  return out;
}
const split = (bytes, sizes) => {
  const out = []; let i = 0;
  for (const s of sizes) { out.push(bytes.slice(i, i + s)); i += s; }
  out.push(bytes.slice(i));
  return out.filter((c) => c.length);
};

const STREAM = ': keepalive\n\ndata: {"type":"ADDED"}\n\nevent: error\ndata: {"code":"out_of_range"}\n\ndata: a\ndata: b\n\n';
const EXPECT = [
  { comment: 'keepalive' },
  { event: 'message', data: '{"type":"ADDED"}', id: undefined },
  { event: 'error', data: '{"code":"out_of_range"}', id: undefined },
  { event: 'message', data: 'a\nb', id: undefined },
];

test('parses events, named events, multi-line data and comments', async () => {
  assert.deepEqual(await collect([enc.encode(STREAM)]), EXPECT);
});

test('the same result however the bytes are split, at every boundary', async () => {
  const bytes = enc.encode(STREAM);
  for (let n = 1; n < bytes.length; n += 1) {
    assert.deepEqual(await collect(split(bytes, [n])), EXPECT, `split at ${n}`);
  }
  assert.deepEqual(await collect(split(bytes, new Array(bytes.length).fill(1))), EXPECT, 'one byte at a time');
});

test('handles \\r\\n and bare \\r line endings, including \\r\\n split across chunks', async () => {
  const crlf = 'data: x\r\n\r\ndata: y\r\rdata: z\r\n\r\n';
  const want = [{ event: 'message', data: 'x', id: undefined }, { event: 'message', data: 'y', id: undefined }, { event: 'message', data: 'z', id: undefined }];
  assert.deepEqual(await collect([enc.encode(crlf)]), want);
  const bytes = enc.encode(crlf);
  for (let n = 1; n < bytes.length; n += 1) assert.deepEqual(await collect(split(bytes, [n])), want, `split at ${n}`);
});

test('a multibyte character split across chunks is decoded intact', async () => {
  const bytes = enc.encode('data: héllo ✓ 😀\n\n');
  for (let n = 1; n < bytes.length; n += 1) {
    assert.deepEqual(await collect(split(bytes, [n])), [{ event: 'message', data: 'héllo ✓ 😀', id: undefined }], `split at ${n}`);
  }
});

test('ignores unknown fields and retry, keeps id, and drops an unterminated trailing event', async () => {
  const out = await collect([enc.encode('retry: 5\nfoo: bar\nid: 7\ndata: ok\n\ndata: never-finished')]);
  assert.deepEqual(out, [{ event: 'message', data: 'ok', id: '7' }]);
});

test('a data field with no space after the colon and empty data lines', async () => {
  assert.deepEqual(await collect([enc.encode('data:a\ndata\n\n')]), [{ event: 'message', data: 'a\n', id: undefined }]);
});
