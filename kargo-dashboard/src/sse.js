// Server-Sent Events parser. Pure: no I/O.
// parseSSE(chunks) takes any async (or sync) iterable of Uint8Array and yields
//   { event, data, id }  for each dispatched event (event defaults to 'message'), and
//   { comment }          for each comment line (": keepalive"), so callers can count them as activity.

export async function* parseSSE(chunks) {
  const decoder = new TextDecoder('utf-8');
  let buffer = '';
  let cur = { event: '', data: [], id: undefined, has: false };
  let skipLF = false; // the previous chunk ended with \r, so a leading \n belongs to it

  function* processLine(line) {
    if (line === '') {
      if (cur.has) yield { event: cur.event || 'message', data: cur.data.join('\n'), id: cur.id };
      cur = { event: '', data: [], id: undefined, has: false };
      return;
    }
    if (line.startsWith(':')) { yield { comment: line.slice(1).replace(/^ /, '') }; return; }
    const i = line.indexOf(':');
    const field = i < 0 ? line : line.slice(0, i);
    const value = i < 0 ? '' : line.slice(i + 1).replace(/^ /, '');
    if (field === 'data') { cur.data.push(value); cur.has = true; }
    else if (field === 'event') { cur.event = value; cur.has = true; }
    else if (field === 'id') { cur.id = value; }
    // retry and unknown fields are ignored
  }

  for await (const chunk of chunks) {
    buffer += typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
    if (skipLF && buffer.startsWith('\n')) buffer = buffer.slice(1);
    skipLF = false;
    let start = 0;
    for (let i = 0; i < buffer.length; i += 1) {
      const ch = buffer[i];
      if (ch !== '\n' && ch !== '\r') continue;
      if (ch === '\r' && i + 1 === buffer.length) { // \r at the end: maybe \r\n, so decide on the next chunk
        yield* processLine(buffer.slice(start, i));
        start = i + 1;
        skipLF = true;
        break;
      }
      yield* processLine(buffer.slice(start, i));
      if (ch === '\r' && buffer[i + 1] === '\n') i += 1;
      start = i + 1;
    }
    buffer = buffer.slice(start);
  }
}
