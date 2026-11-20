import { crc32 } from 'node:zlib';

export function zip(files: Record<string, Buffer> | [string, Buffer][]) {
  const local: Buffer[] = [], directory: Buffer[] = [];
  let offset = 0;
  for (const [file, body] of Array.isArray(files) ? files : Object.entries(files)) {
    const name = Buffer.from(file);
    const entry = Buffer.alloc(30), header = Buffer.alloc(46), crc = crc32(body);
    entry.writeUInt32LE(0x04034b50, 0); entry.writeUInt16LE(20, 4); entry.writeUInt32LE(crc, 14);
    entry.writeUInt32LE(body.length, 18); entry.writeUInt32LE(body.length, 22); entry.writeUInt16LE(name.length, 26);
    header.writeUInt32LE(0x02014b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(20, 6);
    header.writeUInt32LE(crc, 16); header.writeUInt32LE(body.length, 20); header.writeUInt32LE(body.length, 24);
    header.writeUInt16LE(name.length, 28); header.writeUInt32LE(offset, 42);
    local.push(entry, name, body); directory.push(header, name);
    offset += entry.length + name.length + body.length;
  }
  const central = Buffer.concat(directory), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(local.length / 3, 8); end.writeUInt16LE(local.length / 3, 10);
  end.writeUInt32LE(central.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, central, end]);
}
