interface CsvRow { title: string; url: string; username: string; password: string; note: string }

/** Runs inside the short-lived import worker. URLs are parsed, never visited. */
export function prepareBrowserCsv(parsed: string): string {
  const batch = JSON.parse(parsed) as { rows: CsvRow[]; invalid: number; ignoredOtp: number };
  const rows = batch.rows.flatMap(row => {
    try {
      const url = new URL(row.url);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
      return [{ title: row.title || url.hostname, note: row.note,
        data: { kind: 'login', username: row.username, password: row.password, uris: [{ uri: url.href }] } }];
    } catch {
      batch.invalid++;
      return [];
    }
  });
  return JSON.stringify({ rows, invalid: batch.invalid, ignoredOtp: batch.ignoredOtp });
}
