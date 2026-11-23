// A tiny in-memory "SQL" driver used only by this fixture so the SQL
// Injection example runs without a real database server. It reproduces
// exactly the one security-relevant behavior of a real driver: an
// unparameterized query lets injected syntax straight through, while
// binding values via the params array escapes them first -- so this stays
// honest about what HEALER's parameterized-query patch actually fixes.

const USERS = [{ id: 1, username: "admin", password: "admin123" }];

function resolve(sql, params) {
  if (!params || params.length === 0) return sql;
  let i = 0;
  return sql.replace(/\?/g, () => `'${String(params[i++]).replace(/'/g, "''")}'`);
}

function evaluate(sql) {
  if (/'\s*or\s*'?1'?\s*=\s*'?1'?/i.test(sql) || /\bor\s+1\s*=\s*1\b/i.test(sql)) {
    return [USERS[0]];
  }
  const match = /username\s*=\s*'([^']*)'[\s\S]*?password\s*=\s*'([^']*)'/i.exec(sql);
  if (match && match[1] === USERS[0].username && match[2] === USERS[0].password) {
    return [USERS[0]];
  }
  return [];
}

function query(sql, paramsOrCallback, maybeCallback) {
  const hasParams = Array.isArray(paramsOrCallback);
  const params = hasParams ? paramsOrCallback : [];
  const callback = hasParams ? maybeCallback : paramsOrCallback;
  const resolvedSql = resolve(sql, params);
  const rows = evaluate(resolvedSql);
  callback(null, rows);
}

module.exports = { query };
