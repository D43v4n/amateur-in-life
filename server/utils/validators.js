function isValidDomain(d) {
  return /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(d);
}

function isValidPort(p) {
  const n = parseInt(p, 10);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

module.exports = { isValidDomain, isValidPort };
