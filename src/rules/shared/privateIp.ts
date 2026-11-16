function parseIpv4Octets(ip: string): number[] | null {
  const parts = ip.split('.');

  if (parts.length !== 4) {
    return null;
  }

  const octets = parts.map((part) => Number(part));

  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return null;
  }

  return octets;
}

export function isPrivateIpv4(ip: string): boolean {
  const octets = parseIpv4Octets(ip);

  if (!octets) {
    return false;
  }

  if (octets[0] === 10) {
    return true;
  }

  if (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31) {
    return true;
  }

  if (octets[0] === 192 && octets[1] === 168) {
    return true;
  }

  return false;
}

function ipv4FromInAddrArpa(name: string): string | null {
  const labels = name.replace(/\.in-addr\.arpa$/i, '').split('.');

  if (labels.length !== 4 || labels.some((label) => !/^\d{1,3}$/.test(label))) {
    return null;
  }

  return labels.reverse().join('.');
}

export function isPrivateIpValue(value: string): boolean {
  const trimmed = value.trim();

  const withPort = /^(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?$/.exec(trimmed);

  if (withPort?.[1]) {
    return isPrivateIpv4(withPort[1]);
  }

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(trimmed);

  if (mapped?.[1]) {
    return isPrivateIpv4(mapped[1]);
  }

  if (/\.in-addr\.arpa$/i.test(trimmed)) {
    const ip = ipv4FromInAddrArpa(trimmed);
    return ip !== null && isPrivateIpv4(ip);
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) {
    return isPrivateIpv4(trimmed);
  }

  return false;
}
