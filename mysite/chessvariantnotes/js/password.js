export const MIN_PASSWORD_LENGTH = 8;
export function validatePassword(pw) {
  var explanation = `Password min length ${MIN_PASSWORD_LENGTH} incl at least one of upper/lower/digit/symbol each`;
  if (!pw) return { ok: false, message: 'Password required' };
  if (pw.length < MIN_PASSWORD_LENGTH) return { ok: false, message: `${explanation}` };
  if (!/[a-z]/.test(pw)) return { ok: false, message: `${explanation}` };
  if (!/[A-Z]/.test(pw)) return { ok: false, message: `${explanation}` };
  if (!/[0-9]/.test(pw)) return { ok: false, message: `${explanation}` };
  if (!/[^A-Za-z0-9]/.test(pw)) return { ok: false, message: `${explanation}` };
  return { ok: true };
}
