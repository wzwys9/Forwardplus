export function createHomepageDocument(html: string, baseHref = "/") {
  const content = String(html || "").trim();
  if (!content) return "";

  const safeBaseHref = baseHref.replace(/"/g, "%22");
  const headAdditions = [
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<base href="${safeBaseHref}" target="_top">`,
  ].join("");

  if (/<head[\s>]/i.test(content)) {
    return content.replace(/<head([^>]*)>/i, `<head$1>${headAdditions}`);
  }
  if (/<html[\s>]/i.test(content)) {
    return content.replace(/<html([^>]*)>/i, `<html$1><head>${headAdditions}</head>`);
  }

  return `<!doctype html><html><head>${headAdditions}</head><body>${content}</body></html>`;
}
