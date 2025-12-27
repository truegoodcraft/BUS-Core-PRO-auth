export const checkRateLimit = async (
  kv: KVNamespace,
  key: string,
  limit: number,
  windowSeconds: number
): Promise<boolean> => {
  const currentValue = await kv.get(key);

  if (currentValue === null) {
    await kv.put(key, "1", { expirationTtl: windowSeconds });
    return true;
  }

  const count = Number.parseInt(currentValue, 10) || 0;
  if (count >= limit) {
    return false;
  }

  const nextCount = count + 1;
  await kv.put(key, nextCount.toString(), { expirationTtl: windowSeconds });
  return true;
};
