const isUndefinedOrEmpty = <T>(
  value: string | undefined,
  replace_value: T | undefined,
): string | T => {
  if (value === undefined || value.trim() === "") {
    return replace_value as T;
  }
  return value as T;
};

export const NODE_ENV = isUndefinedOrEmpty(Bun.env.NODE_ENV, "development");

export const MOCINNO_PORT = Number(
  isUndefinedOrEmpty<number>(Bun.env.MOCINNO_PORT, 3000),
);

export const MOCINNO_MAX_BODY_REQUEST_SIZE = Number(
  isUndefinedOrEmpty<number>(
    Bun.env.MOCINNO_MAX_BODY_REQUEST_SIZE,
    1024 * 1024 * 128,
  ),
);

export const MOCINNO_HOSTNAME = isUndefinedOrEmpty(
  Bun.env.MOCINNO_HOSTNAME,
  "localhost",
);

export const ENCRYPTION_KEY = (() => {
  if (!isUndefinedOrEmpty(Bun.env.ENCRYPTION_KEY, undefined)) {
    throw new Error("ENCRYPTION_KEY environment variable is required");
  }
  return Bun.env.ENCRYPTION_KEY as string;
})();

export const DISABLE_SSL =
  isUndefinedOrEmpty(Bun.env.DISABLE_SSL, "false").toLowerCase() === "true";

export const SMTP_HOST = isUndefinedOrEmpty(Bun.env.SMTP_HOST, "localhost");
export const SMTP_PORT = Number(isUndefinedOrEmpty(Bun.env.SMTP_PORT, 587));
export const SMTP_USER = isUndefinedOrEmpty(Bun.env.SMTP_USER, undefined);
export const SMTP_PASSWORD = isUndefinedOrEmpty(
  Bun.env.SMTP_PASSWORD,
  undefined,
);

export const ROOTFS = isUndefinedOrEmpty(Bun.env.ROOTFS, "local-zfs:8");
