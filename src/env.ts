import { readFileSync } from "node:fs";

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

export const APP_DOMAIN = isUndefinedOrEmpty(Bun.env.APP_DOMAIN, undefined);

export const SMTP_HOST = isUndefinedOrEmpty(Bun.env.SMTP_HOST, "localhost");
export const SMTP_PORT = Number(isUndefinedOrEmpty(Bun.env.SMTP_PORT, 587));
export const SMTP_USER = isUndefinedOrEmpty(Bun.env.SMTP_USER, undefined);
export const SMTP_FROM = isUndefinedOrEmpty(Bun.env.SMTP_FROM, undefined);
export const SMTP_PASSWORD = isUndefinedOrEmpty(
  Bun.env.SMTP_PASSWORD,
  undefined,
);

export const ROOTFS = isUndefinedOrEmpty(Bun.env.ROOTFS, "local-zfs:8");

export const BASTION_PROXY_KEY_PUB = isUndefinedOrEmpty(
  Bun.env.BASTION_PROXY_KEY_PUB,
  "./bastion_proxy_key.pub",
);

export const BASTION_PROXY_KEY = isUndefinedOrEmpty(
  Bun.env.BASTION_PROXY_KEY,
  "./bastion_proxy_key",
);

export const BASTION_PUB_KEY = readFileSync(
  BASTION_PROXY_KEY_PUB,
  "utf-8",
).trim();

export const BASTION_PRIV_KEY = readFileSync(BASTION_PROXY_KEY, "utf-8").trim();

export const OAUTH_CLIENT_ID = (() => {
  if (!isUndefinedOrEmpty(Bun.env.OAUTH_CLIENT_ID, undefined)) {
    throw new Error("OAUTH_CLIENT_ID environment variable is required");
  }

  return Bun.env.OAUTH_CLIENT_ID as string;
})();

export const OAUTH_CLIENT_SECRET = (() => {
  if (!isUndefinedOrEmpty(Bun.env.OAUTH_CLIENT_SECRET, undefined)) {
    throw new Error("OAUTH_CLIENT_SECRET environment variable is required");
  }

  return Bun.env.OAUTH_CLIENT_SECRET as string;
})();

export const OAUTH_CLIENT_REDIRECT_URI = (() => {
  if (!isUndefinedOrEmpty(Bun.env.OAUTH_CLIENT_REDIRECT_URI, undefined)) {
    throw new Error(
      "OAUTH_CLIENT_REDIRECT_URI environment variable is required",
    );
  }

  return Bun.env.OAUTH_CLIENT_REDIRECT_URI as string;
})();

export const OS_TEMPLATE = isUndefinedOrEmpty(
  Bun.env.OS_TEMPLATE,
  "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst",
);
