// SPDX-License-Identifier: AGPL-3.0-or-later
// readObject: fetch objects/{uuid} with the session's credentials and
// open it with the file's data key — the one read path the folder UI,
// search indexing and export share. `entry` is a materialised manifest
// entry (uuid, data_key_iv, data_key_ct, content_iv, chunk_size, size).

import * as bucket from "./bucket.js";
import * as cryptoLib from "./crypto.js";

const OBJECTS_PREFIX = "objects/";

export async function readObject(session, entry, { signal } = {}) {
  if (!entry?.uuid) throw new Error("readObject: entry has no uuid");
  const get = await bucket.signedGet({
    url: session.bucketBase + OBJECTS_PREFIX + entry.uuid,
    region: session.region, accessKey: session.accessKey, secretKey: session.secretKey, signal,
  });
  if (!get.ok) throw new Error(`GET object failed: ${get.status} ${get.message ?? ""}`);
  const dataKey = await cryptoLib.unwrapDataKey(
    session.masterKey,
    cryptoLib.fromBase64(entry.data_key_iv),
    cryptoLib.fromBase64(entry.data_key_ct),
    entry.uuid,
  );
  try {
    return await cryptoLib.openObject(dataKey, get.body, entry);
  } finally {
    cryptoLib.zero(dataKey);
  }
}
