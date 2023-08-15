// [START mediacdn_dualtoken_sign_token]
"use strict";

const crypto = require("crypto");
/**
 * Generate tokens for MediaCDN Dual-token Auth
 *
 * @param {string} base64_key
 * @param {string} signature_algorithm
 * @param {Date} start_time
 * @param {Date} expiration_time
 * @param {string} url_prefix
 * @param {string} full_path
 * @param {string} path_globs
 * @param {string} session_id
 * @param {string} data
 * @param {Array} headers
 * @param {string} ip_ranges
 */
module.exports.sign_token = function ({
  base64_key,
  signature_algorithm,
  start_time,
  expiration_time,
  url_prefix,
  full_path,
  path_globs,
  session_id,
  data,
  headers,
  ip_ranges,
}) {
  const decoded_key = Buffer.from(base64_key, "base64");
  const algo = signature_algorithm.toLowerCase();

  const tokens = [];
  const to_sign = [];

  if (full_path !== undefined) {
    tokens.push("FullPath");
    to_sign.push(`FullPath=${full_path}`);
  } else if (path_globs !== undefined) {
    path_globs = path_globs.trim();
    const field = `PathGlobs=${path_globs}`;
    tokens.push(field);
    to_sign.push(field);
  } else if (url_prefix !== undefined) {
    const field = "URLPrefix=" + Buffer.from(url_prefix).toString("base64url");
    tokens.push(field);
    to_sign.push(field);
  } else {
    throw new Error(
      "User Input Missing: One of `url_prefix`, `full_path` or `path_globs` must be specified",
    );
  }

  // check & parse optional params
  if (start_time !== undefined) {
    const field = `Starts=${parseInt(start_time / 1000)}`;
    tokens.push(field);
    to_sign.push(field);
  }

  if (expiration_time === undefined) {
    const date = new Date();
    expiration_time = date.setTime(date.getTime() + 1 * 60 * 60 * 1000);
  }
  const field = `Expires=${parseInt(expiration_time / 1000)}`;
  tokens.push(field);
  to_sign.push(field);

  if (session_id !== undefined) {
    const field = `SessionID=${session_id}`;
    tokens.push(field);
    to_sign.push(field);
  }

  if (data !== undefined) {
    const field = `Data=${data}`;
    tokens.push(field);
    to_sign.push(field);
  }

  if (headers !== undefined) {
    const header_names = [];
    const header_pairs = [];

    headers.forEach((each) => {
      header_names.push(each["name"]);
      header_pairs.push(`${each["name"]}=${each["value"]}`);
    });
    tokens.push(`Headers=${header_names.join(",")}`);
    to_sign.push(`Headers=${header_pairs.join(",")}`);
  }

  if (ip_ranges !== undefined) {
    const field = `IPRanges=${Buffer.from(ip_ranges).toString("base64url")}`;
    tokens.push(field);
    to_sign.push(field);
  }

  // generating token
  const to_sign_string = to_sign.join("~");
  if (algo === "ed25519") {
    // construct DER encoded PKCS#8 key that crypto.sign() requires
    // 302e020100300506032b657004220420 is the algorithm marker
    const private_key = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from("302e020100300506032b657004220420", "hex"),
        decoded_key,
      ]),
      format: "der",
      type: "pkcs8",
    });
    const digest = crypto.sign(null, Buffer.from(to_sign_string), {
      key: private_key,
    });
    tokens.push("Signature=" + Buffer.from(digest).toString("base64url"));
  } else if (algo === "sha256") {
    const signature = crypto
      .createHmac("sha256", decoded_key)
      .update(to_sign_string)
      .digest("hex");
    tokens.push("hmac=" + signature);
  } else if (algo === "sha1") {
    const signature = crypto
      .createHmac("sha1", decoded_key)
      .update(to_sign_string)
      .digest("hex");
    tokens.push("hmac=" + signature);
  } else {
    throw new Error(
      "Input Missing Error: `signature_algorithm` can only be one of `sha1`, `sha256` or `ed25519`",
    );
  }
  return tokens.join("~");
}
// [END mediacdn_dualtoken_sign_token]
