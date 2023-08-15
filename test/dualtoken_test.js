'use strict';

const {assert} = require('chai');
const {it} = require('mocha');

const {sign_token} = require('../dualtoken.js')

// set token generator parameters
const start_time = new Date("2022-09-13T00:00:00Z");
const exp_time = new Date("2022-09-13T12:00:00Z");
const headers = [
  { name: "Foo", value: "bar" },
  { name: "BAZ", value: "quux" },
];
const ip_ranges = "203.0.113.0/24,2001:db8:4a7f:a732/64";
const data = "test-data";
const session_id = "test-id";


it('ed25519 url_prefix test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "DJUcnLguVFKmVCFnWGubG1MZg7fWAnxacMjKDhVZMGI=",
      signature_algorithm: "ed25519",
      expiration_time: exp_time,
      url_prefix: "http://10.20.30.40/",
    }) 
    === 'URLPrefix=aHR0cDovLzEwLjIwLjMwLjQwLw~Expires=1663070400~Signature=OQLXEjnApFGJaGZ_jvp2R7VY5q3ic-HT3igFpi9iPsJRXtQuvPF4cxZUT-rtCqzteXx3vSRhk09FxgDQauO_DA', true);
});

it('ed25519 path_glob test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "DJUcnLguVFKmVCFnWGubG1MZg7fWAnxacMjKDhVZMGI=",
      signature_algorithm: "ed25519",
      expiration_time: exp_time,
      path_globs: "/*",
    }) 
    === 'PathGlobs=/*~Expires=1663070400~Signature=9pBdD_6O6LB-4V67HZ_SOc2G_jIkSZ_tMsKnVqElmPlwKB_xDiW7DKAnv8L8CmweeZquaLFlnLogbMcIV8bNCQ', true);
});

it('ed25519 full_path test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "DJUcnLguVFKmVCFnWGubG1MZg7fWAnxacMjKDhVZMGI=",
      signature_algorithm: "ed25519",
      expiration_time: exp_time,
      full_path: "/example.m3u8",
    }) 
    === 'FullPath~Expires=1663070400~Signature=X74OTNjtseIUmsab-YiOTZ8jyX_KG7v4YQWwcFpfFmjhzaX8NdweMc9Wglj8wxEsEW85g3_MBG3T9jzLZFQDCw', true);
});

it('sha1 url_prefix test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
      signature_algorithm: "sha1",
      expiration_time: exp_time,
      url_prefix: "http://10.20.30.40/",
    }) 
    === 'URLPrefix=aHR0cDovLzEwLjIwLjMwLjQwLw~Expires=1663070400~hmac=6f5b4bb82536810d5ee111cba3e534d49c6ac3cb', true);
});

it('sha1 path_glob test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
      signature_algorithm: "sha1",
      expiration_time: exp_time,
      path_globs: "/*",
    }) 
    === 'PathGlobs=/*~Expires=1663070400~hmac=c1c446eea24faa31392519f975fea7eefb945625', true);
});

it('sha1 full_path test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
      signature_algorithm: "sha1",
      expiration_time: exp_time,
      full_path: "/example.m3u8",
    }) 
    === 'FullPath~Expires=1663070400~hmac=7af78177d6bc001d5626eefe387b1774a4a99ca2', true);
});

it('sha256 url_prefix test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
      signature_algorithm: "sha256",
      expiration_time: exp_time,
      url_prefix: "http://10.20.30.40/",
    }) 
    === 'URLPrefix=aHR0cDovLzEwLjIwLjMwLjQwLw~Expires=1663070400~hmac=409722313cf6d987da44bb360e60dccc3d79764520fc5e3b57654e1d4d2c862e', true);
});

it('sha256 path_glob test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
      signature_algorithm: "sha256",
      expiration_time: exp_time,
      path_globs: "/*",
    }) 
    === 'PathGlobs=/*~Expires=1663070400~hmac=9439ecdd5c4919f76f915dea72afa85a045579794e63d8cda664f5a1140c8d93', true);
});

it('sha256 full_path test', () => {
  assert.strictEqual(
    sign_token({
      base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
      signature_algorithm: "sha256",
      expiration_time: exp_time,
      full_path: "/example.m3u8",
    }) 
    === 'FullPath~Expires=1663070400~hmac=365b41fd77297371d890fc9a56e4e3d3baa4c7afbd230a0e9a81c8e1bcab9420', true);
});

it('ed25519 all_params test', () => {
    assert.strictEqual(
      sign_token({
        base64_key: "DJUcnLguVFKmVCFnWGubG1MZg7fWAnxacMjKDhVZMGI=",
        start_time: start_time,
        expiration_time: exp_time,
        signature_algorithm: "ed25519",
        path_globs: "/*",
        session_id: session_id,
        data: data,
        headers: headers,
        ip_ranges: ip_ranges,
      }) 
      === 'PathGlobs=/*~Starts=1663027200~Expires=1663070400~SessionID=test-id~Data=test-data~Headers=Foo,BAZ~IPRanges=MjAzLjAuMTEzLjAvMjQsMjAwMTpkYjg6NGE3ZjphNzMyLzY0~Signature=A7u67hveGxGvP8KBWZlUuH0IsqhS4a2lcsXwy3uc4X3zaVuw7LY-2FQT1ZF8UxkSFAsDS3_0LYnXwXB2XdepDg', true);
  });

it('sha1 all_params test', () => {
    assert.strictEqual(
      sign_token({
        base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
        start_time: start_time,
        expiration_time: exp_time,
        signature_algorithm: "sha1",
        path_globs: "/*",
        session_id: session_id,
        data: data,
        headers: headers,
        ip_ranges: ip_ranges,
      }) 
      === 'PathGlobs=/*~Starts=1663027200~Expires=1663070400~SessionID=test-id~Data=test-data~Headers=Foo,BAZ~IPRanges=MjAzLjAuMTEzLjAvMjQsMjAwMTpkYjg6NGE3ZjphNzMyLzY0~hmac=b8242e8b76cbfbbd61b3540ed0eb60a2ec2fdbdb', true);
  });

it('sha256 all_params test', () => {
    assert.strictEqual(
      sign_token({
        base64_key: "g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=",
        start_time: start_time,
        expiration_time: exp_time,
        signature_algorithm: "sha256",
        path_globs: "/*",
        session_id: session_id,
        data: data,
        headers: headers,
        ip_ranges: ip_ranges,
      }) 
      === 'PathGlobs=/*~Starts=1663027200~Expires=1663070400~SessionID=test-id~Data=test-data~Headers=Foo,BAZ~IPRanges=MjAzLjAuMTEzLjAvMjQsMjAwMTpkYjg6NGE3ZjphNzMyLzY0~hmac=dda9c3d6f3b2e867a09fbb76209ea138dd81f8512210f970d1e92f90927bef4b', true);
  });
