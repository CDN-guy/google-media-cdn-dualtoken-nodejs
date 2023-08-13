const sign_token = require('./dualtoken.js')

// set token generator parameters
const start_time = new Date('2022-09-13T00:00:00Z')
const exp_time = new Date('2022-09-13T12:00:00Z')
//const exp_time = new Date(Date.now() + 1 * 60 * 60 * 1000)
const headers = [{ name: "Foo", value: "bar" }, { name: "BAZ", value: "quux" }]
const ip_ranges = "203.0.113.0/24,2001:db8:4a7f:a732/64"
const data = "test-data"
const session_id = "test-id"

// call sign_token to generate token
//
console.log(sign_token({base64_key:"DJUcnLguVFKmVCFnWGubG1MZg7fWAnxacMjKDhVZMGI=", start_time:start_time, expiration_time:exp_time, signature_algorithm:'ed25519', path_globs:"/*",session_id: session_id, data: data, headers: headers, ip_ranges: ip_ranges }))
// console.log(sign_token({base64_key:"g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=", start_time:start_time, expiration_time:exp_time, signature_algorithm:'sha256', path_globs:"/*",session_id: session_id, data: data, headers: headers, ip_ranges: ip_ranges }))
//console.log(sign_token({base64_key:"g_SlMILiIWKqsC6Z2L7gy0sReDOqtSrJrE7CXNr5Nl8=", start_time:start_time, expiration_time:exp_time, signature_algorithm:'sha1', path_globs:"/*", session_id: session_id, data: data, headers: headers, ip_ranges: ip_ranges }))