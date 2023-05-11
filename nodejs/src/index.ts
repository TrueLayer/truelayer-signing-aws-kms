import { AWS_CONFIG, MERCHANT_DATA_FROM_DB, REQUEST_DATA, REQUIRED_HEADERS } from "./config.js";

/***********
 * SIGNING *
 ***********/
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { Base64 } from "js-base64";
import ecdsaSigFormatter from "ecdsa-sig-formatter";

// Build the signature payload

const jwsHeaders = {
  alg: 'ES512',
  kid: MERCHANT_DATA_FROM_DB.publicKeyKid,
  tl_version: '2',
  tl_headers: REQUIRED_HEADERS.join(','),
};
const jwsPayload = `${REQUEST_DATA.method} ${REQUEST_DATA.path}
${REQUIRED_HEADERS.map(headerName => `${headerName}: ${REQUEST_DATA.headers[headerName]}`).join(`\n`)}
${REQUEST_DATA.body}`;

const jwsSigningInputs = {
  headers: Base64.encodeURI(JSON.stringify(jwsHeaders)),
  payload: Base64.encodeURI(jwsPayload),
};
const message = Buffer.from(`${jwsSigningInputs.headers}.${jwsSigningInputs.payload}`);

// Sign the payload

const client = new KMSClient({
  region: AWS_CONFIG.region,
  credentials: AWS_CONFIG.credentials,
});

const command = new SignCommand({
  KeyId: MERCHANT_DATA_FROM_DB.kmsSigningKeyId,
  SigningAlgorithm: 'ECDSA_SHA_512',
  Message: message,
  MessageType: 'RAW',
});
const response = await client.send(command);

const signatureDerBuffer = Buffer.from(response.Signature!);
const jwsSignature = ecdsaSigFormatter.derToJose(signatureDerBuffer, 'ES512');

// Build JWS with detached payload for Tl-Signature

const tlSignature = `${jwsSigningInputs.headers}..${jwsSignature}`;

console.log(`TL-Signature: ${tlSignature}`);

/********************
 * FETCH PUBLIC KEY *
 ********************/
import { GetPublicKeyCommand } from "@aws-sdk/client-kms";

const fetchCommand = new GetPublicKeyCommand({
  KeyId: MERCHANT_DATA_FROM_DB.kmsSigningKeyId,
});
const fetchResponse = await client.send(fetchCommand);

const publicKeyDerBuffer = Buffer.from(fetchResponse.PublicKey!);
const publicKeyPem = `-----BEGIN PUBLIC KEY-----
${publicKeyDerBuffer.toString("base64").match(/.{0,64}/g)?.join(`\n`).trimEnd()}
-----END PUBLIC KEY-----`;

console.log(publicKeyPem);

/********************
 * VERIFY SIGNATURE *
 ********************/
import * as tlSigning from 'truelayer-signing';

tlSigning.verify({
  publicKeyPem: publicKeyPem,
  signature: tlSignature,
  method: <tlSigning.HttpMethod>REQUEST_DATA.method,
  path: REQUEST_DATA.path,
  body: REQUEST_DATA.body,
  requiredHeaders: REQUIRED_HEADERS,
  headers: REQUEST_DATA.headers,
});
console.log("Verified!");