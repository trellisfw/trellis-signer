import { readFileSync } from 'fs';
import Promise from 'bluebird';
import _ from 'lodash'; // Lazy, lodash isn't really needed anymore
import debug from 'debug';
import { Service } from '@oada/jobs';
import tsig from '@trellisfw/signatures';
import equal from 'deep-equal';

import config from './config.js';
import libConfig from './lib/lib-config.cjs';
import defaultConfig from './config.defaults.js';

const error = debug('trellis-signer:error');
const warn = debug('trellis-signer:warn');
const info = debug('trellis-signer:info');
const trace = debug('trellis-signer:trace');

//----------------------------------------------------------------------------------------
// Load configs (keys, signer name, type)
//----------------------------------------------------------------------------------------

// You can generate a signing key pair by running `oada-certs --create-keys`
const config = libConfig(defaultConfig);
const prvKey = JSON.parse(readFileSync(config.get('privateJWK')));
const pubKey = tsig.keys.pubFromPriv(prvKey);
const header = { jwk: pubKey };
if (prvKey.jku) header.jku = prvKey.jku; // make sure we keep jku and kid
if (prvKey.kid) header.kid = prvKey.kid;
const signer = config.get('signer');
const type = config.get('signatureType');


const TOKEN = config.get('token');
let DOMAIN = config.get('domain') || '';
if (!DOMAIN.match(/^http/)) DOMAIN = 'https://'+DOMAIN;


//----------------------------------------------------------------------------------------
// Utility function: determines if any of the signatures on this document are already from
// this signer and of this type
//----------------------------------------------------------------------------------------
async function alreadyHasSignature(res) {
  // If there is no signatures key, there is no existing signature so go ahead and sign it
  if (!res.signatures) {
    return false;
  }
  try {
    const { trusted, valid, unchanged, payload, original, details } = await tsig.verify(res);

    trace(`Checked for signature, got back trusted ${trusted} valid ${valid} unchanged ${unchanged} payload ${payload}`);
    // If already signed by us, return true
    if (payload && payload.type === type && equal(payload.signer, signer)) return true;

    // If not already signed by us, check if there are more signatures:
    if (original) return alreadyHasSignature(original);

    // If there are no more signatures, and we haven't already signed it, then we can now say it wasn't signed by us.
    return false;
  } catch (e) {
    return false; // tsig.verify threw an exception, so we definitely have not signed it.
  }
}


//----------------------------------------------------------------------------------------
// Main Service definition: will watch /bookmarks/trellisfw/trellis-signer/jobs for
// "sign" jobs to run.
//----------------------------------------------------------------------------------------

// Create service with up to 10 "in-flight" simultaneous requests to OADA
const service = new Service('trellis-signer', DOMAIN, TOKEN, 10);

services.on('sign', 10*1000,  async (job, { jobId, log, oada }) => {
  const path = job?.config?.path;
  if (!path) throw new Error(`FAIL job ${jobId}: job.config.path was not truthy`);

  // Grab the original doc for signing specified in the job config:
  const orig = await oada.get({ path }).then(r => r.data)
  .catch(e => {
    error(`FAIL job ${jobId}: Could not get path ${path}, err = %O`, e);
    throw new Error(`FAIL job ${jobId}: Could not get path ${path}`);
  });

  // Test first if this thing already has a transcription signature.  If so, skip it.
  trace('Checking for existing '+type+' signature...');
  if (await alreadyHasSignature(orig)) {
    warn(`Document at path ${path} already has a ${type} signature on it from us, choose to skip it and not apply a new one`);
    return { success: true };
  }
  trace('Did not find existing '+type+' signature, signing...');

  // Apply the signature:
  const signed = await tsig.sign(orig, prvKey, { header, signer, type })
  .catch (e => {
    error(`Could not apply signature to ${path}, err = %O`, e);
    throw new Error(`Could not apply signature to path ${path}`);
  });

  // Put the signature back (leave rest of document alone):
  info(`PUTing signed signatures key only to /${path}/signatures`);
  await oada.put({
    path: `${path}/signatures`,
    data: signed.signatures,
  }).catch(e => {
    error(`Failed to PUT signature to ${path}/signatures, error = `, e);
    throw new Error(`Failed to PUT signature to ${path}/signatures`);
  });

  // We are done with the job!  Document is signed.
  return { success: true };
}

(async () => {
  try {
    await service.start();
  } catch (e) {
    error(e);
  }
})();
