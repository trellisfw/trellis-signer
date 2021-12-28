/**
 * @license
 * Copyright 2021 https://oatscenter.org
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { readFileSync } from 'fs';
import debug from 'debug';
import { Service } from '@oada/jobs';
import type { WorkerFunction } from '@oada/jobs';
import tsig, { JWK } from '@trellisfw/signatures';
import equal from 'deep-equal';
import oerror from '@overleaf/o-error';
import { sprintf } from 'sprintf-js';
import config from './config.js';

const error = debug('trellis-signer:error');
const warn = debug('trellis-signer:warn');
const info = debug('trellis-signer:info');
const trace = debug('trellis-signer:trace');


//----------------------------------------------------------------------------------------
// Load configs (keys, signer name, type)
//----------------------------------------------------------------------------------------

const { 
  token: tokens, 
  domain,
} = config.get('oada');
const privateJWK = config.get('privateJWK');
const signerName = config.get('signerName');
const signerUrl = config.get('signerUrl');
const signatureType = config.get('signatureType');

// Allows domains with or without http on the front:
let DOMAIN = domain || '';
if (!DOMAIN.match(/^http/)) DOMAIN = 'https://'+DOMAIN;

// Read the signing key and get public key from it
const prvKey = JSON.parse(readFileSync(privateJWK).toString()) as JWK;
const pubKey = await tsig.keys.pubFromPriv(prvKey);
const header: { jwk: JWK; jku?: string; kid?: string } = { jwk: pubKey };
if (prvKey.jku) header.jku = prvKey.jku; // make sure we keep jku and kid
if (prvKey.kid) header.kid = prvKey.kid;
const signer: { name: String, url: String } = {
  name: signerName,
  url: signerUrl,
};
const type = signatureType;


//----------------------------------------------------------------------------------------
// Utility functions
//----------------------------------------------------------------------------------------


/**
 * Helper function to check if a resource already has a signature from us on it.
 */
async function alreadyHasSignature(res: unknown): Promise<Boolean> {
  // If there is no signatures key, there is no existing signature so go ahead and sign it
  if (!res || typeof res !== 'object' || !('signatures' in res)) {
    return false;
  }
  try {
    const { trusted, valid, unchanged, payload, original /*, details */} = await tsig.verify(res);

    trace(`Checked for signature, got back trusted ${trusted} valid ${valid} unchanged ${unchanged} payload ${payload}`);
    // If already signed by us, return true
    if (payload && payload.type === type && equal(payload.signer, signer)) return true;

    // If not already signed by us, check if there are more signatures:
    if (original) return alreadyHasSignature(original);

    // If there are no more signatures, and we haven't already signed it, then we can now say it wasn't signed by us.
    return false;
  } catch (e) {
    warn('Signature on resource was invalid: ', e);
    return false; // tsig.verify threw an exception, so we definitely have not signed it.
  }
}


//-----------------------------------------------------------------
// Job handler: sign a resource given a path
//-----------------------------------------------------------------
interface SignJobConfig {
  path: string;
}
const isSignJobConfig = (obj: unknown): obj is SignJobConfig => {
  if (!obj || typeof obj !== 'object') return false;
  if (!('path' in obj))  return false;
  return true;
}

const handleSignJob: WorkerFunction = async (job, { jobId, /*log,*/ oada }) => {
  if (!isSignJobConfig(job.config)) {
    error('FAIL job ',jobId,': job.config did not have a path');
    throw new oerror(sprintf('FAIL job ',jobId,': job.config did not have a path'));
  }
  const path = job.config.path;
  info('Received sign job ',jobId,': path ', path); 

  // Grab the original doc for signing specified in the job config:
  const orig = await oada.get({ path }).then(r => r.data)
  .catch((e:Error) => {
    error('FAIL job ',jobId,': Could not get path ', path);
    throw oerror.tag(e, sprintf('FAIL job ',jobId,': Could not get path ', path));
  });

  // Test first if this thing already has a transcription signature.  If so, skip it.
  trace('Checking for existing '+type+' signature...');
  if (await alreadyHasSignature(orig)) {
    warn('Document at path ',path,' already has a ',type,' signature on it from us, choose to skip it and not apply a new one');
    return { success: true };
  }

  // Apply the signature in memory:
  trace('Did not find existing '+type+' signature, signing...');
  const signed = await tsig.sign(orig, prvKey, { header, signer, type })
  .catch ((e:Error) => {
    error('Could not apply signature to path ', path);
    throw oerror.tag(e, sprintf('Could not apply signature to path ', path));
  });

  // Put the signature back (leave rest of document alone):
  info(`PUTing signed signatures key only to ${path}/signatures`);
  await oada.put({
    path: `${path}/signatures`,
    data: signed.signatures,
  }).catch((e:Error) => {
    error('Failed to PUT signature to '+path+'/signatures');
    throw oerror.tag(e, sprintf('Failed to PUT signature to '+path+'/signatures'));
  });

  // We are done with the job!  Document is signed.
  return { success: true };
};


// "run" handles one token: One service handler per token
async function run(token: string) {
  // Create service with up to 10 "in-flight" simultaneous requests to OADA
  const service = new Service('trellis-signer', DOMAIN, token, 10);
  // Register the job handler for the "Sign" job type:
  service.on('sign', 10*1000, handleSignJob);
  // Start the service
  await service.start();
}

await Promise.all(tokens.map(async (token) => run(token)));
