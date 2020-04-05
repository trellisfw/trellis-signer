import { readFileSync } from 'fs';
import Promise from 'bluebird';
import _ from 'lodash'; // Lazy, lodash isn't really needed anymore
import debug from 'debug';
import { JobQueue } from '@oada/oada-jobs';
import tsig from '@trellisfw/signatures';

import config from './config.js'

const error = debug('trellis-signer:error');
const warn = debug('trellis-signer:warn');
const info = debug('trellis-signer:info');
const trace = debug('trellis-signer:trace');

// You can generate a signing key pair by running `oada-certs --create-keys`
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

const service = new JobQueue('trellis-signer', doSigning, {
  concurrency: 1,
  domain: DOMAIN,
  token: TOKEN
});

async function doSigning(id, task, con) {
  let vdoc = false;
  try {
    vdoc = await con.get({ path: `/resources/${id}` }).then(r => r.data);
  } catch (e) {
    error(`Could not get /resources/${id}, err = %O`, e);
    throw new Error('Could not find audits');
  }
  let resourceIdsToSign = [];
  if (vdoc.audits) {
    resourceIdsToSign = resourceIdsToSign.concat(_.map(vdoc.audits, link => link._id));
  }
  if (vdoc.cois) {
    resourceIdsToSign = resourceIdsToSign.concat(_.map(vdoc.cois, link => link._id));
  }
  // resourceIdsToSign = [ 'resources/123kl', 'resources/02infko2f' ]

  return Promise.each(resourceIdsToSign, async (signid) => {
    info(`Processing item ${signid} for res ${id}`);
    const r = await con.get({ path: `/${signid}` });
    let a = _.cloneDeep(r.data); // the actual audit or coi json

    try {

      // Test first if this thing already has a transcription signature.  If so, skip it.
      trace('Checking for existing '+type+' signature...');
      async function hasTranscriptionSignature(res) {
        if (!res.signatures) return false;
        const { trusted, valid, unchanged, payload, original, details } = await tsig.verify(res);
	trace(`Checked for signature, got back trusted ${trusted} valid ${valid} unchanged ${unchanged} payload ${payload}`);
	if (payload && payload.type === type) return true; // Found one!
        if (original) return hasTranscriptionSignature(original);
        return false; // shouldn't ever get here.
      }
      if (await hasTranscriptionSignature(a)) {
        warn(`Item ${signid} already has a transcription signature on it, choose to skip it and not apply a new one`);
	return { success: true };
      }
      trace('Did not find existing '+type+' signature, signing...');

      // Otherwise, go ahead and apply the signature
      a = await tsig.sign(a, prvKey, { header, signer, type });
    } catch (e) {
      error(`Could not apply signature to resource ${signid}, err = %O`, e);
      throw new Error(`Could not apply signature to resource ${signid}`);
    }

    info(`PUTing signed signatures key only to /${signid}/signatures`);
    try {
      await con.put({
        path: `/${signid}/signatures`,
        data: a.signatures,
        headers: { 'Content-Type': a._type },
      });
    } catch (e) {
      error(`Failed to apply signature to /${signid}/signatures, error = `, e);
      throw new Error(
        `Failed to apply signature to /${signid}/signatures`
      );
    }
  });
}

(async () => {
  try {
    await service.start();
  } catch (e) {
    console.error(e);
  }
})();
