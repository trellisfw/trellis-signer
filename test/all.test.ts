import { expect } from 'chai';
import { connect, OADAClient } from '@oada/client';
import debug from 'debug';
import { setTimeout } from 'timers/promises';

import { domain, token } from './config';

const info = debug('all.test.ts:info');

const jobwaittime = 1000;

// Content types we'll use
const ct_job  = 'application/vnd.oada.service.job.1+json';
const ct_jobs = 'application/vnd.oada.service.jobs.1+json';
const ct_doc  = 'application/json';

const testdoc = { iam: "a test document" };
const testjob = {
  service: 'trellis-signer',
  type: 'sign',
  config: {
    path: '',
  },
};
const jobspath = '/bookmarks/services/trellis-signer/jobs';

describe('trellis-signer jobs', async function() {
  this.timeout(10000);
  let oada: OADAClient;
  before(async function() {
    oada = await connect({ domain, token});
  });

  it('Should sign a document when a job is posted', async () => {
    // Post a document
    const docpath = await oada.post({
      path: '/resources',
      contentType: ct_doc,
      data: testdoc,
    }).then(r=>(r?.headers['content-location'] || ''));
    info('Posted new document for signing at ', docpath);

    // Post a job resource
    const jobid = await oada.post({
      path: '/resources',
      contentType: ct_job,
      data: { ...testjob, config: { path: docpath } },
    }).then(r=>r?.headers['content-location']?.replace(/^\//,'')); // strip leading slash for id
    info('Posted new job resource at id: ', jobid);

    // Link as a new job
    await oada.post({
      path: jobspath,
      contentType: ct_jobs,
      data: { _id: jobid },
    });
    info('Posted new job to jobs queue');
    
    // Give the job time to run
    await setTimeout(jobwaittime);

    // Grab the document, we should see a signature
    const result = await oada.get({ path: docpath }).then(r=>r.data);
    info('result = ', result);
    
    expect(result).to.have.property('signatures');
    //expect((result as { signatures: [] })?.signatures).to.be.an('array');
  });
});
