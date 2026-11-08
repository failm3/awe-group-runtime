// Fixed, synthetic lifecycle peer. No model, network, DB, secret or mission API.
// It receives no user payload and cannot claim/complete a mission.
if (process.env.AWE_E1_FIXTURE !== '1' || !process.send || process.argv.length !== 2) process.exit(64);
process.on('message', message => {
  if (message?.type === 'STOP' && Object.keys(message).length === 1) {
    process.send({type: 'STOPPED'}, () => process.exit(0));
  } else if (message?.type === 'PING' && Object.keys(message).length === 1) process.send({type: 'PONG'});
});
process.on('disconnect', () => process.exit(0));
process.send({type: 'READY', composition: 'AWE_E1', kind: 'LOCAL_PROCESS_FIXTURE'});
