import {digest} from '../../contracts/canonical.mjs';
import {copy, freeze} from '../policy/json.mjs';

// An in-memory effect recorder. No filesystem, process, socket or provider adapter.
// Tickets belong to this instance and are one-use. This is not VM isolation.
export function createRecordingSink() {
  const tickets = new WeakMap(), journal = [];
  return Object.freeze({
    mint(intent) {
      const ticket = Object.freeze({});
      tickets.set(ticket, digest(intent));
      return ticket;
    },
    dispatch(ticket, intent) {
      if (!tickets.has(ticket) || tickets.get(ticket) !== digest(intent))
        return freeze({decision: 'DENY', reason: 'PEP_TICKET_REQUIRED'});
      tickets.delete(ticket);
      journal.push(freeze(copy(intent)));
      return freeze({decision: 'RECORDED_SIMULATION', sequence: journal.length});
    },
    inspect() { return copy(journal); }
  });
}
