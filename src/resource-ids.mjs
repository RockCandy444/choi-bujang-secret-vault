// Resource kinds are selected by server handlers, never by client input.
// Existing note UUIDs still identify individual notes.
export const RESOURCE_IDS = Object.freeze({
  notes: 'notes',
  notices: 'instructor_notices',
});

export const RESOURCE_ID_HEADER = 'X-Aleph-Resource-Id';
