/**
 * the hub per-command approval for dsh — a cordis plugin that makes a tool call ask
 * before it runs, with a runtime switch that turns the asking off and on.
 *
 * Mounting this row is the whole opt-in: a dsh preset IS its composition, so a
 * session that selects a preset carrying this row asks, and one that does not
 * never loads the plugin. That keeps it a preset among presets rather than a
 * global nail — but a session that has started cannot change preset, so the
 * asking also has to be switchable *within* a session. That is what the
 * `/review` command is for: `/review off` lets every call through untouched,
 * `/review on` starts asking again. The state is a session-log event, folded
 * from the log on read, so a resumed session comes back in the mode it left in.
 *
 * The plugin mounts a `tools/pre-execute` listener that returns `ask`, which
 * routes through dsh's own approval seam (`ctx.approval` → `approval/requested`
 * → the the hub adapter as answerer). dsh's built-in knob only gates what the
 * sandbox refuses or a hook flags; it does not ask before every tool, which is
 * what this plugin is for.
 *
 * The switch is the plugin's own state, not `approval/policy`: that policy
 * decides whether an ask may be shown at all, and its `never` arm rejects
 * rather than allows. "Stop asking" here means the call is not gated, which is
 * a different thing.
 *
 * Plain ESM, no build step.
 */
const STATE_EVENT = 'prts-command-approval/state';

/** Whether this session is asking, from its log. Absent -> the mounted default. */
function askingFor(session) {
  const events = (session && session.events) || [];
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const e = events[i];
    if (e && e.type === STATE_EVENT) return e.data && e.data.asking === true;
  }
  return true; // mounting the row is the opt-in
}

export default function prtsCommandApproval(ctx) {
  ctx.on('tools/pre-execute', async (exec, next) => {
    // The exec carries its caller agent; the switch is that agent's session
    // state, so two sessions of the same preset do not share one flip.
    const session = exec && exec.agent && exec.agent.session;
    if (!askingFor(session)) return next();
    const name = exec && exec.name;
    return { kind: 'ask', reason: `approval required for '${name}'` };
  });

  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.commands.register({
      name: 'review',
      description: 'Ask before every tool call, or stop asking with "/review off"',
      input: { hint: '[on|off|status]' },
      handler: ({ agent, rawInput }) => {
        const arg = String(rawInput || '').trim().toLowerCase();
        if (arg === '' || arg === 'status') {
          return { kind: 'success', text: `review is ${askingFor(agent.session) ? 'on' : 'off'}` };
        }
        if (arg !== 'on' && arg !== 'off') {
          return { kind: 'error', text: `unknown argument "${arg}" (use on, off, or status)` };
        }
        const asking = arg === 'on';
        // Log-only, whole-value replace: the last record wins on the next fold.
        agent.session.append(STATE_EVENT, { asking });
        return { kind: 'success', text: `review ${asking ? 'on' : 'off'}` };
      },
    });
  });
}
