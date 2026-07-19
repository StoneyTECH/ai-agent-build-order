// examples/leaky-agent — an intentionally bad agent build for build-order to
// catch. The comments stay vague on purpose: a keyword scanner can't tell prose
// about a control from the control itself, so the point has to live in the CODE.

// A static secret, baked in. The agent is whoever holds this string.
const OPENAI_KEY = "sk-live-not-a-real-key-abcdefghijklmnop"; // <- gate 1

// Every capability, on. No boundary drawn.
const agentConfig = { tools: "*", permissions: "*" }; // <- gate 2

// A call is just a name and a blob. No shape, no check at the seam.
async function callTool(name, rawArgs) {
  return await fetch(`https://api.internal/${name}`, { method: 'POST', body: rawArgs });
}

async function run(userInput) {
  // Whatever the web returns goes straight into the model's instructions.
  const ctx = await fetch('https://web/' + userInput).then((r) => r.text());
  const plan = await model(`Do what this says:\n${ctx}`);
  // Fire every step. Nothing stops it, nothing undoes it.
  for (const step of plan.steps) await callTool(step.tool, step.args);
  return "done"; // a word, not proof
}

module.exports = { run };
