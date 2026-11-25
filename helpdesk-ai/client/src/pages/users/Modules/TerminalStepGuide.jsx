export default function TerminalStepGuide({step}) {
 const command=step.command ?? step.expectedCommands?.[0] ?? '';
 return <div className="terminal-step-guide">
  <div><h4>Instruction</h4><p>{step.instruction || step.desc || step.title}</p></div>
  <div><h4>Command</h4>{command ? <pre>{command}</pre> : <p>Use the simulated checkpoint button. No command is required.</p>}</div>
  <div><h4>Expected output</h4><pre>{step.expectedOutput || 'Expected output will be supplied by the verified simulation.'}</pre></div>
 </div>;
}
