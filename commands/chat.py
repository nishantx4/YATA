from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel


def run(args) -> int:
    console = Console()
    target_path = Path(args.target).resolve()
    if not target_path.exists() or not target_path.is_dir():
        console.print(f"[bold red]Target path does not exist or is not a directory:[/bold red] {target_path}")
        return 1

    from chat_agent import ChatSession, build_context_from_scan

    console.print(f"[dim]Scanning {target_path.name} for context...[/dim]")
    context = build_context_from_scan(target_path)
    session = ChatSession(context)

    if not session.is_available:
        console.print(Panel(session.unavailable_reason(), border_style="red", title="Chat Unavailable"))
        return 1

    console.print(
        Panel(
            f"Grounded on [cyan]{context.target_name}[/cyan] -- {len(context.findings)} finding(s) discovered.\n"
            "This is a discovery-only preview (no patching/validation ran). "
            "Type your question, or 'exit'/'quit' to leave.",
            border_style="green",
            title="YATA Chat",
            expand=True,
        )
    )

    while True:
        try:
            user_text = console.input("[bold cyan]you>[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        if not user_text:
            continue
        if user_text.lower() in ("exit", "quit", ":q"):
            break

        with console.status("[dim]thinking...[/dim]"):
            reply = session.send(user_text)
        console.print(f"[bold magenta]yata>[/bold magenta] {reply}\n")

    console.print("[dim]Chat session ended.[/dim]")
    return 0
