from __future__ import annotations
from rich.console import Console

def run(args) -> int:
    console = Console()
    version_text = (
        "[bold white]YATA v0.9.9[/bold white]\n\n"
        "HUNTER     [bold green]✓[/bold green]\n"
        "HEALER     [bold green]✓[/bold green]\n"
        "VALIDATOR  [bold green]✓[/bold green]\n"
        "MUTATOR    [bold green]✓[/bold green]\n"
        "LEARNER    [bold green]✓[/bold green]\n\n"
        "[bold white]Supported Vulnerabilities[/bold white]\n\n"
        "[bold green]✓[/bold green] SQL Injection\n"
        "[bold green]✓[/bold green] Hardcoded Secret\n"
        "[bold green]✓[/bold green] Command Injection\n"
        "[bold green]✓[/bold green] Path Traversal\n"
        "[bold green]✓[/bold green] Cross-Site Scripting (XSS)\n"
        "[bold green]✓[/bold green] SSRF\n"
        "[bold green]✓[/bold green] Server-Side Template Injection (SSTI)\n"
        "[bold green]✓[/bold green] Open Redirect\n"
        "[bold green]✓[/bold green] Insecure Deserialization\n\n"
        "[bold white]Supported Languages[/bold white]\n\n"
        "[bold green]✓[/bold green] Python\n"
        "[bold green]✓[/bold green] JavaScript / Node.js\n"
        "[bold green]✓[/bold green] TypeScript"
    )
    console.print(version_text)
    return 0
