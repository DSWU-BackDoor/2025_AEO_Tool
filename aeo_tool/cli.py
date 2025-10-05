import sys
import click
from rich.console import Console

console = Console()

@click.command()

def main():
    console.print("[green]Setup verified[/green]")

if __name__ == "__main__":
    main()