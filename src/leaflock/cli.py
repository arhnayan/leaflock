import os
import sys
import click

from . import env_file
from . import keyfile as kf
from .exceptions import LeaflockError, WrongMachineError
from .machine_id import get_machine_id


@click.group()
def main():
    pass


@main.command()
@click.argument("input", type=click.Path(exists=True))
@click.option("-o", "--output", required=True, help="Output file path")
@click.option("-p", "--passphrase", prompt=True, hide_input=True, help="Passphrase")
def encrypt(input, output, passphrase):
    machine_id = get_machine_id()
    keyfile_path = output + ".key"
    kf.create_keyfile(passphrase, [machine_id], keyfile_path)
    key = kf.decrypt_keyfile(keyfile_path, passphrase)
    env_file.encrypt_env_file(input, output, key)
    click.echo(f"Encrypted {input} -> {output}")
    click.echo(f"Keyfile created: {keyfile_path}")


@main.command()
@click.argument("input", type=click.Path(exists=True))
@click.option("-o", "--output", required=True, help="Output file path")
@click.option("-p", "--passphrase", prompt=True, hide_input=True, help="Passphrase")
def decrypt(input, output, passphrase):
    keyfile_path = input + ".key"
    if not os.path.exists(keyfile_path):
        click.echo("Error: Keyfile not found", err=True)
        sys.exit(1)
    
    try:
        key = kf.decrypt_keyfile(keyfile_path, passphrase)
    except WrongMachineError:
        click.echo("Error: This keyfile is not authorized for this machine", err=True)
        sys.exit(1)
    except LeaflockError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    
    data = env_file.decrypt_env_file(input, key)
    env_file.write_env_file(output, data)
    click.echo(f"Decrypted {input} -> {output}")


@main.command()
@click.argument("keyfile_path", type=click.Path(exists=True))
@click.option("-m", "--machine-id", help="Machine ID to add (default: current machine)")
@click.option("-p", "--passphrase", prompt=True, hide_input=True, help="Passphrase")
def add_machine(keyfile_path, machine_id, passphrase):
    if not machine_id:
        machine_id = get_machine_id()
    
    try:
        kf.add_machine_to_keyfile(keyfile_path, machine_id, passphrase)
        click.echo(f"Added machine {machine_id} to keyfile")
    except LeaflockError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("keyfile_path", type=click.Path(exists=True))
@click.option("-m", "--machine-id", required=True, help="Machine ID to remove")
@click.option("-p", "--passphrase", prompt=True, hide_input=True, help="Passphrase")
def remove_machine(keyfile_path, machine_id, passphrase):
    try:
        kf.remove_machine_from_keyfile(keyfile_path, machine_id, passphrase)
        click.echo(f"Removed machine {machine_id} from keyfile")
    except LeaflockError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
