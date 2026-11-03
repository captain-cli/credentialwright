import argparse
import json
from pathlib import Path
from .core import ensure, plan, parse_env


def main(argv=None):
    parser = argparse.ArgumentParser(prog="credentialwright")

    parser.add_argument(
        "--version",
        action="version",
        version="credentialwright 0.2.0",
    )

    cmds = parser.add_subparsers(dest="command", required=True)
    cmd = cmds.add_parser("ensure")
    cmd.add_argument("--spec", required=True)
    cmd.add_argument("--output", required=True)
    cmd.add_argument("--rotate", action="append", default=[], metavar="KEY")
    cmd.add_argument("--dry-run", action="store_true")
    check = cmds.add_parser("check", help="Check declared credentials exist without displaying values")
    check.add_argument("--spec", required=True)
    check.add_argument("--output", required=True)
    adopt = cmds.add_parser("adopt", help="Safely adopt a SchemaWright-created credential without rotation")
    adopt.add_argument("--source", required=True, help="Private SchemaWright secret file")
    adopt.add_argument("--output", required=True, help="CredentialWright managed env file")
    adopt.add_argument("--spec", required=True, help="Credential declaration JSON")
    adopt.add_argument("--key", required=True, help="Declared credential key")
    adopt.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "adopt":
        from .adopt import adopt_credential, AdoptionError
        try:
            spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
            action = adopt_credential(source=args.source, output=args.output,
                                      key=args.key, spec=spec, dry_run=args.dry_run)
        except (AdoptionError, OSError, ValueError, json.JSONDecodeError):
            print("Credential adoption rejected; verify private files, declared key, and conflicts.", file=__import__('sys').stderr)
            return 1
        print(json.dumps({"action": action, "key": args.key, "dryRun": args.dry_run}))
        return 0
    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    if args.command == "check":
        actions, _ = plan(spec, args.output)
        missing = sorted(key for key, action in actions.items() if action != "keep")
        print(json.dumps({"valid": not missing, "missing": missing}, indent=2))
        return 0 if not missing else 2
    actions = ensure(spec, args.output, args.dry_run, args.rotate)
    print(json.dumps({"dryRun": args.dry_run, "actions": actions}, indent=2))
    return 0

if __name__ == "__main__": main()
