import argparse
import json
from pathlib import Path
from .core import ensure, plan, parse_env


def main(argv=None):
    parser = argparse.ArgumentParser(prog="credentialwright")
    cmds = parser.add_subparsers(dest="command", required=True)
    cmd = cmds.add_parser("ensure")
    cmd.add_argument("--spec", required=True)
    cmd.add_argument("--output", required=True)
    cmd.add_argument("--rotate", action="append", default=[], metavar="KEY")
    cmd.add_argument("--dry-run", action="store_true")
    check = cmds.add_parser("check", help="Check declared credentials exist without displaying values")
    check.add_argument("--spec", required=True)
    check.add_argument("--output", required=True)
    args = parser.parse_args(argv)
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
