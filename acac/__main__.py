"""Public offline evaluation commands for ACAC."""
import argparse
import os
from pathlib import Path
from .evaluation_cli_v14 import EvaluationCLIError, evaluate_bundle, verify_bundle
from .strict_json import dumps

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    sub=parser.add_subparsers(dest="command", required=True)
    demo=sub.add_parser("demo", help="run the bundled offline synthetic demonstration")
    demo.add_argument("--output-dir", type=Path, required=True)
    evaluate=sub.add_parser("evaluate", help="evaluate a supplied v1.4 artifact bundle offline")
    evaluate.add_argument("--bundle", type=Path, required=True)
    evaluate.add_argument("--output-dir", type=Path, required=True)
    evaluate.add_argument("--config", type=Path, default=Path(os.environ.get("LOCALAPPDATA", Path.home()/"AppData"/"Local"))/"ACAC"/"governance.json")
    verify=sub.add_parser("verify-bundle", help="read-only verification of bundle bindings")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--config", type=Path, default=Path(os.environ.get("LOCALAPPDATA", Path.home()/"AppData"/"Local"))/"ACAC"/"governance.json")
    args=parser.parse_args()
    try:
        if args.command=="demo":
            result=evaluate_bundle(args.root/"examples"/"synthetic_v14_bundle",args.output_dir,synthetic_demo=True,configured_approver_id="approver-1")
            expected="completed"
        elif args.command=="evaluate":
            result=evaluate_bundle(args.bundle,args.output_dir,config_path=args.config)
            expected="completed"
        else:
            result=verify_bundle(args.bundle,config_path=args.config)
            expected="verified"
    except (EvaluationCLIError,OSError,ValueError,KeyError,TypeError) as exc:
        print(dumps({"status":"failed","error":str(exc) or "evaluation_failed"}),end="")
        raise SystemExit(2) from exc
    print(dumps(result),end="")
    if result.get("status",result.get("verification_status"))!=expected:
        raise SystemExit(2)
if __name__=="__main__": main()
