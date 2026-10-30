import argparse
import json

from scopelens.config import Settings
from scopelens.evidence.retention import prune

parser = argparse.ArgumentParser(
    description="Expire evidence from terminal scans; metadata remains."
)
parser.add_argument(
    "--apply", action="store_true", help="Delete expired evidence; default is dry run"
)
args = parser.parse_args()
print(json.dumps(prune(Settings(), apply=args.apply)))
