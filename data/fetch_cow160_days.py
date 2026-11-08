"""Fetch several daily Cowrie event logs without downloading the full archive."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from fetch_cow160_day import fetch

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("days",nargs="+",help="UTC dates in YYYY-MM-DD format")
    parser.add_argument("--output-dir",type=Path,default=Path("data/external_raw/cowrie"))
    parser.add_argument("--workers",type=int,default=3)
    args=parser.parse_args()
    if not 1<=args.workers<=6: parser.error("workers must be between 1 and 6")
    args.output_dir.mkdir(parents=True,exist_ok=True)
    jobs={}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for day in args.days:
            output=args.output_dir/f"cow160_{day}.json.gz"
            jobs[pool.submit(fetch,day,output)]=day
        failures=[]
        for future in as_completed(jobs):
            day=jobs[future]
            try: print(f"{day}: {future.result()}",flush=True)
            except Exception as exc: failures.append((day,type(exc).__name__,str(exc)))
    if failures:
        for item in failures: print(f"FAILED {item[0]}: {item[1]}: {item[2]}")
        raise SystemExit(1)
if __name__=="__main__": main()
