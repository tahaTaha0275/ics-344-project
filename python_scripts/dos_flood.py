import argparse
import threading
import time
import requests
from random import randint

# global counters (protected by lock)
stats = {
    "200": 0,
    "400": 0,
    "401": 0,
    "403": 0,
    "404": 0,
    "429": 0,
    "500": 0,
    "other": 0,
    "errors": 0,
}
lock = threading.Lock()


def worker(
    base_url: str,
    sender_id: str,
    receiver_id: str,
    msg_prefix: str,
    requests_per_thread: int,
    sleep_between: float,
    thread_no: int,
    verbose: bool,
):
    s = requests.Session()
    endpoint = base_url.rstrip("/") + "/api/chat/send"
    for i in range(requests_per_thread):
        params = {
            "message": f"{msg_prefix} {thread_no}-{i}",
            "senderId": sender_id,
            "receiverId": receiver_id,
        }
        try:
            r = s.post(endpoint, params=params, timeout=5)
            code = str(r.status_code)
            with lock:
                if code in stats:
                    stats[code] += 1
                else:
                    stats["other"] += 1

            # print first few to see the switch from 200 → 429
            if verbose and i < 5:
                print(
                    f"[T{thread_no}] {r.status_code} {r.text[:120].replace(chr(10),' ')}"
                )

            # if you want to stop early once blocked:
            # if r.status_code == 429:
            #     break

        except Exception as e:
            with lock:
                stats["errors"] += 1
            if verbose:
                print(f"[T{thread_no}] EXCEPTION: {e}")

        # tiny sleep to avoid killing your own machine
        time.sleep(sleep_between + (randint(0, 3) / 1000.0))


def main():
    parser = argparse.ArgumentParser(
        description="Simple DoS / flood tester for the Spring secure chat app"
    )
    parser.add_argument(
        "--url", default="http://localhost:8080", help="Base URL of the app"
    )
    parser.add_argument(
        "--sender",
        default="attacker01",
        help="SenderId to use (the one that will get blocked)",
    )
    parser.add_argument(
        "--receiver", default="victim01", help="ReceiverId to use (connected SSE client)"
    )
    parser.add_argument(
        "--threads", type=int, default=30, help="Number of concurrent threads"
    )
    parser.add_argument(
        "--rpt",
        type=int,
        default=150,
        help="Requests per thread (total = threads * rpt)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.01,
        help="Seconds to sleep between requests in each thread",
    )
    parser.add_argument(
        "--prefix",
        default="flood-msg",
        help="Message prefix so you can recognize flood traffic",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print first few responses per thread",
    )
    args = parser.parse_args()

    print(
        f"Target: {args.url}  | sender={args.sender}  | receiver={args.receiver}  | threads={args.threads}  | rpt={args.rpt}"
    )

    threads = []
    start = time.time()
    for tno in range(args.threads):
        th = threading.Thread(
            target=worker,
            args=(
                args.url,
                args.sender,
                args.receiver,
                args.prefix,
                args.rpt,
                args.sleep,
                tno,
                args.verbose,
            ),
            daemon=True,
        )
        th.start()
        threads.append(th)

    for th in threads:
        th.join()

    elapsed = time.time() - start
    print("\n=== Flood finished ===")
    print(f"Elapsed: {elapsed:.2f} s")
    total = sum(stats.values())
    print(f"Total requests tried: {total}")
    for k in sorted(stats.keys()):
        print(f"{k}: {stats[k]}")


if __name__ == "__main__":
    main()
