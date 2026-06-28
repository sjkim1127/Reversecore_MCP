import concurrent.futures
import sys
import time


def hang():
    while True:
        time.sleep(0.5)


if __name__ == "__main__":
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
            future = executor.submit(hang)
            try:
                future.result(timeout=2)
            except concurrent.futures.TimeoutError:
                print("Timeout caught inside!")
                # Kill the worker processes
                for pid, proc in list(executor._processes.items()):
                    print(f"Killing process {pid}")
                    proc.terminate()
                    # Wait for it to terminate
                    proc.join(timeout=1)

                # Shutdown
                executor.shutdown(wait=False, cancel_futures=True)
                sys.exit(0)
    except Exception as e:
        print(f"Exception: {e}")
        sys.exit(1)
    print("Successfully exited without hang!")
