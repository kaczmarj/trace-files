import multiprocessing
import os

def fun(x):
    return os.getpid()

if __name__ == "__main__":
    print("PYTHON: starting multiprocessing pool")
    with multiprocessing.Pool() as pool:
        processes = pool.map(fun, range(1000000))
    print("PYTHON: ended multiprocessing pool")
    processes = map(str, set(processes))
    print("PYTHON: process IDs: ", ", ".join(processes))
