import threading
import subprocess

def run(file):
    subprocess.run(["python", file])

if __name__== "__main__":
    first = threading.Thread(target=run, args=("Protecto.py",))
    second = threading.Thread(target=run, args=("Protecto Password Generator.py",))

    first.start()
    second.start()

    first.join()
    second.join()