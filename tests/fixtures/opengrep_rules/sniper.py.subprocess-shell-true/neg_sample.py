import subprocess

def run(arg):
    subprocess.run(['ls', arg])
    subprocess.run('ls -la', shell=True)
